use anyhow::{bail, Result};

use crate::to_str;

pub struct StanzaFilter {
    buf_size: usize,
    pub buf: Vec<u8>,
    cnt: usize,
    tag_cnt: usize,
    last_char_was_lt: bool,
    last_char_was_backslash: bool,
}

impl StanzaFilter {
    pub fn new(buf_size: usize) -> StanzaFilter {
        StanzaFilter {
            buf_size,
            buf: vec![0u8; buf_size],
            cnt: 0,
            tag_cnt: 0,
            last_char_was_lt: false,
            last_char_was_backslash: false,
        }
    }

    #[inline(always)]
    pub fn current_buf(&mut self) -> &mut [u8] {
        &mut self.buf[self.cnt..(self.cnt + 1)]
    }

    #[allow(dead_code)]
    pub fn process_next_byte(&mut self) -> Result<Option<&[u8]>> {
        if let Some(idx) = self.process_next_byte_idx()? {
            return Ok(Some(&self.buf[0..idx]));
        }
        Ok(None)
    }

    pub fn process_next_byte_idx(&mut self) -> Result<Option<usize>> {
        //println!("n: {}", n);
        let b = self.buf[self.cnt];
        if b == b'<' {
            self.tag_cnt += 1;
            self.last_char_was_lt = true;
        } else {
            if b == b'/' {
                // if last_char_was_lt but tag_cnt < 2, should only be </stream:stream>
                if self.last_char_was_lt && self.tag_cnt >= 2 {
                    // non-self-closing tag
                    self.tag_cnt -= 2;
                }
                self.last_char_was_backslash = true;
            } else {
                if b == b'>' {
                    if self.last_char_was_backslash {
                        // self-closing tag
                        self.tag_cnt -= 1;
                    }
                    // now special case some tags we want to send stand-alone:
                    if self.tag_cnt == 1 && self.cnt >= 15 && (b"<?xml" == &self.buf[0..5] || b"<stream:stream" == &self.buf[0..14] || b"</stream:stream" == &self.buf[0..15]) {
                        self.tag_cnt = 0; // to fall through to next logic
                    }
                    if self.tag_cnt == 0 {
                        //let ret = Ok(Some(&self.buf[0..(self.cnt + 1)]));
                        let ret = Ok(Some(self.cnt + 1));
                        self.cnt = 0;
                        self.last_char_was_backslash = false;
                        self.last_char_was_lt = false;
                        return ret;
                    }
                }
                self.last_char_was_backslash = false;
            }
            self.last_char_was_lt = false;
        }
        //println!("b: '{}', cnt: {}, tag_cnt: {}, self.buf.len(): {}", b as char, self.cnt, self.tag_cnt, self.buf.len());
        self.cnt += 1;
        if self.cnt == self.buf_size {
            bail!("stanza too big: {}", to_str(&self.buf));
        }
        Ok(None)
    }
}

// this would be better as an async trait, but that doesn't work yet...
pub struct StanzaReader<T>(pub T);

impl<T: tokio::io::AsyncRead + Unpin> StanzaReader<T> {
    pub async fn next<'a>(&'a mut self, filter: &'a mut StanzaFilter) -> Result<Option<&'a [u8]>> {
        use tokio::io::AsyncReadExt;

        loop {
            let n = self.0.read(filter.current_buf()).await?;
            if n == 0 {
                return Ok(None);
            }
            if let Some(idx) = filter.process_next_byte_idx()? {
                return Ok(Some(&filter.buf[0..idx]));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::stanzafilter::*;
    use std::borrow::Cow;
    use std::io::Cursor;

    impl<T: tokio::io::AsyncRead + Unpin> StanzaReader<T> {
        async fn next_str<'a>(&'a mut self, filter: &'a mut StanzaFilter) -> Cow<'_, str> {
            to_str(self.next(filter).await.expect("was Err").expect("was None"))
        }
    }

    #[tokio::test]
    async fn process_next_byte() -> std::result::Result<(), anyhow::Error> {
        let mut filter = StanzaFilter::new(262_144);

        let xml_stream = Cursor::new(br###"<a/><b>inside b before c<c>inside c</c></b><d></d>"###);

        let mut stanza_reader = StanzaReader(xml_stream);

        assert_eq!(stanza_reader.next_str(&mut filter).await, "<a/>");
        assert_eq!(stanza_reader.next_str(&mut filter).await, "<b>inside b before c<c>inside c</c></b>");
        assert_eq!(stanza_reader.next_str(&mut filter).await, "<d></d>");
        assert_eq!(stanza_reader.next(&mut filter).await?, None);

        Ok(())
    }
}

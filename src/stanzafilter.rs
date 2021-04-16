use anyhow::{bail, Result};

use crate::stanzafilter::StanzaState::*;
use crate::to_str;

#[derive(Debug)]
enum StanzaState {
    OutsideStanza,
    StanzaFirstChar,
    InsideTagFirstChar,
    InsideTag,
    BetweenTags,
    ExclamationTag(usize),
    InsideCDATA,
    QuestionTag(usize),
    InsideXmlTag,
    EndStream,
}

pub struct StanzaFilter {
    buf_size: usize,
    pub buf: Vec<u8>,
    cnt: usize,
    tag_cnt: usize,
    state: StanzaState,
}

impl StanzaFilter {
    pub fn new(buf_size: usize) -> StanzaFilter {
        StanzaFilter {
            buf_size,
            buf: vec![0u8; buf_size],
            cnt: 0,
            tag_cnt: 0,
            state: OutsideStanza,
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
        let b = self.buf[self.cnt];
        //print!("b: '{}', cnt: {}, tag_cnt: {}, state: {:?}; ", b as char, self.cnt, self.tag_cnt, self.state);
        match self.state {
            OutsideStanza => {
                if b == b'<' {
                    self.tag_cnt += 1;
                    self.state = StanzaFirstChar;
                } else {
                    // outside of stanzas, let's ignore all characters except <
                    // prosody does this, and since things do whitespace pings, it's good
                    return Ok(None);
                }
            }
            BetweenTags => {
                if b == b'<' {
                    self.tag_cnt += 1;
                    self.state = InsideTagFirstChar;
                }
            }
            StanzaFirstChar => match b {
                b'/' => self.state = EndStream,
                b'!' => bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)])),
                b'?' => self.state = QuestionTag(self.cnt + 4), // 4 is length of b"xml "
                _ => self.state = InsideTag,
            },
            InsideTagFirstChar => match b {
                b'/' => self.tag_cnt -= 2,
                b'!' => self.state = ExclamationTag(self.cnt + 7), // 7 is length of b"[CDATA["
                b'?' => bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)])),
                _ => self.state = InsideTag,
            },
            InsideTag => {
                if b == b'>' {
                    if self.buf[self.cnt - 1] == b'/' {
                        // state can't be InsideTag unless we are on at least the second character, so can't go out of range
                        // self-closing tag
                        self.tag_cnt -= 1;
                    }
                    if self.tag_cnt == 0 {
                        return self.stanza_end();
                    }
                    // now special case <stream:stream ...> which we want to send stand-alone:
                    if self.tag_cnt == 1 && self.buf.len() >= 15 && b"<stream:stream " == &self.buf[0..15] {
                        return self.stanza_end();
                    }
                    self.state = BetweenTags;
                }
            }
            QuestionTag(idx) => {
                if idx == self.cnt {
                    if self.last_equals(b"xml ")? {
                        self.state = InsideXmlTag;
                    } else {
                        bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)]));
                    }
                }
            }
            InsideXmlTag => {
                if b == b'>' {
                    return self.stanza_end();
                }
            }
            ExclamationTag(idx) => {
                if idx == self.cnt {
                    if self.last_equals(b"[CDATA[")? {
                        self.state = InsideCDATA;
                        self.tag_cnt -= 1; // cdata not a tag
                    } else {
                        bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)]));
                    }
                }
            }
            InsideCDATA => {
                if b == b'>' && self.last_equals(b"]]>")? {
                    self.state = BetweenTags;
                }
            }
            EndStream => {
                if b == b'>' {
                    if self.last_equals(b"</stream:stream>")? {
                        return self.stanza_end();
                    } else {
                        bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)]));
                    }
                }
            }
        }
        //println!("cnt: {}, tag_cnt: {}, state: {:?}", self.cnt, self.tag_cnt, self.state);
        self.cnt += 1;
        if self.cnt == self.buf_size {
            bail!("stanza too big: {}", to_str(&self.buf));
        }
        Ok(None)
    }

    fn stanza_end(&mut self) -> Result<Option<usize>> {
        let ret = Ok(Some(self.cnt + 1));
        self.tag_cnt = 0;
        self.cnt = 0;
        self.state = OutsideStanza;
        //println!("cnt: {}, tag_cnt: {}, state: {:?}", self.cnt, self.tag_cnt, self.state);
        return ret;
    }

    fn last_equals(&self, needle: &[u8]) -> Result<bool> {
        Ok(needle == self.last_num_bytes(needle.len())?)
    }

    fn last_num_bytes(&self, num: usize) -> Result<&[u8]> {
        let num = num - 1;
        if num <= self.cnt {
            Ok(&self.buf[(self.cnt - num)..(self.cnt + 1)])
        } else {
            bail!("expected {} bytes only have {} bytes", num, (self.cnt + 1))
        }
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
    use std::io::Cursor;

    impl<T: tokio::io::AsyncRead + Unpin> StanzaReader<T> {
        async fn to_vec<'a>(&'a mut self, filter: &'a mut StanzaFilter) -> Result<Vec<String>> {
            let mut ret = Vec::new();
            while let Some(stanza) = self.next(filter).await? {
                ret.push(to_str(stanza).to_string());
            }
            return Ok(ret);
        }
    }

    #[tokio::test]
    async fn process_next_byte() -> std::result::Result<(), anyhow::Error> {
        let mut filter = StanzaFilter::new(262_144);

        assert_eq!(
            StanzaReader(Cursor::new(
                br###"
            <?xml version='1.0'?>
            <stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' version='1.0' to='example.org' from='example.com' xml:lang='en'>
            <a/><b>inside b before c<c>inside c</c></b></stream:stream>
            <q>bla<![CDATA[<this>is</not><xml/>]]>bloo</q>
            <d></d><e><![CDATA[what]>]]]]></e></stream:stream>
            "###,
            ))
            .to_vec(&mut filter)
            .await?,
            vec![
            "<?xml version='1.0'?>",
            "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' version='1.0' to='example.org' from='example.com' xml:lang='en'>",
            "<a/>",
            "<b>inside b before c<c>inside c</c></b>",
            "</stream:stream>",
            "<q>bla<![CDATA[<this>is</not><xml/>]]>bloo</q>",
            "<d></d>",
            "<e><![CDATA[what]>]]]]></e>",
            "</stream:stream>",
        ]
        );

        Ok(())
    }
}

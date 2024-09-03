#![allow(clippy::upper_case_acronyms)]

use crate::common::to_str;
use anyhow::{bail, Result};

use StanzaState::*;

#[derive(Debug, Clone)]
enum StanzaState {
    OutsideStanza,
    StanzaFirstChar,
    InsideTagFirstChar,
    InsideTag,
    InsideAttribute(u8),
    BetweenTags,
    ExclamationTag(usize),
    InsideCDATA,
    QuestionTag(usize),
    InsideXmlTag,
    EndStream,
}

#[derive(Clone)]
pub struct StanzaFilter {
    buf_size: usize,
    pub buf: Vec<u8>,
    end_of_first_tag: usize,
    cnt: usize,
    tag_cnt: usize,
    state: StanzaState,
}

#[inline(always)]
fn checked_sub(i: usize, s: usize) -> Result<usize> {
    // i.checked_sub(s).ok_or_else(||anyhow::anyhow!("invalid stanza"))
    if s > i {
        bail!("invalid stanza")
    } else {
        Ok(i - s)
    }
}

impl StanzaFilter {
    pub fn new(buf_size: usize) -> StanzaFilter {
        StanzaFilter {
            buf_size,
            buf: vec![0u8; buf_size],
            end_of_first_tag: 0,
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
                b'!' | b'>' | b'\'' | b'"' => bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)])),
                b'?' => self.state = QuestionTag(self.cnt + 4), // 4 is length of b"xml "
                _ => self.state = InsideTag,
            },
            InsideTagFirstChar => match b {
                b'/' => self.tag_cnt = checked_sub(self.tag_cnt, 2)?,
                b'!' => self.state = ExclamationTag(self.cnt + 7), // 7 is length of b"[CDATA["
                b'?' | b'>' | b'\'' | b'"' => bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)])),
                _ => self.state = InsideTag,
            },
            InsideTag => match b {
                b'>' => {
                    if self.end_of_first_tag == 0 {
                        self.end_of_first_tag = self.cnt;
                    }
                    if self.buf[self.cnt - 1] == b'/' {
                        // state can't be InsideTag unless we are on at least the second character, so can't go out of range
                        // self-closing tag
                        self.tag_cnt = checked_sub(self.tag_cnt, 1)?;
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
                b'\'' | b'"' => self.state = InsideAttribute(b),
                _ => {}
            },
            InsideAttribute(end) => {
                if b == end {
                    self.state = InsideTag;
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
                        self.tag_cnt = checked_sub(self.tag_cnt, 1)?; // cdata not a tag
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
                        if self.end_of_first_tag == 0 {
                            self.end_of_first_tag = self.cnt;
                        }
                        return self.stanza_end();
                    } else {
                        bail!("illegal stanza: {}", to_str(&self.buf[..(self.cnt + 1)]));
                    }
                }
            }
        }
        //trace!("cnt: {}, tag_cnt: {}, state: {:?}", self.cnt, self.tag_cnt, self.state);
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
        //trace!("cnt: {}, tag_cnt: {}, state: {:?}", self.cnt, self.tag_cnt, self.state);
        ret
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

    pub async fn next_eoft<'a>(&mut self, filter: &'a mut StanzaFilter) -> Result<Option<(&'a [u8], usize)>> {
        use tokio::io::AsyncReadExt;

        loop {
            let n = self.0.read(filter.current_buf()).await?;
            if n == 0 {
                return Ok(None);
            }
            if let Some(idx) = filter.process_next_byte_idx()? {
                let end_of_first_tag = filter.end_of_first_tag;
                filter.end_of_first_tag = 0;
                return Ok(Some((&filter.buf[0..idx], end_of_first_tag)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::stanzafilter::*;
    use std::io::Cursor;

    impl<T: tokio::io::AsyncRead + Unpin> StanzaReader<T> {
        async fn into_vec(mut self, filter: &mut StanzaFilter) -> Result<Vec<String>> {
            let mut ret = Vec::new();
            while let Some(stanza) = self.next(filter).await? {
                ret.push(to_str(stanza).to_string());
            }
            Ok(ret)
        }
    }

    #[tokio::test]
    async fn process_next_byte() -> Result<()> {
        let mut filter = StanzaFilter::new(262_144);

        assert_eq!(
            StanzaReader(Cursor::new(
                br###"
            <?xml version='1.0'?>
            <stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' version='1.0' to='example.org' from='example.com' xml:lang='en'>
            <a/><b>inside b before c<c>inside c</c></b></stream:stream>
            <q>bla<![CDATA[<this>is</not><xml/>]]>bloo</q>
            <x><![CDATA[ lol</x> ]]></x>
            <z><x><![CDATA[ lol</x> ]]></x></z>
            <a a='![CDATA['/>
            <x a='/>'>This is going to be fun.</x>
            <z><x a='/>'>This is going to be fun.</x></y>
            <d></d><e><![CDATA[what]>]]]]></e></stream:stream>
            "###,
            ))
            .into_vec(&mut filter)
            .await?,
            vec![
            "<?xml version='1.0'?>",
            "<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' version='1.0' to='example.org' from='example.com' xml:lang='en'>",
            "<a/>",
            "<b>inside b before c<c>inside c</c></b>",
            "</stream:stream>",
            "<q>bla<![CDATA[<this>is</not><xml/>]]>bloo</q>",
            "<x><![CDATA[ lol</x> ]]></x>",
            "<z><x><![CDATA[ lol</x> ]]></x></z>",
            "<a a='![CDATA['/>",
            "<x a='/>'>This is going to be fun.</x>",
            "<z><x a='/>'>This is going to be fun.</x></y>",
            "<d></d>",
            "<e><![CDATA[what]>]]]]></e>",
            "</stream:stream>",
        ]
        );

        Ok(())
    }
}

use anyhow::{anyhow, Result};

pub trait SliceSubsequence<T> {
    fn trim_start(&self, needle: &[T]) -> &[T];
    fn first_index_of(&self, needle: &[T]) -> Result<usize>;
    fn replace_first(self, needle: &[T], replacement: &[T]) -> Vec<T>;
    fn extract_between(&self, before: &[T], after: &[T]) -> Result<&[T]>;

    fn contains_seq(&self, needle: &[T]) -> bool {
        self.first_index_of(needle).is_ok()
    }
}

fn last_index_of<T: PartialEq>(s: &[T], needle: &[T]) -> usize {
    let mut len = 0;
    for i in s {
        if needle.contains(i) {
            len += 1;
        } else {
            break;
        }
    }
    len
}

impl<T: PartialEq + Clone> SliceSubsequence<T> for &[T] {
    fn trim_start(&self, needle: &[T]) -> &[T] {
        &self[last_index_of(self, needle)..]
    }

    fn first_index_of(&self, needle: &[T]) -> Result<usize> {
        if self.len() >= needle.len() {
            for i in 0..self.len() - needle.len() + 1 {
                if self[i..i + needle.len()] == needle[..] {
                    return Ok(i);
                }
            }
        }
        Err(anyhow!("not found"))
    }

    fn replace_first(self, needle: &[T], replacement: &[T]) -> Vec<T> {
        self.to_vec().replace_first(needle, replacement)
    }

    fn extract_between(&self, before: &[T], after: &[T]) -> Result<&[T]> {
        let first = &self[self.first_index_of(before)? + before.len()..];
        Ok(&first[..first.first_index_of(after)? + after.len() - 1])
    }
}

impl<T: PartialEq + Clone> SliceSubsequence<T> for Vec<T> {
    fn trim_start(&self, needle: &[T]) -> &[T] {
        &self[last_index_of(self, needle)..]
    }

    fn first_index_of(&self, needle: &[T]) -> Result<usize> {
        (self.as_slice()).first_index_of(needle)
    }

    fn replace_first(self, needle: &[T], replacement: &[T]) -> Vec<T> {
        if let Ok(idx) = self.first_index_of(needle) {
            let second = &self[(idx + needle.len())..];
            let mut ret = Vec::with_capacity(idx + replacement.len() + second.len());
            ret.extend_from_slice(&self[..idx]);
            ret.extend_from_slice(replacement);
            ret.extend_from_slice(second);
            ret
        } else {
            self
        }
    }

    fn extract_between(&self, before: &[T], after: &[T]) -> Result<&[T]> {
        let first = &self[self.first_index_of(before)? + before.len()..];
        Ok(&first[..first.first_index_of(after)? + after.len() - 1])
    }
}

#[cfg(test)]
mod tests {
    use crate::slicesubsequence::*;
    const WHITESPACE: &[u8] = b" \t\n\r";

    #[test]
    fn trim_start() {
        let buf = &b"    bla"[..];
        let buf = buf.trim_start(WHITESPACE);
        assert_eq!(buf, b"bla");

        let buf = &b"\n\t\r   \rbla"[..];
        let buf = buf.trim_start(WHITESPACE);
        assert_eq!(buf, b"bla");
    }
    #[test]
    fn replace_first() {
        let buf = b"bla to='tsnhaou' bla2".replace_first(b" to=", b" from=");
        assert_eq!(buf, b"bla from='tsnhaou' bla2");

        let buf = buf.replace_first(b" from=", b" to=");
        assert_eq!(buf, b"bla to='tsnhaou' bla2");

        let buf = buf.replace_first(b" to=", b" from=");
        assert_eq!(buf, b"bla from='tsnhaou' bla2");

        let buf = b"bla to='tsnhaou' bla2".replace_first(b"bla", b"boo");
        assert_eq!(buf, b"boo to='tsnhaou' bla2");

        let buf = buf.replace_first(b"boo", b"bla");
        assert_eq!(buf, b"bla to='tsnhaou' bla2");

        let buf = buf.replace_first(b" bla2", b"");
        assert_eq!(buf, b"bla to='tsnhaou'");
    }
    #[test]
    fn extract_between() {
        let buf = &b"bla to='tsnhaou' bla2"[..];
        assert_eq!(buf.extract_between(b" to='", b"'").unwrap(), b"tsnhaou");

        let buf = &br###"<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams' xmlns:db='jabber:server:dialback' version='1.0' to='example.org' from='example.com' xml:lang='en'>"###[..];

        assert_eq!(buf.extract_between(b" to='", b"'").or_else(|_| buf.extract_between(b" to=\"", b"\"")).unwrap(), b"example.org");

        let buf = &br###"<stream:stream xmlns="jabber:server" xmlns:stream="http://etherx.jabber.org/streams" xmlns:db="jabber:server:dialback" version="1.0" to="example.org" from="example.com" xml:lang="en">"###[..];

        assert_eq!(buf.extract_between(b" to='", b"'").or_else(|_| buf.extract_between(b" to=\"", b"\"")).unwrap(), b"example.org");
    }
}

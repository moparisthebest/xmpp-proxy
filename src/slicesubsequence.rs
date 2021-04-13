use anyhow::{anyhow, Result};

pub trait SliceSubsequence<T> {
    fn trim_start(&self, needle: &[T]) -> &[T];
    fn first_index_of(&self, needle: &[T]) -> Result<usize>;
    fn replace(self, needle: &[T], replacement: &[T]) -> Vec<T>;

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
        for i in 0..self.len() - needle.len() + 1 {
            if self[i..i + needle.len()] == needle[..] {
                return Ok(i);
            }
        }
        Err(anyhow!("not found"))
    }

    fn replace(self, needle: &[T], replacement: &[T]) -> Vec<T> {
        self.to_vec().replace(needle, replacement)
    }
}

impl<T: PartialEq + Clone> SliceSubsequence<T> for Vec<T> {
    fn trim_start(&self, needle: &[T]) -> &[T] {
        &self[last_index_of(self, needle)..]
    }

    fn first_index_of(&self, needle: &[T]) -> Result<usize> {
        return (self.as_slice()).first_index_of(needle);
    }

    fn replace(mut self, needle: &[T], replacement: &[T]) -> Vec<T> {
        while let Ok(idx) = self.first_index_of(needle) {
            self.splice(idx..(idx + needle.len()), replacement.iter().cloned());
        }
        self
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
    fn replace() {
        let buf = b"bla to='tsnhaou' bla2".replace(b" to=", b" from=");
        assert_eq!(buf, b"bla from='tsnhaou' bla2");

        let buf = buf.replace(b" from=", b" to=");
        assert_eq!(buf, b"bla to='tsnhaou' bla2");

        let buf = buf.replace(b" to=", b" from=");
        assert_eq!(buf, b"bla from='tsnhaou' bla2");

        let buf = b"bla to='tsnhaou' bla2".replace(b"bla", b"boo");
        assert_eq!(buf, b"boo to='tsnhaou' boo2");

        let buf = buf.replace(b"boo", b"bla");
        assert_eq!(buf, b"bla to='tsnhaou' bla2");

        let buf = buf.replace(b" bla2", b"");
        assert_eq!(buf, b"bla to='tsnhaou'");
    }
}

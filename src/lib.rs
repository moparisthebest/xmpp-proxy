mod stanzafilter;
pub use stanzafilter::*;

pub fn to_str(buf: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(buf)
}

//! The SSH wire encoding, read: RFC 4251 section 5.
//!
//! A `string` is a four-byte big-endian length and that many bytes; an
//! `mpint` is a string holding a two's-complement big-endian integer, which
//! for the positive integers of a key or a signature means an optional
//! leading zero byte. Key blobs, signature blobs and the data a client signs
//! are all made of these, so one reader over codec's cursor serves the
//! three.

use authenticate::AuthenticateError;
use codec::cursor::Cursor;

/// Reading the SSH wire types off codec's cursor, calling the bytes `what`
/// in a refusal; a byte is codec's `byte`.
pub trait Ssh<'a> {
    /// One `string`.
    ///
    /// # Errors
    ///
    /// Where the length or the bytes it promises are not there.
    fn string(&mut self, what: &str) -> Result<&'a [u8], AuthenticateError>;

    /// One `string` that is text, such as an algorithm name.
    ///
    /// # Errors
    ///
    /// Where the string is not there or is not UTF-8.
    fn text(&mut self, what: &str) -> Result<&'a str, AuthenticateError>;

    /// One positive `mpint`, without its leading zeros.
    ///
    /// # Errors
    ///
    /// Where the string is not there, or the integer is negative.
    fn mpint(&mut self, what: &str) -> Result<&'a [u8], AuthenticateError>;
}

impl<'a> Ssh<'a> for Cursor<'a> {
    fn string(&mut self, what: &str) -> Result<&'a [u8], AuthenticateError> {
        let truncated = |_| AuthenticateError::new(format!("the {what} is truncated"));
        let length = usize::try_from(self.u32_be().map_err(truncated)?).unwrap_or(usize::MAX);
        self.take(length).map_err(truncated)
    }

    fn text(&mut self, what: &str) -> Result<&'a str, AuthenticateError> {
        core::str::from_utf8(self.string(what)?)
            .map_err(|_| AuthenticateError::new(format!("the {what} names something not text")))
    }

    fn mpint(&mut self, what: &str) -> Result<&'a [u8], AuthenticateError> {
        let value = self.string(what)?;
        if value.first().is_some_and(|first| first & 0x80 != 0) {
            return Err(AuthenticateError::new(format!(
                "the {what} holds a negative integer"
            )));
        }
        let zeros = value.iter().take_while(|byte| **byte == 0).count();
        Ok(&value[zeros..])
    }
}

/// Left-pad a big-endian integer to `width` bytes.
///
/// `None` where it is wider than that.
#[must_use]
pub fn padded<const WIDTH: usize>(integer: &[u8]) -> Option<[u8; WIDTH]> {
    let mut fixed = [0u8; WIDTH];
    let start = WIDTH.checked_sub(integer.len())?;
    fixed[start..].copy_from_slice(integer);
    Some(fixed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Append one `string`.
    pub(crate) fn put(wire: &mut Vec<u8>, value: &[u8]) {
        let length = u32::try_from(value.len()).expect("a short string");
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(value);
    }

    /// Append one positive `mpint`.
    pub(crate) fn put_mpint(wire: &mut Vec<u8>, integer: &[u8]) {
        let zeros = integer.iter().take_while(|byte| **byte == 0).count();
        let mut value = integer[zeros..].to_vec();
        if value.first().is_some_and(|first| first & 0x80 != 0) {
            value.insert(0, 0);
        }
        put(wire, &value);
    }

    #[test]
    fn strings_and_integers_are_read_in_order_and_the_reader_ends_empty() {
        let mut wire = Vec::new();
        put(&mut wire, b"ssh-ed25519");
        put_mpint(&mut wire, &[0x00, 0x80, 0x01]);
        wire.push(50);
        let mut reader = Cursor::new(&wire);

        assert_eq!(reader.text("key blob").expect("text"), "ssh-ed25519");
        assert_eq!(reader.mpint("key blob").expect("integer"), [0x80, 0x01]);
        assert_eq!(reader.byte().expect("byte"), 50);
        assert!(reader.is_empty());
    }

    #[test]
    fn a_length_that_promises_more_than_there_is_names_what_was_truncated() {
        let mut reader = Cursor::new(&[0, 0, 0, 9, b'x']);

        let failure = reader.string("signature blob").expect_err("truncated");

        assert!(failure.message.contains("signature blob is truncated"));
    }

    #[test]
    fn an_integer_is_padded_to_its_width_and_refused_where_it_is_wider() {
        assert_eq!(padded::<4>(&[1, 2]), Some([0, 0, 1, 2]));
        assert_eq!(padded::<1>(&[1, 2]), None);
    }
}

//! The SSH wire encoding, read: RFC 4251 section 5.
//!
//! A `string` is a four-byte big-endian length and that many bytes; an
//! `mpint` is a string holding a two's-complement big-endian integer, which
//! for the positive integers of a key or a signature means an optional
//! leading zero byte. Key blobs, signature blobs and the data a client signs
//! are all made of these, so one reader serves the three.

use authenticate::AuthenticateError;

/// A cursor over bytes in the SSH wire encoding.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    rest: &'a [u8],
    what: &'static str,
}

impl<'a> Reader<'a> {
    /// Read `bytes`, calling them `what` in a refusal.
    #[must_use]
    pub const fn over(bytes: &'a [u8], what: &'static str) -> Self {
        Self { rest: bytes, what }
    }

    /// Whether everything has been read.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// One byte.
    ///
    /// # Errors
    ///
    /// Where nothing is left.
    pub fn byte(&mut self) -> Result<u8, AuthenticateError> {
        let (first, rest) = self.rest.split_first().ok_or_else(|| self.truncated())?;
        self.rest = rest;
        Ok(*first)
    }

    /// One `string`.
    ///
    /// # Errors
    ///
    /// Where the length or the bytes it promises are not there.
    pub fn string(&mut self) -> Result<&'a [u8], AuthenticateError> {
        let (length, rest) = self
            .rest
            .split_first_chunk::<4>()
            .ok_or_else(|| self.truncated())?;
        let length = usize::try_from(u32::from_be_bytes(*length)).unwrap_or(usize::MAX);
        if rest.len() < length {
            return Err(self.truncated());
        }
        let (value, rest) = rest.split_at(length);
        self.rest = rest;
        Ok(value)
    }

    /// One `string` that is text, such as an algorithm name.
    ///
    /// # Errors
    ///
    /// Where the string is not there or is not UTF-8.
    pub fn text(&mut self) -> Result<&'a str, AuthenticateError> {
        let what = self.what;
        core::str::from_utf8(self.string()?)
            .map_err(|_| AuthenticateError::new(format!("the {what} names something not text")))
    }

    /// One positive `mpint`, without its leading zeros.
    ///
    /// # Errors
    ///
    /// Where the string is not there, or the integer is negative.
    pub fn mpint(&mut self) -> Result<&'a [u8], AuthenticateError> {
        let value = self.string()?;
        if value.first().is_some_and(|first| first & 0x80 != 0) {
            return Err(AuthenticateError::new(format!(
                "the {} holds a negative integer",
                self.what
            )));
        }
        let zeros = value.iter().take_while(|byte| **byte == 0).count();
        Ok(&value[zeros..])
    }

    fn truncated(&self) -> AuthenticateError {
        AuthenticateError::new(format!("the {} is truncated", self.what))
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
        let mut reader = Reader::over(&wire, "key blob");

        assert_eq!(reader.text().expect("text"), "ssh-ed25519");
        assert_eq!(reader.mpint().expect("integer"), [0x80, 0x01]);
        assert_eq!(reader.byte().expect("byte"), 50);
        assert!(reader.is_empty());
    }

    #[test]
    fn a_length_that_promises_more_than_there_is_names_what_was_truncated() {
        let mut reader = Reader::over(&[0, 0, 0, 9, b'x'], "signature blob");

        let failure = reader.string().expect_err("truncated");

        assert!(failure.message.contains("signature blob is truncated"));
    }

    #[test]
    fn an_integer_is_padded_to_its_width_and_refused_where_it_is_wider() {
        assert_eq!(padded::<4>(&[1, 2]), Some([0, 0, 1, 2]));
        assert_eq!(padded::<1>(&[1, 2]), None);
    }
}

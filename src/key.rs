//! A public key the node holds as authorized, and the check of one
//! signature made with it.
//!
//! A key is configured as OpenSSH writes it in `authorized_keys`: the key
//! type, the base64 of the key blob, a comment. What the blob holds and how
//! a signature made with it is checked — `ssh-ed25519` strictly,
//! `ecdsa-sha2-nistp256`, and `ssh-rsa` under `rsa-sha2-256` only — is
//! `xmip-core-library-ssh`'s (`ssh::key`), the one reader the SFTP
//! transport checks its peers with too.
//!
//! A line that carries options — `from=`, `command=`, `restrict` — is
//! refused: they narrow what the key may do, this gate cannot enforce them,
//! and honoring the key while ignoring them would widen it silently.

use authenticate::AuthenticateError;
use ssh::Fingerprint;
use ssh::key::{ECDSA_P256, ED25519, PublicKey, RSA};

/// One key the node holds as authorized, for any user or for one.
#[derive(Clone, Debug)]
pub struct AuthorizedKey {
    key: PublicKey,
    fingerprint: Fingerprint,
    user: Option<String>,
    comment: String,
}

impl AuthorizedKey {
    /// Read one `authorized_keys` line: `<type> <base64> [comment]`.
    ///
    /// # Errors
    ///
    /// Where the line carries options, names a key type this gate does not
    /// verify, or its blob is not that type's key.
    pub fn parse(line: &str) -> Result<Self, AuthenticateError> {
        let mut words = line.split_whitespace();
        let named = words.next().unwrap_or_default();
        if !matches!(named, ED25519 | ECDSA_P256 | RSA) {
            return Err(AuthenticateError::new(format!(
                "the authorized key line starts with '{named}': options are not enforced \
                 here and are refused, and the key types verified are {ED25519}, \
                 {ECDSA_P256} and {RSA}"
            )));
        }
        let blob = words
            .next()
            .and_then(|encoded| codec::base64::decode(encoded).ok())
            .ok_or_else(|| AuthenticateError::new("the authorized key's blob is not base64"))?;
        let comment = words.collect::<Vec<_>>().join(" ");

        let key =
            PublicKey::parse(&blob).map_err(|refused| AuthenticateError::new(refused.message))?;
        if key.algorithm() != named {
            return Err(AuthenticateError::new(format!(
                "the authorized key line says {named} and its blob says {}",
                key.algorithm()
            )));
        }
        Ok(Self {
            fingerprint: key.fingerprint(),
            key,
            user: None,
            comment,
        })
    }

    /// Authorized for this user only.
    #[must_use]
    pub fn for_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// The one user this key is authorized for, where it is narrowed to one.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The line's comment, which by custom says whose key it is.
    #[must_use]
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// The key blob, as it travels on the wire.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        self.key.blob()
    }

    /// The key's fingerprint, read once when the line was.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Check a signature blob over `data`.
    ///
    /// # Errors
    ///
    /// Where the blob's algorithm is not one this key makes or not one this
    /// gate verifies, the signature is malformed, or it does not verify.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), AuthenticateError> {
        self.key
            .verify(data, signature)
            .map_err(|refused| AuthenticateError::new(refused.message))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ssh::SshWrite;
    use ssh::key::{RSA_SHA256, sign_ed25519, signature_blob};

    /// An Ed25519 key pair from a fixed seed, and its `authorized_keys` line.
    pub(crate) fn ed25519_pair(seed: u8) -> (ed25519_dalek::SigningKey, String) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let blob = PublicKey::ed25519(&signing.verifying_key()).blob().to_vec();
        let line = format!("{ED25519} {} party-x@example", codec::base64::encode(&blob));
        (signing, line)
    }

    #[test]
    fn an_ed25519_line_is_read_and_verifies_what_its_private_half_signed() {
        let (signing, line) = ed25519_pair(7);
        let key = AuthorizedKey::parse(&line).expect("a key");
        let signature = sign_ed25519(&signing, b"session");

        assert_eq!(key.comment(), "party-x@example");
        assert!(key.fingerprint().to_string().starts_with("SHA256:"));
        assert!(key.verify(b"session", &signature).is_ok());
        let failure = key.verify(b"another", &signature).expect_err("refused");
        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn a_line_with_options_or_another_key_type_is_refused_by_what_it_starts_with() {
        let (_, line) = ed25519_pair(7);

        let options = AuthorizedKey::parse(&format!("restrict {line}")).expect_err("refused");
        let other = AuthorizedKey::parse("ssh-dss AAAA").expect_err("refused");

        assert!(options.message.contains("'restrict'"));
        assert!(other.message.contains("'ssh-dss'"));
    }

    #[test]
    fn a_line_whose_blob_is_another_type_than_it_says_is_refused() {
        let (_, line) = ed25519_pair(7);
        let blob = line.split_whitespace().nth(1).expect("a blob");

        let failure = AuthorizedKey::parse(&format!("{RSA} {blob}")).expect_err("refused");

        assert!(
            failure
                .message
                .contains("says ssh-rsa and its blob says ssh-ed25519")
        );
        let mut hollow = Vec::new();
        hollow.string(ED25519.as_bytes()).string(&[1, 2, 3]);
        let short = format!("{ED25519} {}", codec::base64::encode(&hollow));
        assert!(AuthorizedKey::parse(&short).is_err());
    }

    #[test]
    fn a_signature_of_another_keys_algorithm_is_refused_by_name() {
        let (_, line) = ed25519_pair(7);
        let key = AuthorizedKey::parse(&line).expect("a key");

        let failure = key
            .verify(b"session", &signature_blob(RSA_SHA256, &[0; 256]))
            .expect_err("refused");

        assert!(failure.message.contains("'rsa-sha2-256'"));
    }
}

//! A public key the node holds as authorized, and the check of one
//! signature made with it.
//!
//! A key is configured as OpenSSH writes it in `authorized_keys`: the key
//! type, the base64 of the key blob, a comment. The blob is RFC 4253 section
//! 6.6 for `ssh-rsa` (`e` then `n`), RFC 5656 section 3.1 for
//! `ecdsa-sha2-nistp256` (the curve name then the point) and RFC 8709
//! section 4 for `ssh-ed25519` (the thirty-two bytes). A signature is a blob
//! too: the signature algorithm's name and the signature — raw for Ed25519,
//! `r` and `s` as integers for ECDSA, and for RSA the PKCS #1 v1.5 signature
//! under `rsa-sha2-256` (RFC 8332). An `ssh-rsa` key is one key type and
//! three signature algorithms; only the SHA-256 one is verified here.
//!
//! A line that carries options — `from=`, `command=`, `restrict` — is
//! refused: they narrow what the key may do, this gate cannot enforce them,
//! and honoring the key while ignoring them would widen it silently.

use crate::wire::{Reader, padded};
use authenticate::AuthenticateError;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use rsa::signature::Verifier as _;
use sha2::{Digest, Sha256};

const ED25519: &str = "ssh-ed25519";
const ECDSA_P256: &str = "ecdsa-sha2-nistp256";
const RSA: &str = "ssh-rsa";
const RSA_SHA256: &str = "rsa-sha2-256";

#[derive(Clone, Debug)]
enum Material {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

/// One key the node holds as authorized, for any user or for one.
#[derive(Clone, Debug)]
pub struct AuthorizedKey {
    blob: Vec<u8>,
    material: Material,
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
            .and_then(|encoded| STANDARD.decode(encoded).ok())
            .ok_or_else(|| AuthenticateError::new("the authorized key's blob is not base64"))?;
        let comment = words.collect::<Vec<_>>().join(" ");

        let mut reader = Reader::over(&blob, "key blob");
        let inner = reader.text()?;
        if inner != named {
            return Err(AuthenticateError::new(format!(
                "the authorized key line says {named} and its blob says {inner}"
            )));
        }
        let material = match named {
            ED25519 => ed25519(&mut reader)?,
            ECDSA_P256 => p256_point(&mut reader)?,
            _ => rsa_key(&mut reader)?,
        };
        if !reader.is_empty() {
            return Err(AuthenticateError::new(
                "the key blob carries more than its key",
            ));
        }
        Ok(Self {
            blob,
            material,
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
        &self.blob
    }

    /// `SHA256:<base64>` without padding, as OpenSSH prints it.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(&self.blob))
        )
    }

    /// Check a signature blob over `data`.
    ///
    /// # Errors
    ///
    /// Where the blob's algorithm is not one this key makes or not one this
    /// gate verifies, the signature is malformed, or it does not verify.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), AuthenticateError> {
        let mut reader = Reader::over(signature, "signature blob");
        let algorithm = reader.text()?;
        let raw = reader.string()?;

        let holds = match (&self.material, algorithm) {
            (Material::Ed25519(key), ED25519) => ed25519_dalek::Signature::from_slice(raw)
                .is_ok_and(|signature| key.verify_strict(data, &signature).is_ok()),
            (Material::P256(key), ECDSA_P256) => {
                let mut pair = Reader::over(raw, "ECDSA signature");
                let (r, s) = (pair.mpint()?, pair.mpint()?);
                match (padded::<32>(r), padded::<32>(s)) {
                    (Some(r), Some(s)) => p256::ecdsa::Signature::from_scalars(r, s)
                        .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
                    _ => false,
                }
            }
            (Material::Rsa(key), RSA_SHA256) => {
                // RFC 8332 has the signature as wide as the modulus; some
                // clients drop its leading zeros, and the check wants them.
                let width = rsa::traits::PublicKeyParts::size(key);
                let mut whole = vec![0u8; width.saturating_sub(raw.len())];
                whole.extend_from_slice(raw);
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
                rsa::pkcs1v15::Signature::try_from(whole.as_slice())
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
            (Material::Rsa(_), RSA) => {
                return Err(AuthenticateError::new(
                    "the signature is ssh-rsa, which is SHA-1, and this node verifies \
                     rsa-sha2-256: the client must offer it (RFC 8332)",
                ));
            }
            _ => {
                return Err(AuthenticateError::new(format!(
                    "the signature algorithm '{algorithm}' is not one this node verifies \
                     with the authorized key's type"
                )));
            }
        };

        if holds {
            Ok(())
        } else {
            Err(AuthenticateError::new(format!(
                "the {algorithm} signature does not verify with the authorized key"
            )))
        }
    }
}

fn ed25519(reader: &mut Reader<'_>) -> Result<Material, AuthenticateError> {
    let bytes: &[u8; 32] = reader
        .string()?
        .try_into()
        .map_err(|_| AuthenticateError::new("an Ed25519 key is thirty-two bytes"))?;
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map(Material::Ed25519)
        .map_err(|_| AuthenticateError::new("the Ed25519 key is not a point on the curve"))
}

fn p256_point(reader: &mut Reader<'_>) -> Result<Material, AuthenticateError> {
    let curve = reader.text()?;
    if curve != "nistp256" {
        return Err(AuthenticateError::new(format!(
            "the ECDSA key's curve is '{curve}' and this node verifies nistp256"
        )));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(reader.string()?)
        .map(Material::P256)
        .map_err(|_| AuthenticateError::new("the ECDSA key is not a point on nistp256"))
}

fn rsa_key(reader: &mut Reader<'_>) -> Result<Material, AuthenticateError> {
    let (exponent, modulus) = (reader.mpint()?, reader.mpint()?);
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map(Material::Rsa)
    .map_err(|_| AuthenticateError::new("the RSA modulus and exponent are not a usable key"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::wire::tests::{put, put_mpint};
    use ed25519_dalek::Signer;

    /// An Ed25519 key pair from a fixed seed, and its `authorized_keys` line.
    pub(crate) fn ed25519_pair(seed: u8) -> (ed25519_dalek::SigningKey, String) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut blob = Vec::new();
        put(&mut blob, ED25519.as_bytes());
        put(&mut blob, signing.verifying_key().as_bytes());
        let line = format!("{ED25519} {} partner-x@example", STANDARD.encode(blob));
        (signing, line)
    }

    /// A signature blob: the algorithm's name and the signature.
    pub(crate) fn signature_blob(algorithm: &str, raw: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        put(&mut blob, algorithm.as_bytes());
        put(&mut blob, raw);
        blob
    }

    #[test]
    fn an_ed25519_line_is_read_and_verifies_what_its_private_half_signed() {
        let (signing, line) = ed25519_pair(7);
        let key = AuthorizedKey::parse(&line).expect("a key");
        let signature = signature_blob(ED25519, &signing.sign(b"session").to_bytes());

        assert_eq!(key.comment(), "partner-x@example");
        assert!(key.fingerprint().starts_with("SHA256:"));
        assert_eq!(key.fingerprint().len(), 50);
        assert!(key.verify(b"session", &signature).is_ok());
        let failure = key.verify(b"another", &signature).expect_err("refused");
        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn an_ecdsa_nistp256_key_verifies_a_signature_of_two_integers() {
        use p256::ecdsa::signature::Signer as _;
        let signing = p256::ecdsa::SigningKey::from_slice(&[9; 32]).expect("a scalar");
        let mut blob = Vec::new();
        put(&mut blob, ECDSA_P256.as_bytes());
        put(&mut blob, b"nistp256");
        put(
            &mut blob,
            signing.verifying_key().to_encoded_point(false).as_bytes(),
        );
        let key = AuthorizedKey::parse(&format!("{ECDSA_P256} {}", STANDARD.encode(blob)))
            .expect("a key");
        let signature: p256::ecdsa::Signature = signing.sign(b"session");
        let (r, s) = signature.split_bytes();
        let mut pair = Vec::new();
        put_mpint(&mut pair, &r);
        put_mpint(&mut pair, &s);

        assert!(
            key.verify(b"session", &signature_blob(ECDSA_P256, &pair))
                .is_ok()
        );
        assert!(
            key.verify(b"another", &signature_blob(ECDSA_P256, &pair))
                .is_err()
        );
    }

    #[test]
    fn an_rsa_key_verifies_rsa_sha2_256_and_refuses_sha_1_by_name() {
        use rsa::signature::{SignatureEncoding, Signer as _};
        use rsa::traits::PublicKeyParts;
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key");
        let mut blob = Vec::new();
        put(&mut blob, RSA.as_bytes());
        put_mpint(&mut blob, &private.e().to_bytes_be());
        put_mpint(&mut blob, &private.n().to_bytes_be());
        let key = AuthorizedKey::parse(&format!("{RSA} {}", STANDARD.encode(blob))).expect("key");
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(private);
        let raw = signer.sign(b"session").to_vec();

        assert!(
            key.verify(b"session", &signature_blob(RSA_SHA256, &raw))
                .is_ok()
        );
        let failure = key
            .verify(b"session", &signature_blob(RSA, &raw))
            .expect_err("refused");
        assert!(failure.message.contains("SHA-1"));
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
    fn a_signature_of_another_keys_algorithm_is_refused_by_name() {
        let (_, line) = ed25519_pair(7);
        let key = AuthorizedKey::parse(&line).expect("a key");

        let failure = key
            .verify(b"session", &signature_blob(RSA_SHA256, &[0; 256]))
            .expect_err("refused");

        assert!(failure.message.contains("'rsa-sha2-256'"));
    }
}

#![forbid(unsafe_code)]

//! Authenticate by ssh-key: verifies a signature over a challenge by the
//! presented key.
//!
//! The first gate presented the fingerprint of the public key the peer
//! offered, with the signature the peer made riding as the
//! `ssh-key.signature` proof and what it was made over as `ssh-key.session`,
//! both base64. This gate finds the key with that fingerprint among the
//! `authorized_keys` lines the node holds — a fingerprint no held key has is
//! refused before any arithmetic — and verifies the signature blob over the
//! session bytes with it: `ssh-ed25519`, `ecdsa-sha2-nistp256` and
//! `rsa-sha2-256`, see [`key`]. Offline throughout (ADR-0045): the keys are
//! configuration.
//!
//! The session bytes are verified exactly as the transport reported them;
//! this gate does not rebuild what the client signed. Where they have the
//! shape RFC 4252 section 7 gives the signed data — the session identifier,
//! the user name, the service, `publickey`, the algorithm and the key blob —
//! they are also read: the key blob inside must be the authorized key's, and
//! the user name inside is the user the key must be authorized for. Where
//! they are an opaque challenge, the user is what the transport reported as
//! `ssh.user` evidence, if it reported one. A key narrowed to one user with
//! [`AuthorizedKey::for_user`] is refused where neither names that user.
//!
//! Not verified, and refused by name: `ssh-rsa` signatures (SHA-1),
//! `rsa-sha2-512`, the nistp384 and nistp521 curves, `ssh-dss`, OpenSSH
//! certificates and `sk-` security-key types, and `authorized_keys` options.
//! That the session identifier is this connection's is the transport's to
//! know; this gate cannot see the key exchange.

pub mod key;
pub mod wire;

pub use key::AuthorizedKey;

use authenticate::{AuthenticateError, Authenticator, Presented};
use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use context::Verified;
use wire::Reader;
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the signature blob under, base64.
pub const SIGNATURE_PROOF: &str = "ssh-key.signature";
/// The proof the identify sibling attaches the signed session bytes under.
pub const SESSION_PROOF: &str = "ssh-key.session";
/// The evidence a transport reports the SSH user name under, where the
/// session bytes do not carry it.
pub const USER: &str = "ssh.user";

/// `SSH_MSG_USERAUTH_REQUEST`, RFC 4252 section 6.
const USERAUTH_REQUEST: u8 = 50;

/// Standard base64, padded or not: transports differ.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The ssh-key authenticator: the keys the node holds as authorized.
#[derive(Clone, Debug)]
pub struct Verifier {
    keys: Vec<AuthorizedKey>,
}

/// What RFC 4252 signed data says about itself.
struct Signed<'a> {
    user: &'a str,
    blob: &'a [u8],
}

impl<'a> Signed<'a> {
    /// The signed data read as RFC 4252 section 7, or `None` where the
    /// bytes are not of that shape and are an opaque challenge.
    fn read(data: &'a [u8]) -> Option<Self> {
        let mut reader = Reader::over(data, "signed data");
        reader.string().ok()?;
        if reader.byte().ok()? != USERAUTH_REQUEST {
            return None;
        }
        let user = reader.text().ok()?;
        reader.string().ok()?;
        if reader.text().ok()? != "publickey" || reader.byte().ok()? != 1 {
            return None;
        }
        reader.string().ok()?;
        let blob = reader.string().ok()?;
        reader.is_empty().then_some(Self { user, blob })
    }
}

impl Verifier {
    /// Verifies against these keys.
    #[must_use]
    pub const fn new(keys: Vec<AuthorizedKey>) -> Self {
        Self { keys }
    }

    /// Read an `authorized_keys` file: one key a line, blank lines and `#`
    /// comments passed over.
    ///
    /// # Errors
    ///
    /// Where a line is not a key this gate reads; the message gives the
    /// line's number.
    pub fn from_authorized_keys(text: &str) -> Result<Self, AuthenticateError> {
        let mut keys = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            keys.push(AuthorizedKey::parse(line).map_err(|failure| {
                AuthenticateError::new(format!("line {}: {}", number + 1, failure.message))
            })?);
        }
        Ok(Self::new(keys))
    }
}

fn proof(presented: &Presented, name: &str) -> Result<Vec<u8>, AuthenticateError> {
    let encoded = presented
        .proof(name)
        .ok_or_else(|| AuthenticateError::new(format!("no {name} proof was presented")))?;
    BASE64
        .decode(encoded.trim())
        .map_err(|_| AuthenticateError::new(format!("the {name} proof is not base64")))
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::ssh_key()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies ssh-key"
            )));
        }
        let signature = proof(presented, SIGNATURE_PROOF)?;
        let session = proof(presented, SESSION_PROOF)?;

        let claimed = presented.value.trim().trim_end_matches('=');
        let key = self
            .keys
            .iter()
            .find(|key| key.fingerprint() == claimed)
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "the node holds no authorized key with the fingerprint {claimed}"
                ))
            })?;

        let signed = Signed::read(&session);
        if let Some(signed) = &signed
            && signed.blob != key.blob()
        {
            return Err(AuthenticateError::new(
                "the key inside the signed data is not the key that was claimed",
            ));
        }
        let user = signed.as_ref().map(|signed| signed.user).or_else(|| {
            presented
                .evidence
                .iter()
                .find(|(name, _)| name == USER)
                .map(|(_, user)| user.as_str())
        });
        if let Some(only) = key.user()
            && user != Some(only)
        {
            return Err(AuthenticateError::new(match user {
                Some(user) => format!("the key is authorized for '{only}' and not for '{user}'"),
                None => format!(
                    "the key is authorized for '{only}' only, and neither the signed data \
                     nor {USER} evidence names the user"
                ),
            }));
        }

        key.verify(&session, &signature)?;
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::{ed25519_pair, signature_blob};
    use crate::wire::tests::put;
    use ed25519_dalek::Signer;

    /// What an SSH client signs for `user`: RFC 4252 section 7.
    fn signed_data(user: &str, blob: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        put(&mut data, &[0x5e; 32]);
        data.push(USERAUTH_REQUEST);
        put(&mut data, user.as_bytes());
        put(&mut data, b"ssh-connection");
        put(&mut data, b"publickey");
        data.push(1);
        put(&mut data, b"ssh-ed25519");
        put(&mut data, blob);
        data
    }

    fn presented(fingerprint: &str, data: &[u8], signing: &ed25519_dalek::SigningKey) -> Presented {
        let signature = signature_blob("ssh-ed25519", &signing.sign(data).to_bytes());
        Presented::passed(mechanism::ssh_key(), fingerprint)
            .with_proof(SIGNATURE_PROOF, BASE64.encode(signature))
            .with_proof(SESSION_PROOF, BASE64.encode(data))
    }

    #[test]
    fn a_signature_by_an_authorized_key_over_the_session_is_proven() {
        let (signing, line) = ed25519_pair(7);
        let gate =
            Verifier::from_authorized_keys(&format!("# partners\n\n{line}\n")).expect("keys");
        let key = AuthorizedKey::parse(&line).expect("a key");

        let verified = gate
            .verify(&presented(&key.fingerprint(), b"a challenge", &signing))
            .expect("proven");

        assert_eq!(verified, Verified::Proven);
    }

    #[test]
    fn a_key_the_node_does_not_hold_is_refused_by_its_fingerprint() {
        let (_, held) = ed25519_pair(7);
        let (stranger, line) = ed25519_pair(8);
        let gate = Verifier::from_authorized_keys(&held).expect("keys");
        let fingerprint = AuthorizedKey::parse(&line).expect("a key").fingerprint();

        let failure = gate
            .verify(&presented(&fingerprint, b"a challenge", &stranger))
            .expect_err("refused");

        assert!(failure.message.contains("no authorized key"));
        assert!(failure.message.contains(&fingerprint));
    }

    #[test]
    fn a_signature_by_another_key_under_a_held_fingerprint_is_refused() {
        let (_, line) = ed25519_pair(7);
        let (impostor, _) = ed25519_pair(8);
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let fingerprint = AuthorizedKey::parse(&line).expect("a key").fingerprint();

        let failure = gate
            .verify(&presented(&fingerprint, b"a challenge", &impostor))
            .expect_err("refused");

        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn a_key_narrowed_to_one_user_proves_that_user_and_refuses_another() {
        let (signing, line) = ed25519_pair(7);
        let key = AuthorizedKey::parse(&line)
            .expect("a key")
            .for_user("orders");
        let fingerprint = key.fingerprint();
        let (ours, theirs) = (
            signed_data("orders", key.blob()),
            signed_data("root", key.blob()),
        );
        let gate = Verifier::new(vec![key]);

        let proven = gate.verify(&presented(&fingerprint, &ours, &signing));
        let other = gate
            .verify(&presented(&fingerprint, &theirs, &signing))
            .expect_err("refused");
        let unnamed = gate
            .verify(&presented(&fingerprint, b"a challenge", &signing))
            .expect_err("refused");
        let reported =
            presented(&fingerprint, b"a challenge", &signing).with_evidence(USER, "orders");

        assert_eq!(proven.expect("proven"), Verified::Proven);
        assert!(other.message.contains("not for 'root'"));
        assert!(unnamed.message.contains("ssh.user"));
        assert_eq!(gate.verify(&reported).expect("proven"), Verified::Proven);
    }

    #[test]
    fn signed_data_that_names_another_key_is_refused() {
        let (signing, line) = ed25519_pair(7);
        let (_, other) = ed25519_pair(8);
        let other = AuthorizedKey::parse(&other).expect("a key");
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let fingerprint = AuthorizedKey::parse(&line).expect("a key").fingerprint();

        let failure = gate
            .verify(&presented(
                &fingerprint,
                &signed_data("orders", other.blob()),
                &signing,
            ))
            .expect_err("refused");

        assert!(failure.message.contains("not the key that was claimed"));
    }

    #[test]
    fn another_mechanism_and_each_missing_proof_are_refused_by_name() {
        let (_, line) = ed25519_pair(7);
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let other = Presented::passed(mechanism::certificate(), "CN=x");
        let bare = Presented::passed(mechanism::ssh_key(), "SHA256:x");
        let half = bare.clone().with_proof(SIGNATURE_PROOF, "c2ln");

        assert!(
            gate.verify(&other)
                .expect_err("refused")
                .message
                .contains("'certificate' was presented")
        );
        assert!(
            gate.verify(&bare)
                .expect_err("refused")
                .message
                .contains("ssh-key.signature")
        );
        assert!(
            gate.verify(&half)
                .expect_err("refused")
                .message
                .contains("ssh-key.session")
        );
    }

    #[test]
    fn a_bad_line_in_an_authorized_keys_file_is_named_by_its_number() {
        let (_, line) = ed25519_pair(7);

        let failure =
            Verifier::from_authorized_keys(&format!("{line}\nssh-dss AAAA\n")).expect_err("line");

        assert!(failure.message.starts_with("line 2:"));
    }
}

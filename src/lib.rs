#![forbid(unsafe_code)]

//! Authenticate by ssh-key: verifies the presented key's signature over
//! RFC 4252 signed data.
//!
//! The first gate presented the fingerprint of the public key the peer
//! offered, with the signature the peer made riding as the
//! `ssh-key.signature` proof and what it was made over as `ssh-key.session`,
//! both base64. This gate finds the key with that fingerprint among the
//! `authorized_keys` lines the node holds — a fingerprint no held key has is
//! refused before any arithmetic — and verifies the signature blob over the
//! session bytes with it: `ssh-ed25519`, `ecdsa-sha2-nistp256` and
//! `rsa-sha2-256`, see [`key`], each checked by `xmip-core-library-ssh`.
//! Offline throughout (ADR-0045): the keys are configuration.
//!
//! The session bytes are verified exactly as the transport reported them;
//! this gate does not rebuild what the client signed. They must have the
//! shape RFC 4252 section 7 gives the signed data — the session identifier,
//! the user name, the service, `publickey`, the algorithm and the key blob,
//! read by `ssh::userauth::SignedData` — and anything else is refused: a
//! signature over opaque bytes proves only that the key signed them, once,
//! somewhere. The key blob inside must be the authorized key's, and the user
//! name inside is the user the key must be authorized for; a key narrowed to
//! one user with [`AuthorizedKey::for_user`] is refused for any other.
//!
//! Not verified, and refused by name: `ssh-rsa` signatures (SHA-1),
//! `rsa-sha2-512`, the nistp384 and nistp521 curves, `ssh-dss`, OpenSSH
//! certificates and `sk-` security-key types, and `authorized_keys` options.
//! That the session identifier is this connection's is the transport's to
//! know; this gate cannot see the key exchange.
//!
//! A server that logs a client in by key — Xmip's SSH server, the far ends
//! — verifies the signature itself and asks this gate only whether the key
//! is the user's ([`Verifier::admits`]), handed it as its check
//! (`net::login::Check`): the same lookup and the same narrowing to one
//! user as [`Authenticator::verify`].

pub mod key;

pub use key::AuthorizedKey;

use authenticate::{AuthenticateError, Authenticator};
use context::Verified;
use identify::Presented;
use identify::evidence;
use ssh::Fingerprint;
use ssh::userauth::SignedData;
use xcore::{Mechanism, mechanism};

/// The ssh-key authenticator: the keys the node holds as authorized.
#[derive(Clone, Debug)]
pub struct Verifier {
    keys: Vec<AuthorizedKey>,
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

    /// Whether the public key `key`, its blob as it travels on the wire, is
    /// one this gate holds as authorized for `user`: this gate's own
    /// verdict on a key whose signature the server already verified. What
    /// a server that logs a client in is handed as its check
    /// (`net::login::Check`) — Xmip's SSH server links no authenticator —
    /// so a far end asks of a key what a Receive Location's gate asks.
    #[must_use]
    pub fn admits(&self, user: &str, key: &[u8]) -> bool {
        ssh::key::PublicKey::parse(key).is_ok_and(|presented| {
            self.held(presented.fingerprint())
                .is_some_and(|held| held.blob() == key && narrowed(held, user).is_ok())
        })
    }

    /// The authorized key with `print` as its fingerprint, if this gate
    /// holds one.
    fn held(&self, print: Fingerprint) -> Option<&AuthorizedKey> {
        self.keys.iter().find(|key| key.fingerprint() == print)
    }
}

/// Refused where `key` is narrowed to one user and `user` is not that one.
fn narrowed(key: &AuthorizedKey, user: &str) -> Result<(), AuthenticateError> {
    match key.user() {
        Some(only) if user != only => Err(AuthenticateError::new(format!(
            "the key is authorized for '{only}' and not for '{user}'"
        ))),
        _ => Ok(()),
    }
}

fn proof(presented: &Presented, name: &str) -> Result<Vec<u8>, AuthenticateError> {
    let encoded = presented
        .proof(name)
        .ok_or_else(|| AuthenticateError::new(format!("no {name} proof was presented")))?;
    codec::base64::decode(encoded.trim())
        .map_err(|_| AuthenticateError::new(format!("the {name} proof is not base64")))
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::ssh_key()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let signature = proof(presented, evidence::SSH_KEY_SIGNATURE)?;
        let session = proof(presented, evidence::SSH_KEY_SESSION)?;

        let claimed = presented.value.trim();
        let print = Fingerprint::parse(claimed)
            .map_err(|refused| AuthenticateError::new(refused.message))?;
        let key = self.held(print).ok_or_else(|| {
            AuthenticateError::new(format!(
                "the node holds no authorized key with the fingerprint {claimed}"
            ))
        })?;

        let signed = SignedData::read(&session).ok_or_else(|| {
            AuthenticateError::new(
                "the signed data is not RFC 4252 section 7's: a signature over anything else \
                 proves only that the key signed it, once, somewhere",
            )
        })?;
        if signed.blob != key.blob() {
            return Err(AuthenticateError::new(
                "the key inside the signed data is not the key that was claimed",
            ));
        }
        narrowed(key, signed.user)?;

        key.verify(&session, &signature)?;
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::ed25519_pair;
    use ssh::key::{ED25519, sign_ed25519};

    /// What an SSH client signs for `user`: RFC 4252 section 7.
    fn signed_data(user: &str, blob: &[u8]) -> Vec<u8> {
        ssh::userauth::signed_data(&[0x5e; 32], user, ED25519, blob)
    }

    fn presented(fingerprint: &str, data: &[u8], signing: &ed25519_dalek::SigningKey) -> Presented {
        let signature = sign_ed25519(signing, data);
        Presented::passed(mechanism::ssh_key(), fingerprint)
            .with_proof(
                evidence::SSH_KEY_SIGNATURE,
                codec::base64::encode(&signature),
            )
            .with_proof(evidence::SSH_KEY_SESSION, codec::base64::encode(data))
    }

    #[test]
    fn a_signature_by_an_authorized_key_over_the_session_is_proven() {
        let (signing, line) = ed25519_pair(7);
        let gate = Verifier::from_authorized_keys(&format!("# parties\n\n{line}\n")).expect("keys");
        let key = AuthorizedKey::parse(&line).expect("a key");

        let verified = gate
            .verify(&presented(
                &key.fingerprint().to_string(),
                &signed_data("orders", key.blob()),
                &signing,
            ))
            .expect("proven");

        assert_eq!(verified, Verified::Proven);
    }

    #[test]
    fn an_opaque_challenge_signed_by_an_authorized_key_is_refused() {
        // A signature over bytes that are not RFC 4252's signed data proves
        // the key signed them somewhere, not that this session's client
        // holds it: whoever kept the pair could present it anywhere.
        let (signing, line) = ed25519_pair(7);
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let key = AuthorizedKey::parse(&line).expect("a key");

        let refused = gate
            .verify(&presented(
                &key.fingerprint().to_string(),
                b"a challenge",
                &signing,
            ))
            .expect_err("refused");

        assert!(refused.message.contains("RFC 4252 section 7"), "{refused}");
    }

    #[test]
    fn a_key_the_node_does_not_hold_is_refused_by_its_fingerprint() {
        let (_, held) = ed25519_pair(7);
        let (stranger, line) = ed25519_pair(8);
        let gate = Verifier::from_authorized_keys(&held).expect("keys");
        let fingerprint = AuthorizedKey::parse(&line)
            .expect("a key")
            .fingerprint()
            .to_string();

        let data = signed_data("orders", AuthorizedKey::parse(&line).expect("a key").blob());
        let failure = gate
            .verify(&presented(&fingerprint, &data, &stranger))
            .expect_err("refused");

        assert!(failure.message.contains("no authorized key"));
        assert!(failure.message.contains(&fingerprint));
    }

    #[test]
    fn a_signature_by_another_key_under_a_held_fingerprint_is_refused() {
        let (_, line) = ed25519_pair(7);
        let (impostor, _) = ed25519_pair(8);
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let held = AuthorizedKey::parse(&line).expect("a key");
        let fingerprint = held.fingerprint().to_string();

        let failure = gate
            .verify(&presented(
                &fingerprint,
                &signed_data("orders", held.blob()),
                &impostor,
            ))
            .expect_err("refused");

        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn a_key_narrowed_to_one_user_proves_that_user_and_refuses_another() {
        let (signing, line) = ed25519_pair(7);
        let key = AuthorizedKey::parse(&line)
            .expect("a key")
            .for_user("orders");
        let fingerprint = key.fingerprint().to_string();
        let (ours, theirs) = (
            signed_data("orders", key.blob()),
            signed_data("root", key.blob()),
        );
        let gate = Verifier::new(vec![key]);

        let proven = gate.verify(&presented(&fingerprint, &ours, &signing));
        let other = gate
            .verify(&presented(&fingerprint, &theirs, &signing))
            .expect_err("refused");
        // The transport's word for the user does not stand in for the
        // signed data's.
        let reported = presented(&fingerprint, b"a challenge", &signing)
            .with_evidence(context::property::SSH_USER, "orders");

        assert_eq!(proven.expect("proven"), Verified::Proven);
        assert!(other.message.contains("not for 'root'"));
        assert!(gate.verify(&reported).is_err(), "an opaque challenge");
    }

    #[test]
    fn a_login_is_admitted_only_with_a_held_key_for_its_own_user() {
        let (_, line) = ed25519_pair(7);
        let (_, stranger) = ed25519_pair(8);
        let key = AuthorizedKey::parse(&line).expect("a key");
        let blob = key.blob().to_vec();
        let stranger = AuthorizedKey::parse(&stranger).expect("a key");
        let gate = Verifier::new(vec![key.for_user("orders")]);

        assert!(gate.admits("orders", &blob));
        assert!(!gate.admits("payroll", &blob), "another user");
        assert!(!gate.admits("orders", stranger.blob()), "a key not held");
        assert!(!gate.admits("orders", b"not a key"), "no key at all");
        assert!(
            !Verifier::new(Vec::new()).admits("orders", &blob),
            "none held"
        );
    }

    #[test]
    fn signed_data_that_names_another_key_is_refused() {
        let (signing, line) = ed25519_pair(7);
        let (_, other) = ed25519_pair(8);
        let other = AuthorizedKey::parse(&other).expect("a key");
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let fingerprint = AuthorizedKey::parse(&line)
            .expect("a key")
            .fingerprint()
            .to_string();

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
    fn each_missing_proof_is_refused_by_name() {
        let (_, line) = ed25519_pair(7);
        let gate = Verifier::from_authorized_keys(&line).expect("keys");
        let bare = Presented::passed(mechanism::ssh_key(), "SHA256:x");
        let half = bare.clone().with_proof(evidence::SSH_KEY_SIGNATURE, "c2ln");

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

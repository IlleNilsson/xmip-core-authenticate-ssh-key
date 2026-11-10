# xmip-core-authenticate-ssh-key

Authenticate by ssh-key: verifies the presented key's signature over RFC 4252 signed data. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It finds the presented key, by its SHA-256 fingerprint, among the
`authorized_keys` lines the node holds, and verifies the SSH signature blob
over the signed session data with it: `ssh-ed25519`, `ecdsa-sha2-nistp256` and
`rsa-sha2-256`. It refuses `ssh-rsa` (SHA-1), `rsa-sha2-512`, the other curves,
certificates and `sk-` keys by name, and it does not rebuild the RFC 4252
signed data: the transport reports exactly what was signed.

What was signed must be RFC 4252 section 7's signed data — the session
identifier, the user, the service, `publickey`, the algorithm and the key
blob — and anything else is refused: a signature over opaque bytes proves
only that the key signed them, once, somewhere. The key blob inside must be
the authorized key's, and the user inside is the user a key narrowed to one
user must name.

The key blobs, the signature check (Ed25519 strictly), the fingerprint and
the signed data are `xmip-core-library-ssh`'s, the one home of SSH this gate,
the ssh-key identifier and the SFTP transport share; what is this gate's is
the `authorized_keys` line, a key narrowed to one user, and the verdict
(ADR-0050).

## A server's check

Xmip's SSH server links no authenticator — identity presentation is not a
transport's (`architecture.toml`) — and is handed the check it asks of a
login (`net::login::Check`). Where a client signed with a key, the server
verifies the signature itself and asks the check whether the key is the
user's; `Verifier::admits(user, key)` is this gate's answer, the same lookup
by fingerprint and the same narrowing to one user as `verify` (ADR-0019,
amendment 2026-11-01).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

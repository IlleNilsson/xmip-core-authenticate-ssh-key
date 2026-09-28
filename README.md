# xmip-core-authenticate-ssh-key

Authenticate by ssh-key: verifies a signature over a challenge by the presented key. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It finds the presented key, by its SHA-256 fingerprint, among the
`authorized_keys` lines the node holds, and verifies the SSH signature blob
over the signed session data with it: `ssh-ed25519`, `ecdsa-sha2-nistp256` and
`rsa-sha2-256`. It refuses `ssh-rsa` (SHA-1), `rsa-sha2-512`, the other curves,
certificates and `sk-` keys by name, and it does not rebuild the RFC 4252
signed data: the transport reports exactly what was signed.

The key blobs, the signature check (Ed25519 strictly), the fingerprint and
the signed data are `xmip-core-library-ssh`'s, the one home of SSH this gate,
the ssh-key identifier and the SFTP transport share; what is this gate's is
the `authorized_keys` line, a key narrowed to one user, and the verdict.
Until 2026-09-24 the gate carried a `wire` module of its own, and until
2026-09-28 the key and signature check (ADR-0050, amendments 2026-09-25 and
2026-09-28).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

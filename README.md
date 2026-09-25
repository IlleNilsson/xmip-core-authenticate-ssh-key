# xmip-core-authenticate-ssh-key

Authenticate by ssh-key: verifies a signature over a challenge by the presented key. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It finds the presented key, by its SHA-256 fingerprint, among the
`authorized_keys` lines the node holds, and verifies the SSH signature blob
over the signed session data with it: `ssh-ed25519`, `ecdsa-sha2-nistp256` and
`rsa-sha2-256`. It refuses `ssh-rsa` (SHA-1), `rsa-sha2-512`, the other curves,
certificates and `sk-` keys by name, and it does not rebuild the RFC 4252
signed data: the transport reports exactly what was signed.

The blobs and the signed data are read with `xmip-core-library-ssh`, the one
reader of SSH's wire types (RFC 4251 section 5) this gate and the SFTP
transport share; until 2026-09-24 the gate carried a `wire` module of its own
(ADR-0050, amendment 2026-09-25).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.

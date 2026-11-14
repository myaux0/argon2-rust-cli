# Changelog

## 0.3.0 - 2026-11-15

### Changed

- Migrated the hashing backend from the RustCrypto `argon2` crate to the
  pure-Rust `argon2-rust` implementation.
- Renamed the package and binary to `argon2-rust-cli`.
- Updated the README, installer metadata and integration tests for the fork.

### Added

- Preserved compatibility with the C reference `argon2` CLI for encoded
  (`-e`) and raw (`-r`) output.
- Added a performance comparison against the upstream Rust CLI and the C
  reference implementation.

### Credits

- Original `argon2-cli` by Joel Schulz-Andres and Julian Dickert.

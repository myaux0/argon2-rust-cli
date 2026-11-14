# Changelog

## 0.3.0 - 2026-11-15

### Changed

- Migrated the hashing backend from the RustCrypto `argon2` crate to the
  pure-Rust `argon2-rust` implementation.
- Renamed the package and binary to `argon2-rust-cli`.
- Updated the README, installer metadata and integration tests for the fork.
- Use the current `macos-15` runner for Apple Silicon release builds.

### Added

- Preserved compatibility with the C reference `argon2` CLI for encoded
  (`-e`) and raw (`-r`) output.
- Added a performance comparison against the upstream Rust CLI and the C
  reference implementation, including memory sizes up to 2 GiB.
- Added an opt-in 256 MiB compatibility test (`cargo test -- --ignored`).

### Credits

- Original `argon2-cli` by Joel Schulz-Andres and Julian Dickert.

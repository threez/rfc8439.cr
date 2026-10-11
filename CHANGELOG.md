# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-10-11

### Added

- One-shot `Crypto::AeadChacha20Poly1305.encrypt`/`.decrypt` class methods
  implementing RFC 8439 section 2.8 without the streaming/IO based
  instance interface, for protocols that need a plain
  `encrypt(plaintext, aad) -> {ciphertext, tag}` call per message, such
  as protecting a single TLS 1.3 record (see issue #5).

### Changed

- Bumped the `ameba` dev dependency to `~> 1.7.0` and adjusted the
  `Makefile`/CI to explicitly build it with `shards build ameba`, since
  ameba no longer compiles itself via a `shards install` postinstall
  hook.
- Fixed new ameba 1.7.0 lint violations (`Lint/WhitespaceAroundMacroExpression`,
  `Style/MultilineStringLiteral`) in the spec suite.
- Standardized `.github/workflows/ci.yml` into separate `lint` and `test`
  jobs using `actions/checkout@v4`, a pinned Crystal version, and shards
  caching.

# Changelog

All notable changes to fw-triage are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-09-25

### Fixed
- **`xor_sweep`: removed the inert "entropy collapse" heuristic.** Single-byte
  XOR is a bijection on the byte alphabet, so Shannon entropy is identical for
  all 256 keys — the check could never single out the key. It now relies on file
  magics and, when none match, reports a best-key guess from the padding
  heuristic (0x00 padding XOR key == key, so the most common byte is the key).
- **`xor_sweep`: tar detection** now checks the `ustar` magic at its real offset
  (257), where it could never match at offset 0 before.
- **`crypto_indicators`: word-boundary matching** so short tokens (`aes`, `rsa`,
  `otp`, `xor`) stop matching inside unrelated words (e.g. "rsa" in
  "conversation").
- All three tools guard file opens with a clean error (no traceback) and close
  descriptors; `entropy` validates window/step (was crashing on `-w 0`).

### Added
- Stdlib unittest suite (incl. a regression test for the entropy invariance),
  `ruff` config, `.gitignore`, and a CI workflow (lint + tests).

## [0.1.0]

- Initial release.

# Changelog

All notable changes to this project will be documented in this file.

## [7.8.0] - 2026-07-07

### Fixed
- `src/protocols/tls/certs.rs`: replaced three deprecated `openssl::asn1::Asn1StringRef::as_utf8()` calls with the non-deprecated `to_string()` method (lines 113, 120, 184) — `as_utf8()` truncated at the first interior NUL byte; `to_string()` handles the full string correctly
- `src/cli.rs`: escaped the `<output-base>` literal in the `All` variant doc comment using backticks to suppress the `rustdoc::invalid_html_tags` warning

### Dependencies
- `quick-xml` updated `0.39` → `0.41`; no API call-site changes required (`nmap_xml.rs` uses only stable surface: `Reader::from_reader`, `config_mut().trim_text`, `read_event_into`, `Event` variants, `attributes()`)
- `rusqlite` updated `0.38` → `0.39`; no API call-site changes required (`sqlite.rs` uses only stable surface: `Connection::open`, `execute_batch`, `execute`, `prepare`, `query_map`, `row.get`, `params![]`); 0.40 was skipped — `libsqlite3-sys 0.38.1` (its transitive dep) requires the unstable `cfg_select` nightly feature which is not available on stable Rust
- `libsqlite3-sys` updated `0.36.0` → `0.37.0` (via rusqlite 0.39)
- `hashlink` updated `0.11.1` → `0.12.1`

## [7.7.1] - 2026-07-07

### Fixed
- **HTML**: added `FQDN/IP` and `Port` as explicit table columns per row (previously embedded only in `<h2>` target grouping header); table now uses a single flat layout matching CSV column order (`ID, FQDN/IP, Port, Protocol, Severity, CVSS Score, CVSS Vector, Finding, CVE, CWE`); targets with no findings emit a single spanned row instead of a separate sub-table
- **Table**: added `CVSS Vector` column (`CVSS` was score-only); columns now identical to CSV schema
- **Text**: replaced grouped narrative format with a structured per-finding record block showing all 10 fields explicitly (`ID`, `FQDN/IP`, `Port`, `Protocol`, `Severity`, `CVSS Score`, `CVSS Vector`, `Finding`, `CVE`, `CWE`)

All four output formats (CSV, HTML, Table, Text) now expose identical field coverage in the same column order.

## [7.7.0] - 2026-07-07

### Changed
- **CSV**: restructured to testssl-inspired column layout — `id, fqdn/ip, port, protocol, severity, cvss_score, cvss_vector, finding, cve, cwe` (was `target, finding_id, protocol, severity, cvss_vector, cvss_score, title, details`); `fqdn/ip` and `port` are now separate columns; `finding` combines title and runtime details; severity and protocol are uppercase (`HIGH`, `TLS`, etc.)
- **HTML**: updated table columns to match new layout — columns are now `ID, Protocol, Severity, CVSS Score, CVSS Vector, Finding, CVE, CWE`; severity and protocol displayed in uppercase
- **Table**: split host/port into separate `FQDN/IP` and `Port` columns; added `CVE` and `CWE` columns; `Finding` column combines title and details; severity/protocol uppercase
- **Text**: severity and protocol now uppercase; CVE/CWE appended to each finding block when present

### Added
- CVE extraction from catalog reference URLs at write time — CVE IDs (e.g. `CVE-2016-0800`) are extracted from `https://nvd.nist.gov/vuln/detail/CVE-*` and similar references stored in the finding catalog
- CWE mapping computed per finding ID: `CWE-311` (NULL cipher), `CWE-295` (aNULL/self-signed), `CWE-297` (hostname mismatch), `CWE-298` (certificate validity), `CWE-287` (no NLA), `CWE-326` (all other cryptographic configuration findings)

## [7.6.0] - 2026-07-07

### Changed
- `--output` (format selector) renamed to `--output-format` — breaking flag rename
- `--out` renamed to `--output` (short: `-o`) — breaking flag rename
- **CSV**: added `protocol`, `cvss_vector`, `cvss_score` columns (now 8 columns total)
- **HTML**: replaced bullet list with a full table; added severity, protocol, CVSS vector and score columns; severity cells styled with CSS classes
- **Text**: added protocol and CVSS vector + score to each finding line
- **Table**: added Protocol, CVSS, and Details columns so all formats are data-equivalent

### Added
- `--output-format all`: writes results simultaneously to `<base>.json`, `<base>.txt`, `<base>.table`, `<base>.html`, and `<base>.csv`; requires `--output <base-path>`

### Fixed
- README version badge corrected (was v7.3.3, now v7.6.0)
- All non-JSON output formats now include the full `FindingInstance` field set (protocol, cvss_vector, cvss_score) that was previously only visible in JSON output
- **CVSS corrections** (cross-referenced against NVD, Tenable plugins, CISA-ADP, Rapid7):
  - `HS-TLS-PROTOCOL-0009` (CRIME/TLS compression): Medium 4.8 → **Low 3.1** (`UI:N/C:L/I:L` → `UI:R/C:L/I:N`); CVE-2012-4929 has no CVSS 3.x; CVSS 2.0 = 2.6 Low; requires UI:R
  - `HS-TLS-CIPHER-0003` (EXPORT/FREAK): High 7.4 → **Medium 5.9** (`I:H` → `I:N`); FREAK enables decryption (C:H) not injection; CVE-2015-0204 has no NVD CVSS 3.x
  - `HS-TLS-CIPHER-0004` (RC4/TLS): Medium 5.9 → **Low 3.7** (`C:H` → `C:L`); CVE-2015-2808 rated 3.7 Low by CISA-ADP; statistical attacks yield only partial plaintext
  - `HS-SSH-CIPHER-0107` (arcfour/RC4): Medium 5.9 → **Low 3.7** (`C:H` → `C:L`); analogous to CVE-2015-2808; RC4 bias attacks require millions of sessions
- Added CVE references to `HS-TLS-PROTOCOL-0001` (CVE-2016-0800/DROWN), `HS-TLS-PROTOCOL-0002` (CVE-2014-3566/POODLE), `HS-TLS-CIPHER-0003` (CVE-2015-0204), `HS-TLS-CIPHER-0004` (CVE-2013-2566, CVE-2015-2808), `HS-SSH-CIPHER-0107` (CVE-2015-2808, RFC 8758)
- `FINDING_INDEX.MD` and `FINDING_AUDIT_MATRIX.md` updated to match corrected CVSS values

## [7.5.0] - 2026-03-17

### Fixed
- **Scan error bug**: `?` on expected cipher-probe failures (NULL, aNULL, EXP, RC4, 3DES)
  propagated up to `async_runner` and produced `HS-GENERAL-CONFIG-0902 "scan error"` on
  well-configured servers. All probe connection failures are now treated as "not supported"
  instead of fatal errors.
- `handshake_with_builder` returns `Ok("")` on connection failure (cipher/version unsupported)
  rather than propagating the error.
- `handshake_cipher` swallows `set_cipher_list` errors (cipher family not compiled into
  OpenSSL) and returns `Ok("")` rather than `Err`.
- `check_blocking` (ciphers) now short-circuits to empty results when the initial default
  connection fails, preventing false-positive "no AEAD" / "no FS" findings.
- `scenarios.rs`: `supports_cipher_list`, `weak_cipher_preference`, `dh_temp_bits`,
  `session_resumption_supported` all return `Ok(...)` on connection failure instead of `Err`.
  All `?` calls in `check_blocking` replaced with `.unwrap_or(false)` / `.unwrap_or(None)`.
  `check_downgrade` and `tls13_early_data_enabled` failures are silently skipped.
- `starttls::connect` now uses `TcpStream::connect_timeout` (10 s) instead of the OS
  default (~75 s) to avoid per-connection hangs that exceed the scan timeout.

### Added
- **TLS Posture output** (sslscan-like): every successful scan now populates a `posture`
  object in `metadata`:
  - `protocols_accepted` / `protocols_rejected` — which TLS/SSL versions connected
  - `cipher_categories` — AEAD, FS, NULL, 3DES, RC4, EXPORT, MEDIUM: accepted/rejected
  - `certificate` — subject, issuer, validity dates, key type/bits, signature algorithm, SANs
  - `alpn_protocols` — negotiated application protocols (e.g. `["h2"]`)
  - `fallback_scsv` / `secure_renegotiation` / `compression` — boolean posture flags
- `src/protocols/tls/posture.rs` — new `TlsPosture`, `CipherCategory`, `CertSummary` structs
- `tests/tls_probe.rs` — 5 new fault-tolerance tests verifying all modules return `Ok` on
  unreachable hosts

### Changed
- `src/protocols/tls/probe.rs`: sequential `.await?` chain replaced with `tokio::join!`;
  scan time is now `max(module_time)` instead of `sum(module_times)`.
- All TLS module return types extended to include posture data alongside findings:
  `versions::check` → `(findings, accepted, rejected)`
  `ciphers::check`  → `(findings, Vec<CipherCategory>)`
  `certs::check`    → `(findings, Option<CertSummary>)`
  `alpn::check`     → `(findings, Vec<String>)`
  `scenarios::check`→ `(findings, fallback_scsv, secure_renegotiation, compression)`

## [7.4.0] - 2026-03-15

### Added
- `FINDING_AUDIT_MATRIX.md` — generated 68-row audit matrix mapping each finding to protocol, severity, CVSS vector, and external source basis
- `scripts/generate_finding_audit_matrix.py` — regenerates `FINDING_AUDIT_MATRIX.md` from `src/findings/catalog.rs`
- `scripts/check_finding_index_sync.py` — verifies `FINDING_INDEX.MD` and `FINDING_AUDIT_MATRIX.md` stay aligned with `src/findings/catalog.rs`
- `make verify-docs` and `make generate-audit-matrix`
- 32 additional test scenarios, bringing the suite to 101 tests total
  - `tests/input_edge_cases.rs`
  - `tests/cvss_edges.rs`
  - `tests/catalog_audit.rs`
  - `tests/runtime_edges.rs`
  - `tests/finding_index_sync.rs`

### Changed
- `handshaker scan --file` now auto-detects plain target files, nmap grep, nmap XML, nuclei JSON(L), and testssl JSON
- Full 68-finding audit completed across `src/findings/catalog.rs` and `FINDING_INDEX.MD`
  - CVSS vectors, scores, severities, and references recalibrated against external sources where applicable
  - Original reasoning in `FINDING_INDEX.MD` preserved and augmented with vendor/source calibration notes
- CVSS calculator now rounds up according to CVSS v3.1 rules
- Catalog/document sync is now enforced by test coverage
- **HS-TLS-CERT-0004** (Hostname mismatch): corrected Info/0.0 → Medium/4.8; vector updated to `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` consistent with MITM-class findings; severity reasoning updated with Tenable plugin 45411 citation

### Dependencies
- `rand` updated 0.9.2 → 0.10.0; call site in `src/output/sqlite.rs` updated to `rand::random::<[u8; 16]>()`
- `rusqlite` updated 0.32.1 → 0.38.0
- `quick-xml` updated 0.37.5 → 0.39.2

## [7.3.3] - 2026-03-14

### Fixed
- `ci.yml`: added `macos-13` (Intel x64) and `windows-11-arm` (ARM64) to build matrix so both architectures appear in GitHub Releases
  - `macos-latest` builds macOS ARM64 (Apple Silicon); `macos-13` builds macOS x64 (Intel)
  - `windows-latest` builds Windows x64; `windows-11-arm` builds Windows ARM64

## [7.3.2] - 2026-03-14

### Added
- `FINDING_INDEX.MD` Section 7: Finding Details — standards enrichment blocks for all 68 findings
  - CVE references, CWE IDs, OWASP category, WASC identifier, and CVSS vector component explanations
  - Severity reasoning with industry source citations (NVD, Tenable, RFC references)
  - Attack prerequisites for each finding
- Logo image in `README.md` header

### Changed
- CVSS severity label alignment across `FINDING_INDEX.MD` and `src/findings/catalog.rs`:
  - **Critical→High**: HS-TLS-PROTOCOL-0002 (SSLv3/8.6), HS-TLS-CIPHER-0002 (aNULL/8.6), HS-TLS-CIPHER-0003 (EXPORT→7.4 after vector fix)
  - **Critical→kept Critical** with vector corrected: HS-TLS-PROTOCOL-0001 and HS-TLS-CERT-0001 vectors updated to `A:H` (score 9.8)
  - **Medium→High**: HS-TLS-CIPHER-0005 (SWEET32) vector updated to `AV:N/AC:L/C:H` per CVE-2016-2183 NVD 7.5
  - **High→Medium** (13 findings): HS-TLS-PROTOCOL-0003, 0007; HS-TLS-CIPHER-0004; HS-TLS-CERT-0005, 0006; HS-TLS-SCENARIO-0002, 0004; HS-SSH-KEX-0101, 0102; HS-SSH-HOSTKEY-0104, 0105; HS-SSH-CIPHER-0107; HS-RDP-TLS-0202
  - **3.7→4.8** vector updates (add `I:L`): All Medium findings that had `C:L/I:N/A:N` vectors updated to `C:L/I:L/A:N` for score alignment with Medium severity range
- FINDING_INDEX.MD protocol counts corrected: TLS (48), General (5)
- Finding statistics updated: Critical 3, High 10, Medium 38, Low 12, Info 5

## [7.3.1] - 2026-03-13

### Fixed
- Removed `Cargo.lock` from `.gitignore` — binary projects must commit the lock file; `--locked` flag was failing on all CI platforms
- `ci.yml`: replaced deprecated `actions-rs/toolchain@v1` with `dtolnay/rust-toolchain@stable`
- `ci.yml`: replaced unavailable `macos-13` runner with `macos-latest`
- `ci.yml`: replaced invalid `ubuntu-22.04-arm64` runner with `ubuntu-24.04-arm` (correct GitHub-hosted ARM runner name)
- `ci.yml`: corrected binary name from `weakssl`/`weakssl.exe` to `handshaker`/`handshaker.exe` in Package steps and artifact names
- `ci.yml`: added dedicated `test` job (`cargo test --locked`) that gates all build jobs
- Deleted `release.yml` stub — redundant with `ci.yml`'s `release` job; both triggered on `v*` tags causing conflicts

## [7.3.0] - 2026-03-13

### Added
- `FINDING_INDEX.MD` — comprehensive finding reference document at project root
  - All 68 security findings across TLS (51), SSH (10), RDP (5), and General (2) protocols
  - Each finding entry includes: ID, title, severity, CVSS 3.1 score, CVSS vector, and description
  - Testssl-class coverage matrix mapping testssl.sh check categories to Handshaker finding IDs and implementation files
  - Policy profile cross-reference table showing which findings are enforced under Default, PCI-DSS, NIST 800-52r2, and CIS-Like compliance profiles

## [7.2.0] - 2026-03-13

### Added
- `handshaker help [<cmd>]` subcommand — man-page-style documentation for all 7 subcommands with NAME, SYNOPSIS, DESCRIPTION, OPTIONS, and EXAMPLES sections
- Triple-slash doc comments on every `#[arg]` field in `src/cli.rs` — all flags now show descriptions in `handshaker <cmd> --help` output
- `make ci` Makefile target that runs `fmt + test + build` for use in CI pipelines
- Per-subcommand `#[command(about = ...)]` annotations for improved `--help` top-level descriptions

### Changed
- `Cargo.toml` license corrected from `MIT OR Apache-2.0` to `GPL-3.0` (matches LICENSE file)
- Version bumped to 7.2.0
- `README.md` fully rewritten: 13-section structure covering features, installation (binaries/cargo/source/scripts), per-subcommand flag tables, usage examples, Docker, Makefile, contributing workflow, and GPL-3.0 license

## [7.1.0] - 2026-03-08

### Fixed
- SSH host-key size check no longer false-positives on Ed25519/ECDSA keys; guard is now RSA-only (RFC-compliant)
- RDP NLA finding `HS-RDP-TLS-0201` only fires when plain TLS succeeds without CredSSP (was unconditional)
- `find_by_id` upgraded from O(n) linear scan to O(1) `OnceLock<HashMap>` lookup
- `secure_renegotiation_supported` inverted logic fixed; now correctly calls `SSL_ctrl(SSL_CTRL_GET_RI_SUPPORT=76)` instead of `SSL_renegotiate`
- `read_line` in STARTTLS parser now enforces 8 KB max to prevent DoS from adversarial servers
- Wildcard SAN matching now enforces single-label only per RFC 6125 §6.4.3
- nmap XML parser handles both `Event::Empty` (self-closing) and `Event::Start` elements; MAC address entries filtered out
- `write_explain` now displays the computed CVSS score alongside the vector string

### Changed
- SQLite schema: added `UNIQUE (run_id, target, finding_id)` on `findings` table and `REFERENCES` foreign-key constraints with `PRAGMA foreign_keys = ON`
- Dependency updates: `thiserror` 1→2, `rand` 0.8→0.9 (renamed `thread_rng` → `rng`), `quick-xml` 0.31→0.37 (API update: `config_mut().trim_text()`), `rusqlite` 0.31→0.32

### Added
- Comprehensive test suite: 47 tests across 10 test binaries covering catalog, CVSS, scoring, policy evaluation, diff, benchmarking, target parsing, and input parsers
- `tempfile` dev-dependency for integration test file I/O

## [4.0.1] - 2025-10-01
- Add cross-platform install scripts for Linux/macOS (bash) and Windows (PowerShell)
- Update CI to produce predictable asset names per OS/arch
- Update README with one-line installers and install notes

## [4.0.0] - 2025-10-01
- Rewrite tooling in Rust as a zero-dependency CLI.
- Preserve legacy shell scripts in `legacy/`.
- Add Makefile and Dockerfile for builds.
- Add GitHub Actions to build on Linux/macOS/Windows (x64 + arm64).
- Generate simple HTML reports without requiring `aha`.
- Publish release artifacts on tagged builds.

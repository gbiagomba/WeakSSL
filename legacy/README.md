# Legacy Scripts

These are the original shell scripts that WeakSSL started from. They orchestrate common TLS/SSL tools (nmap, sslscan, sslyze, testssl.sh, cipherscan, ssh-audit, openssl) to detect weak ciphers and misconfigurations.

Status
- Deprecated: kept for reference and historical context.
- Replaced by the Rust CLI in the repository root. Prefer using `weakssl` from the top-level README.

Quick Start (use at your own risk)
- Ensure required tools are installed (as available on your system): `nmap`, `sslscan`, `sslyze`, `testssl.sh`, `cipherscan`, `ssh-audit`, `openssl`, and optionally `aha` for HTML formatting.
- Run one of the scripts directly, e.g.:
  - `./Weak.sh`
  - `./TLS_Check.sh`
  - `./WeakSSL2.sh`

Notes
- Scripts may assume a Unix-like environment and tools on `PATH`.
- Outputs are typically written under a local working directory (e.g., `Reports/` or a script-created workspace).
- These scripts are not actively maintained; behavior may vary across platforms and tool versions.

For the maintained CLI and usage, see the repository root `README.md`.


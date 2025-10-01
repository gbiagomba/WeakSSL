# rsc/ Resources

Reference assets related to TLS/SSL scanning. The Rust CLI does not require these at runtime; they are kept for compatibility, offline review, and documentation.

- ssl-enum-ciphers.nse: Local copy of the Nmap NSE script that enumerates supported TLS ciphersuites. Useful for reference or offline customization; Nmap ships its own copy.
- sslyze.xsl: Stylesheet for transforming SSLyze XML into HTML in legacy workflows. The Rust CLI generates simple HTML directly and does not use this.
- OpenSSL_Ciphers.txt: Reference list of OpenSSL cipher names and aliases used by older scripts when probing weak ciphers.

## Legacy Notes
- Older shell scripts (see `../legacy/`) expected this `rsc/` folder to be present and referenced a file named `WeakCiphers.txt`. In this repository, that list is provided as `OpenSSL_Ciphers.txt`.
- Those scripts are preserved for historical context; the Rust CLI is the primary entrypoint now.

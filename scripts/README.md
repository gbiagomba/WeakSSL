# Scripts

Install helpers for WeakSSL across platforms.

- install.sh: Linux/macOS installer.
  - Downloads the latest release binary when available, falling back to `cargo build --release`.
  - Installs to `/usr/local/bin/weakssl` (uses `sudo` if not root).
  - Optional env vars:
    - `WEAKSSL_VERSION`: pin a specific tag (e.g., `v0.1.0`).
    - `WEAKSSL_USE_SOURCE=1`: force source build instead of binary download.
  - Run locally: `bash install.sh`

- install.ps1: Windows installer (PowerShell).
  - Downloads the latest release binary when available, falling back to source build with `cargo`.
  - Installs to `%ProgramFiles%\weakssl.exe` and updates PATH if needed.
  - Parameters:
    - `-Version <tag>`: pin a specific release (e.g., `v0.1.0`).
    - `-UseSource`: force source build.
  - Run locally (PowerShell): `./install.ps1` or `./install.ps1 -Version v0.1.0`


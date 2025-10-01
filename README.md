# WeakSSL (Rust)
WeakSSL is a Rust-based CLI that orchestrates multiple TLS/SSL scanners (nmap, sslscan, sslyze, testssl, cipherscan, ssh-audit, and openssl) to discover weak ciphers and misconfigurations. It is a rewrite of the legacy shell scripts in `legacy/`.

The new CLI focuses on portability and zero external Rust dependencies, running the external tools when they are available and skipping gracefully when they are not.

## Features
- Orchestrates scans using popular tools and collates outputs to simple HTML reports.
- Creates a workspace with subfolders for results and reports.
- Accepts a single target, a file of targets, port lists, and a working directory override.
- Runs targeted subsets (`--nmap`, `--sslscan`, `--sslyze`, `--testssl`, `--cipherscan`, `--ssh-audit`, `--weak-openssl`) or `--all`.

## Install
- Prerequisites: a Rust toolchain (1.70+). External scanner tools are optional but recommended (nmap, sslscan, sslyze, testssl, cipherscan, ssh-audit, openssl).

Build from source:
```
make build
```

Run locally without installing:
```
make run ARGS="--help"
```

## Usage
```
weakssl [OPTIONS]

Options:
  -h, --help                 Show help
  -V, --version              Show version
  -t, --target <HOST>        Single target host/IP
  -f, --file <PATH>          File with targets (one per line)
  -p, --ports <LIST>         Comma-separated ports (default set from legacy)
  -w, --workspace <DIR>      Working directory (default: CWD)
  --nmap                     Run nmap discovery + TLS scripts
  --sslscan                  Run sslscan across targets/ports
  --sslyze                   Run sslyze across targets/ports
  --testssl                  Run testssl.sh across targets/ports
  --cipherscan               Run mozilla cipherscan (and analyze)
  --ssh-audit                Run ssh-audit across targets/ports
  --weak-openssl             Probe with openssl s_client
  -a, --all                  Run all available tools
```

Example:
```
weakssl --nmap --sslscan --file hosts.txt -p 443,8443 -w ./workspace
```

Outputs are written to `./Reports` under the chosen workspace. If `aha` is not installed, reports are simple HTML with preformatted text.

## Legacy
The previous shell scripts are preserved in `legacy/` for reference but are no longer the primary entrypoint.

## Development
- Format: `make fmt`
- Test: `make test`
- Build: `make build`

## License
This project is dual-licensed under MIT or Apache-2.0.

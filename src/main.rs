use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Default)]
struct Config {
    target: Option<String>,
    target_file: Option<PathBuf>,
    ports: Vec<u16>,
    workspace: PathBuf,
    use_nmap: bool,
    use_sslscan: bool,
    use_sslyze: bool,
    use_testssl: bool,
    use_cipherscan: bool,
    use_ssh_audit: bool,
    use_weak_openssl: bool,
    all: bool,
}

fn print_help() {
    println!("WeakSSL {VERSION}\n");
    println!("Usage: weakssl [OPTIONS]\n");
    println!("Options:");
    println!("  -h, --help                 Show this help");
    println!("  -V, --version              Show version");
    println!("  -t, --target <HOST>        Single target host/IP");
    println!("  -f, --file <PATH>          File with targets (one per line)");
    println!("  -p, --ports <LIST>         Comma-separated ports (default common TLS set)");
    println!("  -w, --workspace <DIR>      Working directory (default: CWD)");
    println!("  --nmap                     Run nmap discovery + TLS scripts");
    println!("  --sslscan                  Run sslscan across targets/ports");
    println!("  --sslyze                   Run sslyze across targets/ports");
    println!("  --testssl                  Run testssl.sh across targets/ports");
    println!("  --cipherscan               Run mozilla cipherscan (and analyze)");
    println!("  --ssh-audit                Run ssh-audit across targets/ports");
    println!("  --weak-openssl             Probe with openssl s_client and weak ciphers");
    println!("  -a, --all                  Run all available tools");
}

fn parse_args() -> Result<Config, String> {
    let mut cfg = Config::default();
    cfg.workspace = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    // Default ports from legacy/Weak.sh
    cfg.ports = vec![
        22, 25, 443, 567, 593, 808, 1433, 3389, 4443, 4848, 7103, 7201, 8443, 8888,
    ];

    let mut args = env::args().skip(1).peekable();
    if args.peek().is_none() {
        print_help();
        return Ok(cfg);
    }

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("{VERSION}");
                std::process::exit(0);
            }
            "-t" | "--target" => {
                cfg.target = args.next();
            }
            "-f" | "--file" | "--file-name" => {
                if let Some(p) = args.next() { cfg.target_file = Some(PathBuf::from(p)); }
                else { return Err("--file requires a path".into()); }
            }
            "-p" | "--ports" => {
                let val = args.next().ok_or("--ports requires a value")?;
                cfg.ports = parse_ports(&val)?;
            }
            "-w" | "--workspace" => {
                let p = args.next().ok_or("--workspace requires a path")?;
                cfg.workspace = PathBuf::from(p);
            }
            "--nmap" | "-nM" | "--network-mapper" => cfg.use_nmap = true,
            "--sslscan" | "-sC" | "--ssl-scan" => cfg.use_sslscan = true,
            "--sslyze" | "-sL" => cfg.use_sslyze = true,
            "--testssl" | "-sT" | "--ssl-test" => cfg.use_testssl = true,
            "--cipherscan" | "-cS" | "--cipher-scan" => cfg.use_cipherscan = true,
            "--ssh-audit" | "-sA" => cfg.use_ssh_audit = true,
            "--weak-openssl" | "-wC" | "--weak-cipher" => cfg.use_weak_openssl = true,
            "-a" | "--all" => cfg.all = true,
            other => return Err(format!("Unknown argument: {}", other)),
        }
    }
    Ok(cfg)
}

fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for p in s.split(',') {
        let p = p.trim();
        if p.is_empty() { continue; }
        match p.parse::<u16>() { Ok(v) => ports.push(v), Err(_) => return Err(format!("Invalid port: {}", p)) }
    }
    if ports.is_empty() { return Err("No valid ports provided".into()); }
    Ok(ports)
}

fn ensure_dirs(base: &Path) -> io::Result<()> {
    for d in [
        "Nmap", "SSLScan", "SSLyze", "Cipherscan", "TestSSL", "WeakSSL", "Reports", "SSH-Audit",
    ] {
        fs::create_dir_all(base.join(d))?;
    }
    Ok(())
}

fn read_targets(cfg: &Config) -> io::Result<Vec<String>> {
    let mut set = HashSet::new();
    if let Some(t) = &cfg.target { set.insert(t.clone()); }
    if let Some(p) = &cfg.target_file {
        let file = File::open(p)?;
        for line in io::BufReader::new(file).lines() {
            let l = line?.trim().to_string();
            if l.is_empty() || l.starts_with('#') { continue; }
            set.insert(l);
        }
    }
    Ok(set.into_iter().collect())
}

fn which(bin: &str) -> bool {
    Command::new(if cfg!(windows) { "where" } else { "which" })
        .arg(bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_cmd_save<P: AsRef<Path>>(cmd: &mut Command, out_path: P) -> io::Result<()> {
    let out_path = out_path.as_ref();
    let output = cmd.output()?;
    let mut f = File::create(out_path)?;
    f.write_all(&output.stdout)?;
    if !output.status.success() {
        let _ = writeln!(f, "\n[weakssl] Command exited with status: {:?}", output.status.code());
    }
    Ok(())
}

fn nmap_discovery(cfg: &Config, targets: &[String]) -> io::Result<PathBuf> {
    if !which("nmap") {
        eprintln!("[warn] nmap not found in PATH; skipping nmap scan");
        return Ok(cfg.workspace.join("Nmap").join("nmap_output.gnmap"));
    }
    let nmap_dir = cfg.workspace.join("Nmap");
    let input_file = cfg.workspace.join("targets.txt");
    fs::write(&input_file, targets.join("\n"))?;

    let ports_csv = cfg.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let mut nmap = Command::new("nmap");
    nmap.arg("-sS").arg("-sV")
        .arg("--script=ssh2-enum-algos,ssl-enum-ciphers,rdp-enum-encryption,vulners")
        .arg("-R").arg("-iL").arg(&input_file)
        .arg("-A").arg("-p").arg(ports_csv)
        .arg("-Pn")
        .arg("-oA").arg(nmap_dir.join("nmap_output"));
    let status = nmap.status()?;
    if !status.success() {
        eprintln!("[warn] nmap exited non-zero: {}", status);
    }

    // Try to convert XML to HTML if xsltproc is available
    let xml = nmap_dir.join("nmap_output.xml");
    if which("xsltproc") && xml.exists() {
        let _ = Command::new("xsltproc")
            .arg(&xml)
            .arg("-o")
            .arg(cfg.workspace.join("Reports").join("Nmap_SSL_Output.html"))
            .status();
    }
    Ok(nmap_dir.join("nmap_output.gnmap"))
}

fn parse_livehosts(gnmap_path: &Path, workspace: &Path) -> io::Result<Vec<String>> {
    if !gnmap_path.exists() {
        return Ok(vec![]);
    }
    let mut hosts = HashSet::new();
    let f = File::open(gnmap_path)?;
    for line in io::BufReader::new(f).lines() {
        let line = line?;
        if let Some(ip) = extract_ip(&line) {
            if line.contains("Status: Up") {
                hosts.insert(ip.to_string());
            }
        }
    }
    let livehosts = workspace.join("livehosts");
    let mut v = hosts.into_iter().collect::<Vec<_>>();
    v.sort();
    fs::write(&livehosts, v.join("\n"))?;
    Ok(v)
}

fn extract_ip(s: &str) -> Option<&str> {
    // crude IPv4 extractor: look for tokens with 3 dots and digits
    for token in s.split_whitespace() {
        if token.matches('.').count() == 3 && token.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Some(token);
        }
    }
    None
}

fn has_aha() -> bool { which("aha") }

fn html_wrap_if_aha(input: &str, title: &str) -> String {
    if has_aha() {
        // If aha exists, we will not use it here to avoid piping. Instead, we create a minimal HTML.
        // Many environments lack aha; generate simple preformatted HTML.
    }
    format!("<html><head><title>{}</title></head><body><pre>\n{}\n</pre></body></html>", title, html_escape(input))
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn run_tool_on_hosts(
    cfg: &Config,
    name: &str,
    bin: &str,
    make_cmd: &mut dyn FnMut(&str, u16) -> Command,
    report_name: &str,
    targets: &[String],
) -> io::Result<()> {
    if !which(bin) {
        eprintln!("[warn] {} not found; skipping {}", bin, name);
        return Ok(());
    }
    let mut combined = String::new();
    for host in targets {
        for &port in &cfg.ports {
            let mut cmd = make_cmd(host, port);
            match cmd.output() {
                Ok(output) => {
                    let mut section = format!(
                        "===== {} {}:{} =====\n",
                        name, host, port
                    );
                    section.push_str(&String::from_utf8_lossy(&output.stdout));
                    section.push_str("\n\n");
                    combined.push_str(&section);
                }
                Err(err) => {
                    combined.push_str(&format!("[weakssl] failed {} on {}:{} => {:?}\n", name, host, port, err));
                }
            }
        }
    }
    let html = html_wrap_if_aha(&combined, report_name);
    fs::write(cfg.workspace.join("Reports").join(report_name), html)?;
    Ok(())
}

fn main() -> io::Result<()> {
    let cfg = match parse_args() { Ok(c) => c, Err(e) => { eprintln!("{}\n", e); print_help(); std::process::exit(2); } };
    ensure_dirs(&cfg.workspace)?;

    // Build target list
    let mut targets = read_targets(&cfg)?;
    if targets.is_empty() {
        // If none given, ask interactively like legacy scripts
        eprintln!("No targets provided. Enter a path to targets file:");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let p = input.trim();
        if !p.is_empty() {
            let mut cfg2 = cfg.clone();
            cfg2.target_file = Some(PathBuf::from(p));
            targets = read_targets(&cfg2)?;
        }
    }
    if targets.is_empty() {
        eprintln!("No targets found. Exiting.");
        return Ok(());
    }

    // Always write given targets to workspace
    fs::write(cfg.workspace.join("targets.txt"), targets.join("\n"))?;

    // Nmap discovery
    let mut livehosts = targets.clone();
    if cfg.all || cfg.use_nmap {
        let gnmap = nmap_discovery(&cfg, &targets)?;
        let lh = parse_livehosts(&gnmap, &cfg.workspace)?;
        if !lh.is_empty() { livehosts = lh; }
    }

    // sslscan
    if cfg.all || cfg.use_sslscan {
        run_tool_on_hosts(&cfg, "sslscan", "sslscan",
            &mut |host, port| {
                let mut c = Command::new("sslscan");
                c.arg(format!("{}:{}", host, port));
                c
            },
            "sslscan_output.html",
            &livehosts,
        )?;
    }

    // sslyze
    if cfg.all || cfg.use_sslyze {
        run_tool_on_hosts(&cfg, "sslyze", "sslyze",
            &mut |host, port| {
                let mut c = Command::new("sslyze");
                c.arg("--regular").arg(format!("{}:{}", host, port));
                c
            },
            "sslyze_output.html",
            &livehosts,
        )?;
    }

    // testssl
    if cfg.all || cfg.use_testssl {
        run_tool_on_hosts(&cfg, "testssl", "testssl",
            &mut |host, port| {
                let mut c = Command::new("testssl");
                c.arg("--fast").arg("--sneaky").arg(format!("{}:{}", host, port));
                c
            },
            "testssl_output.html",
            &livehosts,
        )?;
    }

    // cipherscan
    if cfg.all || cfg.use_cipherscan {
        run_tool_on_hosts(&cfg, "cipherscan", "cipherscan",
            &mut |host, port| {
                let mut c = Command::new("cipherscan");
                c.arg(format!("{}:{}", host, port));
                c
            },
            "cipherscan_output.html",
            &livehosts,
        )?;
    }

    // ssh-audit
    if cfg.all || cfg.use_ssh_audit {
        run_tool_on_hosts(&cfg, "ssh-audit", "ssh-audit",
            &mut |host, port| {
                let mut c = Command::new("ssh-audit");
                c.arg(format!("{}:{}", host, port));
                c
            },
            "ssh_audit_output.html",
            &livehosts,
        )?;
    }

    // weak openssl sweep (basic banner)
    if cfg.all || cfg.use_weak_openssl {
        if which("openssl") {
            run_tool_on_hosts(&cfg, "openssl", "openssl",
                &mut |host, port| {
                    let mut c = Command::new("openssl");
                    c.arg("s_client").arg("-connect").arg(format!("{}:{}", host, port));
                    c
                },
                "openssl_output.html",
                &livehosts,
            )?;
        } else {
            eprintln!("[warn] openssl not found; skipping openssl sweep");
        }
    }

    println!("Done. Reports are in: {}", cfg.workspace.join("Reports").display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_ok() {
        let v = parse_ports("443,8443, 22").unwrap();
        assert_eq!(v, vec![443, 8443, 22]);
    }

    #[test]
    fn test_parse_ports_err() {
        assert!(parse_ports("abc").is_err());
    }

    #[test]
    fn test_extract_ip() {
        let s = "Host: 10.1.2.3 ()  Status: Up";
        assert_eq!(extract_ip(s), Some("10.1.2.3"));
    }
}

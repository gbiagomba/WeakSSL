use crate::errors::Result;
use crate::models::ScanResult;
use crate::output::csv::{cves_for_finding, cwe_for_finding};
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut buf = String::new();
    for r in results {
        buf.push_str(&format!("Target: {}:{}\n", r.target.host, r.target.port));
        for f in &r.findings {
            let cve = cves_for_finding(&f.id);
            let cwe = cwe_for_finding(&f.id);
            let refs = match (cve.is_empty(), cwe.is_empty()) {
                (false, false) => format!("  CVE: {}  CWE: {}\n", cve, cwe),
                (false, true) => format!("  CVE: {}\n", cve),
                (true, false) => format!("  CWE: {}\n", cwe),
                (true, true) => String::new(),
            };
            buf.push_str(&format!(
                "  - {} [{}] ({}) CVSS {} {:.1}  {}\n    {}\n{}",
                f.id,
                format!("{}", f.severity).to_uppercase(),
                format!("{:?}", f.protocol).to_uppercase(),
                f.cvss_vector,
                f.cvss_score,
                f.title,
                f.details,
                refs,
            ));
        }
    }
    match out {
        Some(w) => w.write_all(buf.as_bytes())?,
        None => print!("{buf}"),
    }
    Ok(())
}

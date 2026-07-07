use crate::errors::Result;
use crate::models::ScanResult;
use crate::output::csv::{cves_for_finding, cwe_for_finding};
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut buf = String::new();
    for r in results {
        for f in &r.findings {
            let finding = if f.details.is_empty() {
                f.title.clone()
            } else {
                format!("{}: {}", f.title, f.details)
            };
            let cve = cves_for_finding(&f.id);
            let cwe = cwe_for_finding(&f.id);
            buf.push_str(&format!(
                "[FINDING]\n\
                  ID:          {}\n\
                  FQDN/IP:     {}\n\
                  Port:        {}\n\
                  Protocol:    {}\n\
                  Severity:    {}\n\
                  CVSS Score:  {:.1}\n\
                  CVSS Vector: {}\n\
                  Finding:     {}\n\
                  CVE:         {}\n\
                  CWE:         {}\n\n",
                f.id,
                r.target.host,
                r.target.port,
                format!("{:?}", f.protocol).to_uppercase(),
                format!("{}", f.severity).to_uppercase(),
                f.cvss_score,
                f.cvss_vector,
                finding,
                cve,
                cwe,
            ));
        }
    }
    match out {
        Some(w) => w.write_all(buf.as_bytes())?,
        None => print!("{buf}"),
    }
    Ok(())
}

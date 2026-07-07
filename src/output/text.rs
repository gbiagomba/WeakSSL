use crate::errors::Result;
use crate::models::ScanResult;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut buf = String::new();
    for r in results {
        buf.push_str(&format!("Target: {}:{}\n", r.target.host, r.target.port));
        for f in &r.findings {
            buf.push_str(&format!(
                "  - {} [{severity}] ({protocol:?}) CVSS {cvss_vector} {cvss_score:.1}  {title}\n    {details}\n",
                f.id,
                severity = f.severity,
                protocol = f.protocol,
                cvss_vector = f.cvss_vector,
                cvss_score = f.cvss_score,
                title = f.title,
                details = f.details,
            ));
        }
    }
    match out {
        Some(w) => w.write_all(buf.as_bytes())?,
        None => print!("{buf}"),
    }
    Ok(())
}

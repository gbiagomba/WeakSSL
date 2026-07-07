use crate::errors::Result;
use crate::models::ScanResult;
use crate::output::csv::{cves_for_finding, cwe_for_finding};
use comfy_table::{Cell, Table};
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut table = Table::new();
    table.set_header(vec![
        "ID",
        "FQDN/IP",
        "Port",
        "Protocol",
        "Severity",
        "CVSS",
        "Finding",
        "CVE",
        "CWE",
    ]);
    for r in results {
        for f in &r.findings {
            let finding = if f.details.is_empty() {
                f.title.clone()
            } else {
                format!("{}: {}", f.title, f.details)
            };
            table.add_row(vec![
                Cell::new(&f.id),
                Cell::new(&r.target.host),
                Cell::new(r.target.port),
                Cell::new(format!("{:?}", f.protocol).to_uppercase()),
                Cell::new(format!("{}", f.severity).to_uppercase()),
                Cell::new(format!("{:.1}", f.cvss_score)),
                Cell::new(&finding),
                Cell::new(cves_for_finding(&f.id)),
                Cell::new(cwe_for_finding(&f.id)),
            ]);
        }
    }
    let output = table.to_string();
    match out {
        Some(w) => writeln!(w, "{output}")?,
        None => println!("{output}"),
    }
    Ok(())
}

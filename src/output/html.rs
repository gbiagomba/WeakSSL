use crate::errors::Result;
use crate::models::ScanResult;
use crate::output::csv::{cves_for_finding, cwe_for_finding};
use html_escape::encode_text;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut html = String::new();
    html.push_str(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
        <title>Handshaker Report</title>\
        <style>\
        body{font-family:sans-serif;margin:2em}\
        table{border-collapse:collapse;width:100%}\
        th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;vertical-align:top}\
        th{background:#f4f4f4}\
        .severity-critical{color:#c00;font-weight:bold}\
        .severity-high{color:#d44}\
        .severity-medium{color:#d80}\
        .severity-low{color:#88a}\
        .severity-info{color:#666}\
        </style></head><body>",
    );
    html.push_str("<h1>Handshaker Report</h1>");

    if results.is_empty() {
        html.push_str("<p><em>No results.</em></p>");
    } else {
        html.push_str(
            "<table>\
            <thead><tr>\
            <th>ID</th><th>FQDN/IP</th><th>Port</th><th>Protocol</th><th>Severity</th>\
            <th>CVSS Score</th><th>CVSS Vector</th><th>Finding</th><th>CVE</th><th>CWE</th>\
            </tr></thead><tbody>",
        );

        for r in results {
            if r.findings.is_empty() {
                html.push_str(&format!(
                    "<tr><td colspan=\"10\"><em>{}:{} — no findings</em></td></tr>",
                    encode_text(&r.target.host),
                    r.target.port,
                ));
                continue;
            }

            for f in &r.findings {
                let sev_class = match f.severity {
                    crate::models::Severity::Critical => "severity-critical",
                    crate::models::Severity::High => "severity-high",
                    crate::models::Severity::Medium => "severity-medium",
                    crate::models::Severity::Low => "severity-low",
                    crate::models::Severity::Info => "severity-info",
                };
                let finding = if f.details.is_empty() {
                    f.title.clone()
                } else {
                    format!("{}: {}", f.title, f.details)
                };
                let cve = cves_for_finding(&f.id);
                let cwe = cwe_for_finding(&f.id);
                html.push_str(&format!(
                    "<tr>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td class=\"{sev_class}\">{}</td>\
                    <td>{:.1}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    </tr>",
                    encode_text(f.id.as_str()),
                    encode_text(r.target.host.as_str()),
                    r.target.port,
                    encode_text(&format!("{:?}", f.protocol).to_uppercase()),
                    encode_text(&format!("{}", f.severity).to_uppercase()),
                    f.cvss_score,
                    encode_text(f.cvss_vector.as_str()),
                    encode_text(&finding),
                    encode_text(&cve),
                    encode_text(cwe),
                ));
            }
        }
        html.push_str("</tbody></table>");
    }

    html.push_str("</body></html>");

    match out {
        Some(w) => writeln!(w, "{html}")?,
        None => println!("{html}"),
    }
    Ok(())
}

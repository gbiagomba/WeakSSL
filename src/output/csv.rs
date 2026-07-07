use crate::errors::Result;
use crate::findings::catalog::find_by_id;
use crate::models::ScanResult;
use csv::Writer;
use std::io::Write;

pub fn write(results: &[ScanResult], out: Option<&mut dyn Write>) -> Result<()> {
    let mut buffer = Vec::new();
    {
        let mut wtr = Writer::from_writer(&mut buffer);
        wtr.write_record([
            "id",
            "fqdn/ip",
            "port",
            "protocol",
            "severity",
            "cvss_score",
            "cvss_vector",
            "finding",
            "cve",
            "cwe",
        ])?;
        for r in results {
            for f in &r.findings {
                let protocol = format!("{:?}", f.protocol).to_uppercase();
                let severity = format!("{}", f.severity).to_uppercase();
                let finding = if f.details.is_empty() {
                    f.title.clone()
                } else {
                    format!("{}: {}", f.title, f.details)
                };
                let cve = cves_for_finding(&f.id);
                let cwe = cwe_for_finding(&f.id);
                wtr.write_record([
                    f.id.as_str(),
                    r.target.host.as_str(),
                    &r.target.port.to_string(),
                    &protocol,
                    &severity,
                    &format!("{:.1}", f.cvss_score),
                    f.cvss_vector.as_str(),
                    &finding,
                    &cve,
                    cwe,
                ])?;
            }
        }
        wtr.flush()?;
    }
    match out {
        Some(w) => w.write_all(&buffer)?,
        None => std::io::stdout().write_all(&buffer)?,
    }
    Ok(())
}

/// Extract CVE IDs (e.g. "CVE-2016-0800") from the catalog entry's reference URLs.
pub fn cves_for_finding(finding_id: &str) -> String {
    let Some(meta) = find_by_id(finding_id) else {
        return String::new();
    };
    let mut seen: Vec<String> = Vec::new();
    for r in meta.references {
        if let Some(pos) = r.find("CVE-") {
            let tail = &r[pos..];
            let end = tail
                .find(|c: char| c != '-' && !c.is_ascii_alphanumeric())
                .unwrap_or(tail.len());
            let cve = &tail[..end];
            if !seen.iter().any(|s| s == cve) {
                seen.push(cve.to_owned());
            }
        }
    }
    seen.join(" ")
}

/// Map a finding ID to a CWE identifier using the dominant weakness class.
pub fn cwe_for_finding(id: &str) -> &'static str {
    if id.starts_with("HS-GENERAL-") {
        return "";
    }
    match id {
        "HS-TLS-CIPHER-0001" => "CWE-311", // NULL cipher: no encryption
        "HS-TLS-CIPHER-0002" => "CWE-295", // aNULL: no server authentication
        "HS-TLS-CERT-0001" | "HS-TLS-CERT-0002" => "CWE-298", // certificate validity
        "HS-TLS-CERT-0003" => "CWE-295",   // self-signed: improper cert validation
        "HS-TLS-CERT-0004" => "CWE-297",   // hostname mismatch
        "HS-RDP-TLS-0201" => "CWE-287",    // no NLA: improper authentication
        _ => "CWE-326",                    // inadequate encryption strength
    }
}

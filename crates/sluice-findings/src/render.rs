//! Output renderers: Markdown, JSON, SARIF, HTML, and a terminal summary.

use crate::finding::{Finding, Severity};
use serde_json::json;

/// Group findings by severity (Critical→Info), returning counts.
pub fn severity_counts(findings: &[Finding]) -> [(Severity, usize); 5] {
    let mut counts = [
        (Severity::Critical, 0),
        (Severity::High, 0),
        (Severity::Medium, 0),
        (Severity::Low, 0),
        (Severity::Info, 0),
    ];
    for f in findings {
        for c in counts.iter_mut() {
            if c.0 == f.severity {
                c.1 += 1;
            }
        }
    }
    counts
}

/// A compact one-line-per-finding terminal summary (no color codes; the CLI adds those).
pub fn console_summary(findings: &[Finding]) -> String {
    let mut out = String::new();
    for f in findings {
        out.push_str(&format!(
            "[{:>8}] {:<22} {}:{}  {}\n",
            f.severity.label(),
            f.category.slug(),
            f.file,
            f.line,
            f.title
        ));
    }
    let c = severity_counts(findings);
    out.push_str(&format!(
        "\n{} findings — Critical {}, High {}, Medium {}, Low {}, Info {}\n",
        findings.len(),
        c[0].1,
        c[1].1,
        c[2].1,
        c[3].1,
        c[4].1
    ));
    out
}

/// Full Markdown report with traces and recommendations.
pub fn markdown(findings: &[Finding], project: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!("# Sluice report — {project}\n\n"));
    let c = severity_counts(findings);
    s.push_str("| Severity | Count |\n|---|---|\n");
    for (sev, n) in c {
        s.push_str(&format!("| {} | {} |\n", sev.label(), n));
    }
    s.push_str(&format!("| **Total** | **{}** |\n\n", findings.len()));

    for f in findings {
        s.push_str(&format!("## {} — {}\n\n", f.id, f.title));
        s.push_str(&format!(
            "- **Severity:** {} (score {:.0})  \n- **Confidence:** {:.0}%  \n- **Category:** `{}`  \n- **Detector:** `{}`  \n- **Location:** `{}:{}` in `{}.{}`\n",
            f.severity.label(),
            f.severity_score,
            f.confidence * 100.0,
            f.category.slug(),
            f.detector,
            f.file,
            f.line,
            f.contract,
            f.function,
        ));
        if !f.dimensions.is_empty() {
            let dims: Vec<&str> = f.dimensions.iter().map(|d| d.label()).collect();
            s.push_str(&format!("- **Corroborating dimensions:** {}\n", dims.join(" + ")));
        }
        s.push('\n');
        if !f.snippet.is_empty() {
            s.push_str(&format!("```solidity\n{}\n```\n\n", f.snippet));
        }
        s.push_str(&format!("{}\n\n", f.message));
        if !f.trace.is_empty() {
            s.push_str("**Value-flow trace:**\n\n");
            for (i, t) in f.trace.iter().enumerate() {
                s.push_str(&format!("{}. {} — `{}:{}`  `{}`\n", i + 1, t.label, t.file, t.line, t.snippet));
            }
            s.push('\n');
        }
        if !f.recommendation.is_empty() {
            s.push_str(&format!("**Recommendation:** {}\n\n", f.recommendation));
        }
        if let Some(poc) = &f.poc {
            s.push_str("**Proof-of-concept (Foundry):**\n\n```solidity\n");
            s.push_str(poc);
            s.push_str("\n```\n\n");
        }
        if !f.references.is_empty() {
            s.push_str(&format!("*References: {}*\n\n", f.references.join(", ")));
        }
        s.push_str("---\n\n");
    }
    s
}

/// Machine-readable JSON array of findings.
pub fn json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".into())
}

/// SARIF 2.1.0 for CI / IDE consumption.
pub fn sarif(findings: &[Finding]) -> String {
    let rules: Vec<_> = {
        let mut seen = std::collections::BTreeSet::new();
        findings
            .iter()
            .filter(|f| seen.insert(f.category.slug()))
            .map(|f| {
                json!({
                    "id": f.category.slug(),
                    "name": f.category.slug(),
                    "helpUri": "https://github.com/0xCyberstan/sluice",
                    "properties": { "references": f.references }
                })
            })
            .collect()
    };

    let results: Vec<_> = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.category.slug(),
                "level": f.severity.sarif_level(),
                "message": { "text": format!("{}: {}", f.title, f.message) },
                "properties": {
                    "severity": f.severity.label(),
                    "score": f.severity_score,
                    "confidence": f.confidence,
                    "dimensions": f.dimensions.iter().map(|d| d.label()).collect::<Vec<_>>(),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": { "startLine": f.line.max(1) }
                    }
                }]
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Sluice",
                "informationUri": "https://github.com/0xCyberstan/sluice",
                "rules": rules
            }},
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

/// A self-contained styled HTML report.
pub fn html(findings: &[Finding], project: &str) -> String {
    let c = severity_counts(findings);
    let mut rows = String::new();
    for f in findings {
        let color = match f.severity {
            Severity::Critical => "#b00020",
            Severity::High => "#d35400",
            Severity::Medium => "#b8860b",
            Severity::Low => "#2c7",
            Severity::Info => "#789",
        };
        rows.push_str(&format!(
            "<div class='f'><span class='sev' style='background:{}'>{}</span> \
             <span class='cat'>{}</span> <b>{}</b><div class='loc'>{}:{} · {}.{} · conf {:.0}%</div>\
             <pre>{}</pre><p>{}</p>{}</div>",
            color,
            f.severity.label(),
            f.category.slug(),
            html_escape(&f.title),
            html_escape(&f.file),
            f.line,
            html_escape(&f.contract),
            html_escape(&f.function),
            f.confidence * 100.0,
            html_escape(&f.snippet),
            html_escape(&f.message),
            if f.recommendation.is_empty() {
                String::new()
            } else {
                format!("<p class='rec'>💡 {}</p>", html_escape(&f.recommendation))
            }
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>Sluice — {project}</title>\
        <style>body{{font:14px/1.5 system-ui,sans-serif;max-width:920px;margin:2rem auto;color:#222}}\
        h1{{font-size:1.4rem}}.sum span{{display:inline-block;padding:.2rem .6rem;margin:.2rem;border-radius:4px;background:#eee}}\
        .f{{border:1px solid #e3e3e3;border-radius:8px;padding:1rem;margin:1rem 0}}\
        .sev{{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.8rem;font-weight:600}}\
        .cat{{color:#666;font-family:monospace;margin-left:.5rem}}.loc{{color:#888;font-size:.85rem;margin:.3rem 0}}\
        pre{{background:#f6f8fa;padding:.6rem;border-radius:6px;overflow:auto;font-size:.85rem}}\
        .rec{{color:#0a7}}</style></head><body>\
        <h1>Sluice report — {project}</h1>\
        <div class='sum'><span>Critical {}</span><span>High {}</span><span>Medium {}</span><span>Low {}</span><span>Info {}</span></div>\
        {}</body></html>",
        c[0].1, c[1].1, c[2].1, c[3].1, c[4].1, rows
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

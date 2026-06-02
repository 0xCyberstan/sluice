//! # sluice-findings
//!
//! The output pipeline: the [`Finding`] model that every detector populates,
//! an ergonomic [`FindingBuilder`], and renderers (Markdown / JSON / SARIF /
//! HTML / console). The analog of `vortex-findings`.

mod builder;
mod finding;
mod render;

pub use builder::{trace_step, FindingBuilder};
pub use finding::{Category, Dimension, Finding, Severity, TraceStep};
pub use render::{console_summary, html, json, markdown, sarif, severity_counts};

/// Convenience: start building a finding.
pub fn finding(detector: impl Into<String>, category: Category) -> FindingBuilder {
    FindingBuilder::new(detector, category)
}

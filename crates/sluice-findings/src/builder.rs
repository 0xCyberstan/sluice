//! Ergonomic [`Finding`] construction for detector authors.

use crate::finding::{Category, Dimension, Finding, Severity, TraceStep};
use sluice_ir::{Scir, Span};

/// A fluent builder. The engine assigns the final `id` and `severity_score`
/// after corroboration scoring, so detectors only express intent.
pub struct FindingBuilder {
    f: Finding,
}

impl FindingBuilder {
    pub fn new(detector: impl Into<String>, category: Category) -> Self {
        let references = category.references().iter().map(|s| s.to_string()).collect();
        FindingBuilder {
            f: Finding {
                id: String::new(),
                detector: detector.into(),
                title: String::new(),
                category,
                severity: Severity::Medium,
                severity_score: 0.0,
                confidence: 0.5,
                contract: String::new(),
                function: String::new(),
                file: String::new(),
                line: 0,
                span: Span::dummy(),
                snippet: String::new(),
                message: String::new(),
                recommendation: String::new(),
                dimensions: Vec::new(),
                trace: Vec::new(),
                references,
                poc: None,
                tags: Vec::new(),
            },
        }
    }

    pub fn title(mut self, t: impl Into<String>) -> Self {
        self.f.title = t.into();
        self
    }

    pub fn severity(mut self, s: Severity) -> Self {
        self.f.severity = s;
        self
    }

    pub fn confidence(mut self, c: f32) -> Self {
        self.f.confidence = c.clamp(0.0, 1.0);
        self
    }

    pub fn message(mut self, m: impl Into<String>) -> Self {
        self.f.message = m.into();
        self
    }

    pub fn recommendation(mut self, r: impl Into<String>) -> Self {
        self.f.recommendation = r.into();
        self
    }

    pub fn dimension(mut self, d: Dimension) -> Self {
        if !self.f.dimensions.contains(&d) {
            self.f.dimensions.push(d);
        }
        self
    }

    pub fn dimensions(mut self, ds: impl IntoIterator<Item = Dimension>) -> Self {
        for d in ds {
            self = self.dimension(d);
        }
        self
    }

    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.f.tags.push(t.into());
        self
    }

    pub fn reference(mut self, r: impl Into<String>) -> Self {
        self.f.references.push(r.into());
        self
    }

    pub fn trace_step(mut self, step: TraceStep) -> Self {
        self.f.trace.push(step);
        self
    }

    /// Resolve `file`/`line`/`snippet` from the IR span and set contract/function.
    pub fn at(mut self, scir: &Scir, contract: impl Into<String>, function: impl Into<String>, span: Span) -> Self {
        let (file, line) = scir.location(span);
        self.f.contract = contract.into();
        self.f.function = function.into();
        self.f.file = file;
        self.f.line = line;
        self.f.span = span;
        self.f.snippet = scir.line_text(span);
        self
    }

    /// Set location fields directly (when no `Scir` is convenient).
    pub fn location(
        mut self,
        contract: impl Into<String>,
        function: impl Into<String>,
        file: impl Into<String>,
        line: usize,
        snippet: impl Into<String>,
    ) -> Self {
        self.f.contract = contract.into();
        self.f.function = function.into();
        self.f.file = file.into();
        self.f.line = line;
        self.f.snippet = snippet.into();
        self
    }

    pub fn build(self) -> Finding {
        self.f
    }
}

/// Convenience helper to make a trace step from an IR span.
pub fn trace_step(scir: &Scir, label: impl Into<String>, span: Span) -> TraceStep {
    let (file, line) = scir.location(span);
    TraceStep {
        label: label.into(),
        file,
        line,
        snippet: scir.line_text(span),
    }
}

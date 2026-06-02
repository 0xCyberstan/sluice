//! The `Detector` trait — the unit of analysis plugged into the engine.

use crate::context::AnalysisContext;
use sluice_findings::{Category, Finding};

/// A detector inspects the [`AnalysisContext`] (IR + the three analysis
/// dimensions) and emits findings. Detectors are stateless and `Sync` so the
/// engine can run them in parallel with rayon.
pub trait Detector: Sync + Send {
    /// Stable id, e.g. `"reentrancy"`. Must match a [`Category::slug`] where
    /// possible so config enable/disable is intuitive.
    fn id(&self) -> &'static str;

    /// The primary category of findings this detector emits.
    fn category(&self) -> Category;

    /// One-line description (shown by `sluice detectors`).
    fn description(&self) -> &'static str;

    /// Run against a fully-prepared analysis context.
    fn run(&self, cx: &AnalysisContext) -> Vec<Finding>;
}

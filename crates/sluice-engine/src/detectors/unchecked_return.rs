//! Unchecked external-call return values and unsafe ERC-20 transfers.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::CallKind;

pub struct UncheckedReturnDetector;

impl Detector for UncheckedReturnDetector {
    fn id(&self) -> &'static str {
        "unchecked-return"
    }
    fn category(&self) -> Category {
        Category::UncheckedReturn
    }
    fn description(&self) -> &'static str {
        "Ignored return of low-level call / send / ERC-20 transfer"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for c in cx.frontier.unchecked_returns() {
            // Only value-moving transfers matter here. `approve` (and especially
            // `approve(spender, 0)` resets) returns a bool that is conventionally
            // ignored and is not a fund-loss vector — flagging it was noise.
            let is_token_call = matches!(
                c.func_name.as_deref(),
                Some("transfer") | Some("transferFrom")
            ) && c.kind == CallKind::External;

            // Only two cases are genuinely "unchecked return" bugs:
            //   (a) a raw low-level call / send (the boolean really is dropped), or
            //   (b) a RAW ERC-20 transfer/transferFrom/approve (returns a bool).
            // Any other external call (notify hooks, `safe*` wrappers that revert,
            // arbitrary contract methods) is NOT a finding — flagging those was a
            // major false-positive source.
            let is_low_level = matches!(c.kind, CallKind::LowLevelCall | CallKind::Send);
            if !is_low_level && !is_token_call {
                continue;
            }
            // `safe*` wrappers (SafeERC20 / Address.sendValue) revert on failure;
            // ignoring their return is correct.
            if c.func_name.as_deref().map(|n| n.starts_with("safe")).unwrap_or(false) {
                continue;
            }

            // SafeERC20 in scope → token transfers are safe.
            if is_token_call && cx.uses_safe_erc20(c.contract) {
                continue;
            }

            let (cat, title, sev, msg, rec) = if is_token_call {
                (
                    Category::UnsafeErc20,
                    "Unchecked ERC-20 transfer",
                    Severity::Medium,
                    "calls a raw ERC-20 transfer/approve and ignores the boolean return. Non-standard \
                     tokens (USDT, etc.) return false or revert, silently losing funds.",
                    "Use OpenZeppelin `SafeERC20` (`safeTransfer`/`safeTransferFrom`).",
                )
            } else {
                (
                    Category::UncheckedReturn,
                    "Unchecked low-level call",
                    Severity::Medium,
                    "ignores the success boolean of a low-level call/send. A failed call is swallowed, \
                     leaving the contract in an inconsistent state.",
                    "Check the returned success flag (`require(ok)`), or use a checked wrapper.",
                )
            };

            let (cname, fname) = cx.names(c.function);
            let b = FindingBuilder::new(self.id(), cat)
                .title(title)
                .severity(sev)
                .confidence(0.6)
                .dimension(Dimension::Frontier)
                .message(format!("`{cname}.{fname}` {msg}"))
                .recommendation(rec);
            out.push(cx.finish(b, c.function, c.span));
        }
        out
    }
}

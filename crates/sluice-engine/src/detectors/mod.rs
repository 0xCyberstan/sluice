//! Built-in detectors. Each module is one detector implementing
//! [`crate::detector::Detector`]. New detectors only need to (a) implement the
//! trait and (b) be added to [`builtin_detectors`].

pub mod accounting;
pub mod access_control;
pub mod oracle;
pub mod reentrancy;
pub mod signature;
pub mod unchecked_return;
pub mod upgradeable;
pub mod vault;

use crate::detector::Detector;

/// The registry of built-in detectors.
pub fn builtin_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(reentrancy::ReentrancyDetector),
        Box::new(access_control::AccessControlDetector),
        Box::new(oracle::OracleDetector),
        Box::new(unchecked_return::UncheckedReturnDetector),
        Box::new(accounting::AccountingDetector),
        Box::new(signature::SignatureDetector),
        Box::new(upgradeable::UpgradeableDetector),
        Box::new(vault::VaultDetector),
    ]
}

// ----------------------------------------------------------------- shared utils

use sluice_ir::{Expr, ExprKind, Function, Span};

/// Find the first spot-price call (`balanceOf`, `getReserves`, ...) in a
/// function body, returning its span.
pub(crate) fn find_spot_price(f: &Function) -> Option<Span> {
    let mut found = None;
    for s in &f.body {
        s.visit_exprs(&mut |e| {
            if found.is_some() {
                return;
            }
            if let ExprKind::Call(c) = &e.kind {
                if sluice_dataflow::is_spot_price_call(c) {
                    found = Some(e.span);
                }
            }
        });
    }
    found
}

/// Does a name look like protocol accounting state (balance, collateral, debt,
/// shares, price, reserves, amount)?
pub(crate) fn is_accounting_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "balance", "collateral", "debt", "share", "deposit", "borrow", "reserve", "price", "amount",
        "liquidity", "total", "supply", "assets", "rate",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Names that indicate privileged/admin state.
pub(crate) fn is_privileged_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "owner", "admin", "governance", "governor", "operator", "treasury", "fee", "implementation",
        "paused", "oracle", "pricefeed", "whitelist", "blacklist", "minter", "role", "pending",
        "proxy", "beacon", "guardian", "authority", "manager",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Visit every call expression in a function body.
pub(crate) fn visit_calls<'a>(f: &'a Function, mut visit: impl FnMut(&'a sluice_ir::Call, Span)) {
    for s in &f.body {
        s.visit_exprs(&mut |e: &'a Expr| {
            if let ExprKind::Call(c) = &e.kind {
                visit(c, e.span);
            }
        });
    }
}

//! Missing access control, consensus-guard outliers, and `tx.origin` auth.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use crate::detectors::is_privileged_name;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_invariant::InvariantKind;
use sluice_ir::GuardKind;

pub struct AccessControlDetector;

impl Detector for AccessControlDetector {
    fn id(&self) -> &'static str {
        "access-control"
    }
    fn category(&self) -> Category {
        Category::AccessControl
    }
    fn description(&self) -> &'static str {
        "Unprotected privileged functions, guard-consensus outliers, tx.origin auth"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();

        // (1) Consensus guard violations (most siblings enforce access control).
        for v in &cx.invariants.violations {
            if let InvariantKind::GuardConsensus { guard } = &v.kind {
                if guard == "access-control" {
                    // Initializers are guarded by `initializer` (not a per-call auth
                    // modifier), and user-facing functions (deposit/withdraw/claim/…)
                    // are intentionally permissionless — neither is a missing-guard
                    // bug, so don't report them as consensus violations.
                    if let Some(f) = cx.scir.function(v.function) {
                        // A function with its own inline `require(msg.sender == …)`
                        // guard is not "missing" the sibling guard — it enforces it
                        // in a different form. (The root cause is also fixed in
                        // effects ordering, but this keeps the consensus path robust
                        // to any guard the miner doesn't model.)
                        if cx.has_access_control(f)
                            || cx.is_initializer(f)
                            || is_oneshot_initializer(f)
                            || is_user_facing(&f.name)
                            || is_framework_hook(&f.name)
                        {
                            continue;
                        }
                        // An empty / no-op body (e.g. `fallback() external payable {}`
                        // or a stub `receive`) performs no privileged action — there is
                        // nothing for the sibling guard to protect, so a missing guard
                        // is not a bug. Likewise, a function that mutates no privileged
                        // (non-mapping) state is not the "missing-onlyOwner" class the
                        // consensus invariant targets (e.g. a permissionless `deploy`
                        // that only emits an event and clones via a factory). Requiring
                        // a privileged write keeps the genuine TPs — an unguarded
                        // `owner = …` / `admin = …` setter still writes privileged state.
                        if is_noop_body(f) || !writes_privileged_state(cx, f) {
                            continue;
                        }
                    }
                    let conf = (v.consensus * 0.9).clamp(0.4, 0.9);
                    let b = FindingBuilder::new(self.id(), Category::AccessControl)
                        .title("Function skips the access-control guard its siblings enforce")
                        .severity(Severity::High)
                        .confidence(conf)
                        .dimension(Dimension::Invariant)
                        .message(v.description.clone())
                        .recommendation("Add the same authorization modifier/require used by sibling functions.");
                    out.push(cx.finish(b, v.function, v.span));
                }
            }
        }

        // (2) Direct: external state-mutating function writes privileged state
        //     with no access control or initializer guard.
        for f in cx.entry_points() {
            // (3) tx.origin authorization — checked FIRST, because a tx.origin
            // guard is itself the vulnerability and would otherwise be mistaken
            // for valid access control and suppressed.
            if uses_tx_origin_auth(cx, f) {
                let b = FindingBuilder::new(self.id(), Category::TxOriginAuth)
                    .title("Authorization via tx.origin")
                    .severity(Severity::High)
                    .confidence(0.7)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` authorizes using `tx.origin`, which is phishable: a malicious \
                         intermediary contract the owner is tricked into calling passes the check \
                         on the victim's behalf.",
                        f.name
                    ))
                    .recommendation("Use `msg.sender` for authorization, never `tx.origin`.");
                out.push(cx.finish(b, f.id, f.span));
            }

            if cx.has_access_control(f)
                || cx.is_initializer(f)
                || is_oneshot_initializer(f)
                || f.is_constructor()
                || is_framework_hook(&f.name)
                || is_noop_body(f)
            {
                continue;
            }
            // Admin state is a scalar (`owner = x`), not a per-key mapping write
            // (which is ordinary per-entity bookkeeping). Skip mapping writes.
            let is_mapping_var = |name: &str| {
                cx.contract_of(f.id)
                    .and_then(|c| c.state_vars.iter().find(|v| v.name == name))
                    .map(|v| v.is_mapping())
                    .unwrap_or(false)
            };
            let priv_write = f
                .effects
                .storage_writes
                .iter()
                .find(|w| is_privileged_name(&w.var) && !is_mapping_var(&w.var));
            if let Some(w) = priv_write {
                // skip if a sibling-consensus finding already covers it (dedup by line later)
                let b = FindingBuilder::new(self.id(), Category::AccessControl)
                    .title("Privileged state mutable by anyone")
                    .severity(Severity::High)
                    .confidence(0.5)
                    .dimension(Dimension::Invariant)
                    .message(format!(
                        "`{}` writes privileged state `{}` but has no `onlyOwner`/role guard, so any \
                         caller can change it.",
                        f.name, w.var
                    ))
                    .recommendation("Restrict with an access-control modifier (e.g. `onlyOwner`/`onlyRole`).");
                out.push(cx.finish(b, f.id, w.span));
            }

        }
        out
    }
}

/// Framework / standard lifecycle hooks that look unguarded but are gated by an
/// implicit single trusted caller (e.g. a Kernel) or are pure metadata — flagging
/// them for "missing access control" is a false positive (Default Framework's
/// `configureDependencies`/`requestPermissions`, ERC-165 `supportsInterface`, …).
fn is_framework_hook(name: &str) -> bool {
    matches!(
        name,
        "configureDependencies"
            | "requestPermissions"
            | "supportsInterface"
            | "KEYCODE"
            | "VERSION"
            | "changeKernel"
            | "onERC721Received"
            | "onERC1155Received"
            | "onERC1155BatchReceived"
            | "tokensReceived"
    )
}

/// True if the function body performs no privileged action: it writes no state
/// and makes no external/low-level/value-transferring call. An empty
/// `fallback() external payable {}` / stub `receive()` / no-op function has
/// nothing for an access-control guard to protect, so "missing access control"
/// is a false positive.
fn is_noop_body(f: &sluice_ir::Function) -> bool {
    f.effects.storage_writes.is_empty()
        && f.effects.internal_calls.is_empty()
        && !f.effects.call_sites.iter().any(|c| c.kind.is_external_transfer_of_control())
}

/// True if the function writes privileged (non-mapping) admin state — the thing
/// an access-control guard exists to protect. Mapping writes are ordinary
/// per-entity bookkeeping (mirrors the direct-path mapping skip), and a function
/// that writes no privileged scalar (e.g. a permissionless `deploy` that only
/// emits an event) is not the missing-`onlyOwner` class.
fn writes_privileged_state(cx: &AnalysisContext, f: &sluice_ir::Function) -> bool {
    let is_mapping_var = |name: &str| {
        cx.contract_of(f.id)
            .and_then(|c| c.state_vars.iter().find(|v| v.name == name))
            .map(|v| v.is_mapping())
            .unwrap_or(false)
    };
    f.effects
        .storage_writes
        .iter()
        .any(|w| is_privileged_name(&w.var) && !is_mapping_var(&w.var))
}

/// True if the function is a guarded one-shot initializer of the OpenZeppelin
/// shape — `require(!initialized)` / `if (version != 0) revert` followed by the
/// body setting that same init flag. This is *not* "missing access control":
/// the init-flag guard makes the privileged setup callable exactly once, which
/// is the standard upgradeable-proxy initializer. It is recognized in addition
/// to the `initializer`/`reinitializer` *modifier* (`cx.is_initializer`).
///
/// Crucially this only fires when a leading guard actually references the same
/// flag the body writes, so a genuinely unguarded setup function (e.g. Parity's
/// `initWallet`, which has no guard at all) is still reported.
fn is_oneshot_initializer(f: &sluice_ir::Function) -> bool {
    f.effects.guards.iter().any(|g| {
        matches!(g.kind, GuardKind::Require | GuardKind::MsgSenderCheck)
            && f.effects.storage_writes.iter().any(|w| {
                is_init_flag_name(&w.var) && guard_mentions_var(&g.text, &w.var)
            })
    })
}

/// A state-variable name that denotes a one-time-initialization flag rather than
/// privileged config (so a guard on it marks a one-shot initializer).
fn is_init_flag_name(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    let l = l.trim_start_matches('_');
    l == "initialized"
        || l == "version"
        || l == "initializing"
        || l == "initialised"
        || l == "isinitialized"
}

/// Whole-identifier match of `var` inside a guard's textual condition (so
/// `version` does not match `versionMajor`).
fn guard_mentions_var(text: &str, var: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let bytes = text.as_bytes();
    let v = var.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find(var) {
        let start = i + pos;
        let end = start + v.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1] as char);
        let after_ok = end >= bytes.len() || !is_ident(bytes[end] as char);
        if before_ok && after_ok {
            return true;
        }
        i = start + 1;
    }
    false
}

/// Intentionally-permissionless, user-facing function names that should not be
/// flagged for "missing the access-control guard their siblings enforce".
fn is_user_facing(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    [
        "deposit", "withdraw", "claim", "mint", "redeem", "stake", "unstake", "swap", "borrow",
        "repay", "transfer", "approve", "permit", "wrap", "unwrap", "harvest", "compound",
        "flashloan", "liquidate", "enter", "exit", "vote", "delegate",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// True if a function authorizes via `tx.origin` — either directly in its body
/// or through an applied modifier whose body reads `tx.origin`.
fn uses_tx_origin_auth(cx: &AnalysisContext, f: &sluice_ir::Function) -> bool {
    if f.effects.reads_tx_origin && f.effects.guards.iter().any(|g| g.text.contains("tx.origin")) {
        return true;
    }
    // Look through applied modifiers (the `onlyOwner { require(tx.origin == owner) }` case).
    for m in &f.modifiers {
        if let Some(modf) = cx
            .scir
            .functions_of(f.contract)
            .find(|x| x.is_modifier() && x.name == m.name)
        {
            if modf.effects.reads_tx_origin {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    use sluice_findings::Finding;

    /// All access-control-detector findings for a source blob.
    fn ac_findings(src: &str) -> Vec<Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default())
            .findings
            .into_iter()
            .filter(|f| f.detector == "access-control")
            .collect()
    }

    fn fires_on(src: &str, func: &str) -> bool {
        ac_findings(src).iter().any(|f| f.function == func)
    }

    // ---- FP: empty `fallback() external payable {}` (Compound Timelock /
    // MarketUpdateTimelock). A no-op fallback performs no privileged action, so
    // the consensus path must NOT flag it for "skipping" the sibling guard. ----
    #[test]
    fn silent_on_empty_fallback() {
        // Mirror Timelock: most siblings enforce `require(msg.sender == ...)`, so
        // the access-control consensus is strong, but the empty fallback is a no-op.
        let src = r#"
            contract Timelock {
                address public admin;
                address public pendingAdmin;
                uint public delay;
                mapping (bytes32 => bool) public queuedTransactions;
                fallback() external payable { }
                function setDelay(uint d) public {
                    require(msg.sender == address(this), "self");
                    delay = d;
                }
                function acceptAdmin() public {
                    require(msg.sender == pendingAdmin, "pa");
                    admin = msg.sender;
                    pendingAdmin = address(0);
                }
                function setPendingAdmin(address a) public {
                    require(msg.sender == address(this), "self");
                    pendingAdmin = a;
                }
                function queueTransaction(bytes32 h) public {
                    require(msg.sender == admin, "admin");
                    queuedTransactions[h] = true;
                }
                function cancelTransaction(bytes32 h) public {
                    require(msg.sender == admin, "admin");
                    queuedTransactions[h] = false;
                }
            }
        "#;
        assert!(!fires_on(src, "fallback"), "empty fallback must not be flagged");
    }

    // ---- FP: empty `receive() external payable {}` is likewise a no-op. ----
    #[test]
    fn silent_on_empty_receive() {
        let src = r#"
            contract Vault {
                address public owner;
                address public guardian;
                receive() external payable { }
                function setOwner(address o) external { require(msg.sender == owner); owner = o; }
                function setGuardian(address g) external { require(msg.sender == owner); guardian = g; }
                function poke() external { require(msg.sender == owner); }
            }
        "#;
        assert!(!fires_on(src, "receive"), "empty receive must not be flagged");
    }

    // ---- FP: OZ-style one-shot initializer guarded by a version/initialized flag
    // (Compound Configurator.initialize). `if (version != 0) revert; ...; version = 1;`
    // makes the privileged setup callable exactly once — not "missing access
    // control". Must stay silent on BOTH the consensus and direct paths. ----
    #[test]
    fn silent_on_version_guarded_initializer() {
        let src = r#"
            contract Configurator {
                uint public version;
                address public governor;
                error AlreadyInitialized();
                error InvalidAddress();
                error Unauthorized();
                function initialize(address governor_) public {
                    if (version != 0) revert AlreadyInitialized();
                    if (governor_ == address(0)) revert InvalidAddress();
                    governor = governor_;
                    version = 1;
                }
                function setFactory(address p, address f) external {
                    if (msg.sender != governor) revert Unauthorized();
                    governor = f;
                }
                function transferGovernor(address g) external {
                    if (msg.sender != governor) revert Unauthorized();
                    governor = g;
                }
                function setOther(address g) external {
                    if (msg.sender != governor) revert Unauthorized();
                    governor = g;
                }
            }
        "#;
        assert!(!fires_on(src, "initialize"), "version-guarded one-shot initializer must not be flagged");
    }

    // ---- FP: a `require(!initialized)` one-shot initializer is the same shape. ----
    #[test]
    fn silent_on_initialized_flag_initializer() {
        let src = r#"
            contract Proxy {
                bool public initialized;
                address public owner;
                function initialize(address o) external {
                    require(!initialized, "init");
                    initialized = true;
                    owner = o;
                }
                function setOwner(address o) external { require(msg.sender == owner); owner = o; }
                function a() external { require(msg.sender == owner); }
                function b() external { require(msg.sender == owner); }
            }
        "#;
        assert!(!fires_on(src, "initialize"), "require(!initialized) initializer must not be flagged");
    }

    // ---- FP: a permissionless function that writes NO privileged state
    // (Compound Configurator.deploy — only emits an event + clones via a
    // factory). The consensus path must not flag it just for lacking the guard. ----
    #[test]
    fn silent_on_permissionless_deploy_no_privileged_write() {
        let src = r#"
            interface IFactory { function clone(address) external returns (address); }
            contract Configurator {
                address public governor;
                mapping(address => address) public factory;
                event CometDeployed(address indexed p, address indexed c);
                error Unauthorized();
                function deploy(address cometProxy) external returns (address) {
                    address newComet = IFactory(factory[cometProxy]).clone(cometProxy);
                    emit CometDeployed(cometProxy, newComet);
                    return newComet;
                }
                function setGovernor(address g) external { if (msg.sender != governor) revert Unauthorized(); governor = g; }
                function setFactory(address p, address f) external { if (msg.sender != governor) revert Unauthorized(); factory[p] = f; }
                function transferGovernor(address g) external { if (msg.sender != governor) revert Unauthorized(); governor = g; }
            }
        "#;
        assert!(!fires_on(src, "deploy"), "permissionless deploy with no privileged write must not be flagged");
    }

    // ---- TP guard: a genuinely unguarded privileged setter MUST still fire. ----
    #[test]
    fn fires_on_unguarded_owner_setter() {
        let src = r#"
            contract FeeManager {
                address public owner;
                function setOwner(address newOwner) external { owner = newOwner; }
                function noop() external {}
            }
        "#;
        assert!(fires_on(src, "setOwner"), "unguarded owner setter must still fire (recall)");
    }

    // ---- TP guard: Parity-style `initWallet` writes `owner` with NO guard of any
    // kind. It looks initializer-named but is NOT a one-shot guarded init, so it
    // MUST still fire (the $150M Parity class). ----
    #[test]
    fn fires_on_unguarded_init_owner_write() {
        let src = r#"
            contract ParityWallet {
                address public owner;
                receive() external payable {}
                function initWallet(address _owner) external { owner = _owner; }
                function execute(address to, uint256 amt) external { require(msg.sender == owner); }
                function withdraw(address to, uint256 amt) external { require(msg.sender == owner); }
                function kill(address to) external { require(msg.sender == owner); selfdestruct(payable(to)); }
            }
        "#;
        assert!(fires_on(src, "initWallet"), "unguarded initWallet (Parity) must still fire (recall)");
    }
}


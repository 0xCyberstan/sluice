//! Hook-callback reentrancy: an external token operation that *looks* inert (a
//! "plain ERC20" `transfer`/`transferFrom`/`mint`/`send`) but actually hands
//! control to the caller via a token-standard receive hook
//! (ERC777 `tokensReceived`/`tokensToSend`, ERC721 `onERC721Received`). If such
//! a call precedes a state update and the function has no reentrancy guard, the
//! callee can re-enter before storage settles.
//!
//! This is the dForce / Lendf.me ($25M) class: the protocol believed it was
//! interacting with a vanilla ERC20, but the token implemented ERC777, so the
//! "interaction" was really an attacker-controlled callback executed *before*
//! the "effects" — a checks-effects-interactions violation hidden behind a
//! transfer that the developer assumed could not re-enter.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::CallKind;

pub struct Erc777Detector;

/// Token-operation method names that carry a standard receive/send hook. A call
/// to any of these on an external token can dispatch control to a counterparty
/// contract (ERC777 `tokensReceived`/`tokensToSend`, ERC721 `onERC721Received`),
/// even though the call site reads like an ordinary ERC20 movement.
// Only genuinely hook-dispatching ops. Plain ERC-20 `transfer`/`transferFrom`
// are intentionally excluded: those are already covered by the generic
// reentrancy detector, and including them double-reported every standard
// `transferFrom`-then-update deposit. This detector is specifically for the
// ERC777/ERC721 *callback* surface (the dForce/Lendf.me class).
const HOOK_BEARING_TOKEN_OPS: &[&str] = &[
    "safeTransferFrom",  // ERC721/1155: invokes onERC721Received/onERC1155Received
    "safeTransfer",      // ERC721 safe transfer hook
    "safeMint",          // ERC721: invokes onERC721Received
    "_safeMint",
    "safeBatchTransferFrom",
    "send",              // ERC777 `token.send(to, amount, data)` -> tokensReceived
    "operatorSend",      // ERC777 operator send
];

/// True iff `name` reads like a VALUE / balance / accounting state variable — the
/// only storage whose post-hook corruption is the actual ERC777-reentrancy payday
/// (inflate a credited supply, double-count a share, drain a balance). Every
/// genuine fixture writes such a var after the hook-bearing transfer
/// (`supplyBalance`, `totalSupply`, `shares`, `balances`). A write to an unrelated
/// bool/flag/registry/status var is bookkeeping, not value at risk, and is not the
/// dForce/Lendf.me shape. Mirrors the generic reentrancy detector's value-state
/// gate so the two agree on what a "vulnerable post-call update" is.
fn is_value_state_var(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    const VALUE_KEYS: &[&str] = &[
        "balance", "borrow", "supply", "deposit", "share", "underlying", "reserve",
        "credit", "collateral", "amount", "stake", "debt", "principal", "asset",
        "liquidity", "funds", "owed", "escrow", "withdraw", "redeem", "payout",
        "vault", "token", "reward", "ledger", "accru",
    ];
    VALUE_KEYS.iter().any(|k| l.contains(k))
}

/// External *view* calls that read a live token balance / share supply — the kind
/// of read a redemption / withdrawal uses to size or PRORATE the amount it is
/// about to pay out (`token.balanceOf(pool)`, `totalSupply()`, `totalAssets()`).
/// When such a read precedes an unguarded hook-bearing transfer that pays the
/// caller inside a loop, the read is a stale collateral/solvency snapshot the hook
/// can invalidate by re-entering (the Reserve-RToken `redeem` shape, C4 M-07): the
/// remaining loop iterations keep paying out against the pre-hook balance even
/// after a re-entrant redeem has already drawn it down. Kept deliberately narrow
/// (balance/supply/asset reads only) so it does not fire on every external view.
fn is_balance_supply_view(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "balanceOf"
                | "totalSupply"
                | "totalAssets"
                | "getReserves"
                | "convertToAssets"
                | "convertToShares"
        )
    )
}

/// True iff the function pays its CALLER (the redeemer / withdrawer) — the
/// recipient of the hook-bearing transfer is attacker-controllable. The contest
/// code reaches `msg.sender` through OpenZeppelin's `_msgSender()` (an internal
/// call), so the literal `msg.sender` env flag is not enough; also accept a
/// `_msgSender()` internal call. (`tx.origin` likewise resolves to the caller.)
fn pays_the_caller(f: &sluice_ir::Function) -> bool {
    f.effects.reads_msg_sender
        || f.effects.reads_tx_origin
        || f
            .effects
            .internal_calls
            .iter()
            .any(|n| n == "_msgSender" || n == "msgSender")
}

impl Detector for Erc777Detector {
    fn id(&self) -> &'static str {
        "erc777-reentrancy"
    }
    fn category(&self) -> Category {
        Category::Erc777Reentrancy
    }
    fn description(&self) -> &'static str {
        "Reentrancy via a token receive hook (ERC777 tokensReceived / ERC721 onERC721Received) on a \
         supposedly-inert ERC20 transfer before a state update"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Suppression: an explicit reentrancy guard (lock modifier or a
            // ReentrancyGuard base) makes the callback harmless.
            if cx.has_reentrancy_guard(f) {
                continue;
            }

            // Find the earliest hook-bearing token op that is classified as a
            // genuine external call (a token handle's `transfer`, not an ETH
            // `addr.transfer`). We anchor on the earliest such op so any later
            // storage write counts as "state updated after the hook".
            let token_op = f
                .effects
                .call_sites
                .iter()
                .filter(|c| c.kind == CallKind::External)
                .filter(|c| {
                    c.func_name
                        .as_deref()
                        .map(|n| HOOK_BEARING_TOKEN_OPS.contains(&n))
                        .unwrap_or(false)
                })
                .min_by_key(|c| c.order);

            let token_op = match token_op {
                Some(c) => c,
                None => continue,
            };

            // CEI-downgrade (mirrors the generic reentrancy detector's
            // `has_qualifying_post_call_write`). A finding requires a VALUE/balance
            // write positioned STRICTLY AFTER the hook-bearing transfer that was NOT
            // already SETTLED (written) before that transfer.
            //
            // In a genuine ERC777-reentrancy (Lendf.me `supply`/`withdraw`, Grim
            // `depositFor`) the credited slot is read before and written ONLY after
            // the hook (`supplyBalance += amount` with no pre-hook write), so the
            // hook re-enters while the balance is stale. When the SAME var is also
            // written BEFORE the transfer, the function settles it before interacting
            // on every path it actually transfers on; a later (cross-branch) write to
            // it is the flat-order artifact of a sibling branch, not a stale-state
            // window. LoopFi `_processLock` credits `totalSupply`/`balances` in its
            // ETH branch (no call) before the non-ETH branch's `safeTransferFrom`, and
            // `_claim` zeroes `balances` before its `safeTransfer` — both CEI-correct,
            // so their post-hook writes are settled-before and must not fire.
            //
            // Restricting to VALUE/balance state also drops post-hook writes to
            // unrelated flags/registries (not the dForce/Lendf.me payday).
            let settled_before: rustc_hash::FxHashSet<&str> = f
                .effects
                .storage_writes
                .iter()
                .filter(|w| w.order < token_op.order)
                .map(|w| w.var.as_str())
                .collect();
            let write_after = f.effects.storage_writes.iter().find(|w| {
                w.order > token_op.order
                    && is_value_state_var(&w.var)
                    && !settled_before.contains(w.var.as_str())
            });

            let op_name = token_op.func_name.as_deref().unwrap_or("transfer");
            let b = match write_after {
                // ---- Direct CEI violation: a value/balance slot is written in
                // SOURCE after the hook-bearing transfer (Lendf.me/Grim shape). ----
                Some(write_after) => FindingBuilder::new(self.id(), Category::Erc777Reentrancy)
                    .title("Token-hook reentrancy: external token op before state update")
                    .severity(Severity::High)
                    // Heuristic, and it overlaps the generic reentrancy detector
                    // (the engine de-duplicates by location), so keep confidence
                    // modest rather than asserting structural certainty.
                    .confidence(0.5)
                    // Frontier: the hazard is a trust frontier crossed unsafely —
                    // an external token call hands control to a counterparty before
                    // the value slot is written.
                    .dimension(Dimension::Frontier)
                    .message(format!(
                        "`{}` calls `{}` on an external token and only afterwards writes `{}`. If that token \
                         implements a receive hook (ERC777 `tokensReceived`/`tokensToSend`, or ERC721 \
                         `onERC721Received`), the recipient regains control *before* the state update and can \
                         re-enter. A path the developer assumed was a vanilla, non-reentrant ERC20 transfer is \
                         actually reentrant — the dForce/Lendf.me ($25M) class.",
                        f.name, op_name, write_after.var
                    ))
                    .recommendation(
                        "Apply checks-effects-interactions (update storage before the token call) and add a \
                         `nonReentrant` guard. Do not assume an external token is hook-free; treat ERC777/ERC721 \
                         transfers as control-transferring external calls.",
                    ),

                // ---- Stale-balance-read-before-hook (Reserve RToken `redeem`,
                // C4 M-07). No value/balance STORAGE slot trails the transfer —
                // the contract settles its supply via an internal `_burn`/`_mint`
                // (no ordered storage-write proxy), so the direct-CEI rule above
                // sees nothing and the wave-5 CEI-downgrade suppresses it. But the
                // payout AMOUNT is bounded by a live external balance / supply read
                // (`balanceOf(backingManager)` / `totalSupply()`) taken BEFORE an
                // unguarded loop of hook-bearing transfers to the CALLER. The first
                // transfer's hook re-enters and redeems again; the remaining loop
                // iterations keep paying out against that now-stale snapshot,
                // bypassing the under-collateralization (prorata) bound. ----
                None => {
                    // Earliest external balance/supply view read must precede the
                    // hook transfer (the prorata snapshot the hook can invalidate).
                    let stale_read_before = f.effects.call_sites.iter().any(|c| {
                        c.kind == CallKind::External
                            && c.order < token_op.order
                            && is_balance_supply_view(c.func_name.as_deref())
                    });
                    // Require the hazardous loop AND that the payout goes to the
                    // caller (attacker-controllable hook recipient). The
                    // reentrancy-guard suppression at the top of the loop is the
                    // safe-out: a guarded redeem never reaches here.
                    //
                    // ALSO require the path be permissionless. The hook recipient
                    // is `msg.sender`; if the function is access-controlled to a
                    // single trusted caller (`require(_msgSender() == backingManager)`)
                    // the recipient is that trusted contract, not an attacker, so the
                    // re-entry is not reachable. (Reserve `StRSR.seizeRSR` is exactly
                    // this — backingManager-only, transferring the protocol's own
                    // non-hook RSR — and must NOT fire; `redeem` is permissionless.)
                    if !(stale_read_before
                        && f.effects.has_loop
                        && pays_the_caller(f)
                        && !cx.has_access_control(f))
                    {
                        continue;
                    }
                    FindingBuilder::new(self.id(), Category::Erc777Reentrancy)
                        .title("Token-hook reentrancy: stale balance snapshot before a hook-bearing payout loop")
                        .severity(Severity::High)
                        // Subtler than the direct-CEI shape (the corrupted state is
                        // a re-read external balance, not a trailing storage write),
                        // so report a notch lower in confidence.
                        .confidence(0.45)
                        .dimension(Dimension::Frontier)
                        .message(format!(
                            "`{}` bounds each payout by a live external balance/supply read (e.g. \
                             `balanceOf(...)` / `totalSupply()`) and then sends collateral to the caller via \
                             `{}` inside an unguarded loop. If a basket/collateral token implements a receive \
                             hook (ERC777 `tokensReceived`, or ERC721 `onERC721Received`), the first transfer \
                             hands control back to the redeemer, who re-enters and redeems again; the remaining \
                             loop iterations keep paying out against the now-stale snapshot, bypassing the \
                             under-collateralization (prorata) bound. This is the Reserve RToken `redeem` shape \
                             (Code4rena M-07): the supply is retired by an internal `_burn`/`_mint` (no \
                             trailing storage write), so a plain checks-effects-interactions scan misses it.",
                            f.name, op_name
                        ))
                        .recommendation(
                            "Add a `nonReentrant` guard to the redemption/withdrawal path, and treat \
                             ERC777/ERC721 collateral transfers as control-transferring external calls. Do not \
                             rely on a pre-loop balance/supply snapshot to bound payouts that are sent before \
                             the loop completes; re-validate solvency after each interaction or settle all \
                             accounting before any transfer.",
                        )
                }
            };

            // Value-flow corroboration: a hook-bearing transfer is itself a
            // value movement, and the post-call write / stale snapshot is what the
            // re-entrant path manipulates.
            let b = b.dimension(Dimension::ValueFlow);

            out.push(cx.finish(b, f.id, token_op.span));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    // Hook-bearing token op (ERC721 safeTransferFrom -> onERC721Received) executed
    // BEFORE the balance update, with no reentrancy guard: the recipient hook can
    // re-enter while state is stale (dForce/Lendf.me class).
    const VULN: &str = r#"
        interface INFT { function safeTransferFrom(address from, address to, uint256 id) external; }
        contract Bank {
            mapping(address => uint256) public balances;
            INFT public nft;
            function deposit() external { balances[msg.sender] += 1; }
            function withdraw(uint256 id) external {
                require(balances[msg.sender] >= 1);
                nft.safeTransferFrom(address(this), msg.sender, id);
                balances[msg.sender] -= 1;
            }
        }
    "#;

    // Checks-effects-interactions honored: the balance is decremented BEFORE
    // the hook-bearing call, so no state write follows it.
    const SAFE: &str = r#"
        interface INFT { function safeTransferFrom(address from, address to, uint256 id) external; }
        contract Bank {
            mapping(address => uint256) public balances;
            INFT public nft;
            function deposit() external { balances[msg.sender] += 1; }
            function withdraw(uint256 id) external {
                require(balances[msg.sender] >= 1);
                balances[msg.sender] -= 1;
                nft.safeTransferFrom(address(this), msg.sender, id);
            }
        }
    "#;

    // Lendf.me / dForce shape (the canonical ERC777 reentrancy): the ERC777
    // `send` fires the recipient's `tokensReceived` hook BEFORE the balance is
    // debited, and `supplyBalance` is written ONLY after the hook (never settled
    // before it). This MUST still fire after the CEI-downgrade.
    const LENDF: &str = r#"
        interface IERC777 {
            function send(address to, uint256 amount, bytes calldata data) external;
            function safeTransferFrom(address from, address to, uint256 amount) external;
        }
        contract LendfMePool {
            IERC777 public token;
            mapping(address => uint256) public supplyBalance;
            function supply(uint256 amount) external {
                token.safeTransferFrom(msg.sender, address(this), amount); // hook -> attacker
                supplyBalance[msg.sender] += amount;                       // effect, too late
            }
            function withdraw(uint256 amount) external {
                require(supplyBalance[msg.sender] >= amount);
                token.send(msg.sender, amount, "");  // hook -> attacker re-enters
                supplyBalance[msg.sender] -= amount; // effect after reentry
            }
        }
    "#;

    // CEI-correct claim with a cross-branch settle (LoopFi `_claim` shape): the
    // balance slot is SETTLED (written) before the real `safeTransfer` on the path
    // that transfers, and the other branch's write to the same slot is just the
    // flat-order artifact of a sibling branch. The CEI-downgrade must keep this
    // silent even though a `balances` write trails the transfer in source order.
    const CEI_CLAIM: &str = r#"
        interface ILpETH {
            function safeTransfer(address to, uint256 a) external;
            function deposit(address r) external payable;
        }
        contract PrelaunchPoints {
            mapping(address => mapping(address => uint256)) public balances;
            uint256 public totalSupply;
            uint256 public totalLpETH;
            address public constant ETH = address(0xee);
            ILpETH public lpETH;
            function _fillQuote(address t, uint256 a) internal { (bool ok,) = t.call(""); require(ok); }
            function _claim(address _token, address _receiver) internal returns (uint256 claimedAmount) {
                uint256 userStake = balances[msg.sender][_token];
                require(userStake != 0);
                if (_token == ETH) {
                    claimedAmount = userStake;
                    balances[msg.sender][_token] = 0;            // settle BEFORE the transfer
                    lpETH.safeTransfer(_receiver, claimedAmount); // hook-bearing call, last
                } else {
                    balances[msg.sender][_token] = userStake - 1; // settle BEFORE the calls
                    _fillQuote(_token, 1);
                    claimedAmount = address(this).balance;
                    lpETH.deposit{value: claimedAmount}(_receiver);
                }
            }
        }
    "#;

    #[test]
    fn fires_on_vuln() {
        let fs = run(VULN);
        assert!(fs.iter().any(|f| f.detector == "erc777-reentrancy"), "{:?}", fs);
    }

    #[test]
    fn silent_on_safe() {
        let fs = run(SAFE);
        assert!(!fs.iter().any(|f| f.detector == "erc777-reentrancy"));
    }

    // HARD recall guard: the canonical Lendf.me ERC777 reentrancy (state write
    // AFTER the hook, never settled before it) must STILL fire after the
    // CEI-downgrade.
    #[test]
    fn fires_on_lendf_state_write_after_hook() {
        let fs = run(LENDF);
        assert!(
            fs.iter().any(|f| f.detector == "erc777-reentrancy"),
            "Lendf.me-shape (state write after the ERC777 transfer) must still fire: {:?}",
            fs
        );
    }

    // CEI-downgrade regression: a function that settles the balance slot BEFORE the
    // hook-bearing transfer (the only post-hook write being a cross-branch artifact
    // on the SAME, already-settled slot) is CEI-correct and must stay silent. Real
    // site: LoopFi `PrelaunchPoints._claim`.
    #[test]
    fn silent_on_cei_settle_before_hook_transfer() {
        let fs = run(CEI_CLAIM);
        assert!(
            !fs.iter().any(|f| f.detector == "erc777-reentrancy"),
            "CEI-correct claim (balance settled before the hook transfer) must stay silent: {:?}",
            fs
        );
    }

    // Reserve RToken `redeem` shape (Code4rena M-07). The supply is retired by an
    // internal `_burn` (no trailing storage write) and the only direct storage
    // write (`basketsNeeded`) is settled BEFORE the transfer, so the direct-CEI
    // rule sees nothing. The hazard: each payout is bounded by a live external
    // `balanceOf(backingManager)` / `totalSupply()` snapshot taken before an
    // unguarded loop of hook-bearing `safeTransferFrom`s to the redeemer. A token
    // hook re-enters and the remaining iterations pay against the stale snapshot.
    const RESERVE_REDEEM: &str = r#"
        interface IERC20U {
            function safeTransferFrom(address f, address t, uint256 a) external;
            function balanceOf(address a) external view returns (uint256);
        }
        contract RTokenP1 {
            uint192 public basketsNeeded;
            IERC20U backingManager;
            function totalSupply() public view returns (uint256) { return 1; }
            function _msgSender() internal view returns (address) { return msg.sender; }
            function _burn(address a, uint256 x) internal {}
            function redeem(uint256 amount) external {
                require(amount > 0, "Cannot redeem zero");
                address redeemer = _msgSender();
                uint192 basketsNeeded_ = basketsNeeded;
                uint256 supply = totalSupply();
                uint192 baskets = uint192((basketsNeeded_ * amount) / supply);
                address[] memory erc20s; uint256[] memory amounts;
                uint256 erc20length = erc20s.length;
                for (uint256 i = 0; i < erc20length; ++i) {
                    uint256 bal = backingManager.balanceOf(address(backingManager));
                    uint256 prorata = (bal * amount) / supply;
                    if (prorata < amounts[i]) amounts[i] = prorata;
                }
                basketsNeeded = basketsNeeded_ - baskets;   // settled BEFORE transfer
                _burn(redeemer, amount);                    // supply retired (no storage write)
                for (uint256 i = 0; i < erc20length; ++i) {
                    if (amounts[i] == 0) continue;
                    backingManager.safeTransferFrom(address(backingManager), redeemer, amounts[i]);
                }
            }
        }
    "#;

    // Same `redeem` but with a `nonReentrant` guard: the guard is the safe-out, so
    // the stale-snapshot fallback must stay silent.
    const RESERVE_REDEEM_GUARDED: &str = r#"
        interface IERC20U {
            function safeTransferFrom(address f, address t, uint256 a) external;
            function balanceOf(address a) external view returns (uint256);
        }
        contract ReentrancyGuard { modifier nonReentrant() { _; } }
        contract RTokenP1 is ReentrancyGuard {
            uint192 public basketsNeeded;
            IERC20U backingManager;
            function totalSupply() public view returns (uint256) { return 1; }
            function _msgSender() internal view returns (address) { return msg.sender; }
            function _burn(address a, uint256 x) internal {}
            function redeem(uint256 amount) external nonReentrant {
                address redeemer = _msgSender();
                uint192 basketsNeeded_ = basketsNeeded;
                uint256 supply = totalSupply();
                address[] memory erc20s; uint256[] memory amounts;
                for (uint256 i = 0; i < erc20s.length; ++i) {
                    uint256 bal = backingManager.balanceOf(address(backingManager));
                    if ((bal * amount) / supply < amounts[i]) amounts[i] = (bal * amount) / supply;
                }
                basketsNeeded = basketsNeeded_ - 1;
                _burn(redeemer, amount);
                for (uint256 i = 0; i < erc20s.length; ++i) {
                    backingManager.safeTransferFrom(address(backingManager), redeemer, amounts[i]);
                }
            }
        }
    "#;

    // A hook-bearing transfer in a loop that pays the caller but does NOT read any
    // external balance/supply before it (no stale solvency snapshot) — e.g. a plain
    // batch airdrop of fixed per-recipient amounts. The fallback must NOT fire (it
    // is not the prorata-redeem hazard), and there is no trailing value write, so
    // the direct-CEI rule is silent too.
    const LOOP_NO_BALANCE_READ: &str = r#"
        interface IERC20U { function safeTransfer(address t, uint256 a) external; }
        contract Airdrop {
            IERC20U token;
            uint256[] amounts;
            function claimAll() external {
                address to = msg.sender;
                for (uint256 i = 0; i < amounts.length; ++i) {
                    token.safeTransfer(to, amounts[i]);
                }
            }
        }
    "#;

    // HARD recall guard (the missed real bug): the Reserve `redeem` shape must fire.
    #[test]
    fn fires_on_reserve_redeem_stale_balance_loop() {
        let fs = run(RESERVE_REDEEM);
        assert!(
            fs.iter().any(|f| f.detector == "erc777-reentrancy"),
            "Reserve RToken `redeem` (stale balance snapshot before unguarded hook-payout loop) must fire: {:?}",
            fs
        );
    }

    // Precision: the guarded `redeem` must stay silent (the reentrancy guard is the
    // documented safe-out for this whole detector).
    #[test]
    fn silent_on_reserve_redeem_with_guard() {
        let fs = run(RESERVE_REDEEM_GUARDED);
        assert!(
            !fs.iter().any(|f| f.detector == "erc777-reentrancy"),
            "Guarded redeem must stay silent: {:?}",
            fs
        );
    }

    // Precision: a hook-payout loop with NO pre-transfer external balance/supply
    // read is not the prorata-redeem hazard and must stay silent.
    #[test]
    fn silent_on_hook_loop_without_balance_read() {
        let fs = run(LOOP_NO_BALANCE_READ);
        assert!(
            !fs.iter().any(|f| f.detector == "erc777-reentrancy"),
            "Hook-payout loop without a stale balance snapshot must stay silent: {:?}",
            fs
        );
    }

    // Precision: the structural twin of `redeem` but access-controlled to a single
    // trusted caller (`require(_msgSender() == ...)`). The hook recipient is that
    // trusted contract, not an attacker, so the re-entry is unreachable. Real site:
    // Reserve `StRSR.seizeRSR` (backingManager-only, transferring the non-hook RSR).
    const PRIVILEGED_SEIZE: &str = r#"
        interface IERC20U {
            function safeTransfer(address t, uint256 a) external;
            function balanceOf(address a) external view returns (uint256);
        }
        contract StRSR {
            IERC20U rsr;
            address backingManager;
            uint256 rsrBacking;
            uint256[] queue;
            function _msgSender() internal view returns (address) { return msg.sender; }
            function seizeRSR(uint256 rsrAmount) external {
                require(_msgSender() == backingManager, "not backing manager");
                uint256 rsrBalance = rsr.balanceOf(address(this));
                uint256 seized;
                for (uint256 i = 0; i < queue.length; i++) {
                    uint256 take = (queue[i] * rsrAmount) / rsrBalance;
                    queue[i] -= take;
                    seized += take;
                }
                rsr.safeTransfer(_msgSender(), seized);
            }
        }
    "#;

    #[test]
    fn silent_on_privileged_seize_to_trusted_caller() {
        let fs = run(PRIVILEGED_SEIZE);
        assert!(
            !fs.iter().any(|f| f.detector == "erc777-reentrancy"),
            "Access-controlled seize (trusted-only caller) must stay silent: {:?}",
            fs
        );
    }
}

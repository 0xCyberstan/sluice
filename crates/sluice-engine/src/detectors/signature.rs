//! Signature verification flaws: ecrecover→address(0), replay (missing nonce /
//! chainId), missing deadline, malleability.

use crate::context::AnalysisContext;
use crate::detector::Detector;
use sluice_findings::{Category, Dimension, Finding, FindingBuilder, Severity};
use sluice_ir::Function;

pub struct SignatureDetector;

impl Detector for SignatureDetector {
    fn id(&self) -> &'static str {
        "signature"
    }
    fn category(&self) -> Category {
        Category::SignatureReplay
    }
    fn description(&self) -> &'static str {
        "ecrecover zero-address, signature replay (nonce/chainId), missing deadline, malleability"
    }

    fn run(&self, cx: &AnalysisContext) -> Vec<Finding> {
        let mut out = Vec::new();
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            // Replay protection (nonce/deadline/chainId) is the responsibility of
            // the verification *entry point*, not of a pure recovery primitive.
            // Skip library helpers and non-entry functions (e.g. an `ECDSA.recover`
            // implementation legitimately has no nonce).
            if !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            if cx.contract_of(f.id).map(|c| c.is_library()).unwrap_or(false) {
                continue;
            }
            let src = cx.source_text(f.span);
            if !src.contains("ecrecover") {
                continue;
            }
            // OpenZeppelin ECDSA handles zero-address + malleability.
            let uses_ecdsa = src.contains(".recover(")
                || cx.scir.contract(f.contract).map(|c| c.uses_library_like("ecdsa")).unwrap_or(false);

            let mk = |cat: Category, title: &str, sev: Severity, conf: f32, msg: String, rec: &str| {
                FindingBuilder::new("signature", cat)
                    .title(title)
                    .severity(sev)
                    .confidence(conf)
                    .dimension(Dimension::ValueFlow)
                    .message(msg)
                    .recommendation(rec)
            };

            if !uses_ecdsa && !src.contains("address(0)") {
                out.push(cx.finish(
                    mk(
                        Category::EcrecoverZeroAddress,
                        "ecrecover result not checked against address(0)",
                        Severity::High,
                        0.7,
                        format!(
                            "`{}` calls `ecrecover` but never rejects `address(0)`. A malformed signature \
                             makes `ecrecover` return `address(0)`; if that can equal an expected signer, \
                             forgery passes.",
                            f.name
                        ),
                        "Use OpenZeppelin `ECDSA.recover` (reverts on bad sigs) or `require(signer != address(0))`.",
                    ),
                    f.id,
                    f.span,
                ));
            }
            if !src.contains("nonce") {
                out.push(cx.finish(
                    mk(
                        Category::SignatureReplay,
                        "Signed message lacks a nonce (replayable)",
                        Severity::High,
                        0.6,
                        format!(
                            "`{}` verifies a signature without a per-signer nonce, so a captured signature \
                             can be replayed.",
                            f.name
                        ),
                        "Include and consume a per-signer `nonce` in the signed digest.",
                    ),
                    f.id,
                    f.span,
                ));
            }
            if !src.contains("chainid") && !src.contains("domain_separator") {
                out.push(cx.finish(
                    mk(
                        Category::SignatureReplay,
                        "Signed digest omits chainId / EIP-712 domain separator",
                        Severity::Medium,
                        0.5,
                        format!(
                            "`{}` does not bind the signature to a chainId / domain separator, enabling \
                             cross-chain or cross-contract replay.",
                            f.name
                        ),
                        "Bind the digest to an EIP-712 domain separator that includes `block.chainid`.",
                    ),
                    f.id,
                    f.span,
                ));
            }
            if !src.contains("deadline") && !src.contains("expiry") && !src.contains("validuntil") {
                out.push(cx.finish(
                    mk(
                        Category::MissingDeadline,
                        "Signature has no deadline (valid forever)",
                        Severity::Low,
                        0.45,
                        format!("`{}` accepts a signature with no expiry, so stale signatures remain usable.", f.name),
                        "Include a `deadline` in the signed payload and `require(block.timestamp <= deadline)`.",
                    ),
                    f.id,
                    f.span,
                ));
            }
        }

        // ---------------------------------------------------------------------
        // Broadening A — time-windowed signed-message replay.
        //
        // The loop above only inspects ecrecover-*literal*, state-mutating,
        // non-library *entry points*. That structurally misses a very common
        // real-world shape: a `view`/library *price/attestation verifier* (e.g.
        // Tigris `TradingLibrary.verifyPrice`) that recovers an off-chain
        // signer via OpenZeppelin `ECDSA` (`...toEthSignedMessageHash().recover(sig)`)
        // and *accepts* the signed payload as authorization purely because it is
        // recent enough — `require(block.timestamp <= signed.timestamp + window)`.
        // Such a signature carries no nonce and no single-use marker, so the SAME
        // signature is replayable for the whole freshness window.
        //
        // We deliberately scope this independently of mutability/library status
        // (the replay risk lives in the signed-payload *design*, not in who calls
        // it) but require ALL of:
        //   (1) an ECDSA recovery (`ecrecover` or `.recover(`),
        //   (2) an additive timestamp *freshness window* gating acceptance
        //       (`block.timestamp` AND a validity-timer term),
        //   (3) NO nonce token, and
        //   (4) NO single-use / consumed marker.
        // (2) is what distinguishes a "recent-enough ⇒ accept" verifier from a
        // pure recovery helper that returns a bool (balancer/lido `isValidSignature`
        // have no timestamp logic), and (3)+(4) keep us silent on every EIP-712
        // permit flow on the dogfood repos — each of those consumes a `nonce`
        // (and universal-router additionally marks `noncesUsed[..]`).
        for f in cx.functions() {
            if !f.has_body {
                continue;
            }
            let src = cx.source_text(f.span);
            // (1) recovers an ECDSA signer.
            let recovers = src.contains("ecrecover") || src.contains(".recover(");
            if !recovers {
                continue;
            }
            // (2) accepts within an additive freshness window. Require both a
            // `block.timestamp` read and a validity-timer term so a fixed
            // `block.timestamp <= deadline` (single-use permit) does not match.
            let has_timestamp = src.contains("block.timestamp") || src.contains("block_timestamp");
            let has_freshness_window = src.contains("timer")
                || src.contains("validity")
                || src.contains("validfor")
                || src.contains("signaturelifetime")
                || src.contains("maxage")
                || src.contains("staleness");
            if !(has_timestamp && has_freshness_window) {
                continue;
            }
            // (3) no per-message nonce, and (4) no single-use / consumed marker.
            if src.contains("nonce") {
                continue;
            }
            let has_single_use_marker = src.contains("used[")
                || src.contains("isused")
                || src.contains("usedsignature")
                || src.contains("usedhash")
                || src.contains("consumed")
                || src.contains("invalidate")
                || src.contains("executed[")
                || src.contains("processed")
                || src.contains("seen[")
                || src.contains("spent[");
            if has_single_use_marker {
                continue;
            }
            // Avoid double-reporting if the entry-point loop above already flagged
            // this exact function for SignatureReplay.
            if out
                .iter()
                .any(|fnd| fnd.category == Category::SignatureReplay && fnd.function == f.name)
            {
                continue;
            }
            out.push(cx.finish(
                FindingBuilder::new("signature", Category::SignatureReplay)
                    .title("Signed message accepted within a time window with no replay protection")
                    .severity(Severity::High)
                    .confidence(0.6)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` recovers an ECDSA signer and accepts the signed payload as authorization \
                         whenever it is within a freshness window (`block.timestamp <= ... + timer`), but \
                         binds no per-message `nonce` and records no single-use marker. The identical \
                         signature can therefore be replayed any number of times until the window expires.",
                        f.name
                    ))
                    .recommendation(
                        "Bind a per-signer `nonce` (or a single-use signature/hash mapping) into the signed \
                         digest and consume it on use, so each signature authorizes exactly one action.",
                    ),
                f.id,
                f.span,
            ));
        }

        // ---------------------------------------------------------------------
        // Broadening B — price-sensitive AMM trade with no deadline.
        //
        // The `MissingDeadline` finding above is only emitted as a *sub-finding*
        // of signature verification (a signed payload with no expiry). It never
        // fires for the far more common case: a public AMM *trade* entry point
        // that settles a value transfer at a pool-determined (constant-product)
        // price yet takes NO `deadline` parameter — so the tx can sit in the
        // mempool and execute later at a stale price (Caviar `PrivatePool`
        // `buy`/`sell`/`change`; only the EthRouter wrappers carry the deadline).
        //
        // This is FP-prone, so we scope it tightly to genuine bonding-curve
        // trades and keep oracle-priced / liquidity / admin functions out:
        //   - contract-level gate: a *concrete* contract that declares a pool
        //     reserve state var (name contains "reserves") AND exposes a
        //     price/quote view — i.e. it is itself an AMM pool. (comet prices via
        //     a Chainlink `getPrice` oracle and has no such `reserves` state var;
        //     its `_reserved` storage-gap fields are singular and excluded.)
        //   - per-function gate: public/external, state-mutating, transfers value
        //     AND prices the trade off the curve (writes a `reserves` var or calls
        //     a `*quote*`/`price` helper), with NO deadline/expiry parameter and
        //     NO in-function `block.timestamp <= deadline` guard, and not gated by
        //     an owner-only modifier (admin setters legitimately need no deadline).
        // On the six dogfood repos this matches nothing: balancer's `Vault.swap`
        // carries a `deadline`, pool `onSwap` hooks move no value to `msg.sender`,
        // and no dogfood contract pairs a `reserves` pricing var with a
        // deadline-less value-transferring trade.
        for c in cx.scir.contracts.values() {
            if !c.is_concrete() {
                continue;
            }
            // Contract is an AMM pool: has a plural "reserves" pricing state var
            // and a price/quote-style view function.
            let has_reserves_var = c
                .state_vars
                .iter()
                .any(|v| v.name.to_ascii_lowercase().contains("reserves"));
            if !has_reserves_var {
                continue;
            }
            let exposes_pricing_view = c.functions.iter().filter_map(|fid| cx.scir.function(*fid)).any(|fp| {
                let n = fp.name.to_ascii_lowercase();
                fp.is_view_or_pure()
                    && (n == "price" || n.contains("quote") || n.starts_with("getamount") || n.contains("spotprice"))
            });
            if !exposes_pricing_view {
                continue;
            }

            for fid in &c.functions {
                let Some(f) = cx.scir.function(*fid) else { continue };
                if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                    continue;
                }
                // Admin setters are owner-gated and need no deadline.
                if f.has_modifier_like("onlyowner")
                    || f.has_modifier_like("onlygovernor")
                    || f.has_modifier_like("onlyadmin")
                    || f.has_modifier_like("auth")
                {
                    continue;
                }
                // Has a deadline/expiry parameter? Then it is already protected.
                let has_deadline_param = f.params.iter().any(|p| {
                    let n = p.name.as_deref().unwrap_or("").to_ascii_lowercase();
                    n.contains("deadline") || n.contains("expiry") || n == "validuntil" || n.contains("expiration")
                });
                if has_deadline_param {
                    continue;
                }
                let src = cx.source_text(f.span);
                // In-function timestamp deadline guard counts as protection too.
                if (src.contains("deadline") || src.contains("expiry") || src.contains("validuntil"))
                    && src.contains("block.timestamp")
                {
                    continue;
                }
                // Trade signal: prices off the curve (writes a reserves var or
                // calls a quote/price helper) AND settles a value/asset transfer.
                let prices_off_curve = f
                    .effects
                    .storage_writes
                    .iter()
                    .any(|w| w.var.to_ascii_lowercase().contains("reserves"))
                    || src.contains("quote")
                    || src.contains("price(");
                let transfers_value = f.is_payable()
                    || f.effects.call_sites.iter().any(|cs| {
                        cs.sends_value
                            || cs
                                .func_name
                                .as_deref()
                                .map(|m| m.to_ascii_lowercase().contains("transfer"))
                                .unwrap_or(false)
                    })
                    || src.contains("safetransfer")
                    || src.contains(".transfer(");
                if !(prices_off_curve && transfers_value) {
                    continue;
                }
                out.push(cx.finish(
                    FindingBuilder::new("signature", Category::MissingDeadline)
                        .title("AMM trade function takes no deadline (stale-price execution)")
                        .severity(Severity::Medium)
                        .confidence(0.55)
                        .dimension(Dimension::ValueFlow)
                        .message(format!(
                            "`{}` settles a value transfer at the pool's constant-product price but accepts no \
                             `deadline`/`expiry` parameter and enforces no `block.timestamp` bound. A submitted \
                             trade can linger in the mempool and be executed much later at a stale, \
                             unfavorable price (e.g. after the reserves have moved).",
                            f.name
                        ))
                        .recommendation(
                            "Add a `deadline` parameter to the trade entry point and \
                             `require(block.timestamp <= deadline)` so a delayed transaction reverts instead of \
                             executing at a stale price.",
                        ),
                    f.id,
                    f.span,
                ));
            }
        }

        // ---------------------------------------------------------------------
        // Broadening C — public entry point invokes a deadline-less AMM *router*
        // swap.
        //
        // Broadening B only recognizes a contract that *is itself* an AMM pool
        // (it holds a `reserves` pricing var). It structurally misses the far more
        // common liquid-staking / vault shape (Asymmetry `Reth.deposit`): a public
        // entry point that swaps on an *external* Uniswap-style router
        // (`ISwapRouter(..).exactInputSingle(params)`) without passing any
        // `deadline`. The Uniswap V3 `SwapRouter02` `ExactInput*`/`ExactOutput*`
        // structs carry no `deadline` field at all, so such a stake/deposit tx can
        // sit in the mempool and execute much later at a stale price. The contract
        // holds no `reserves` var, so arm B never sees it.
        //
        // We key on the *router method name* (resolved `func_name`, original case)
        // rather than on pool state, and we look one internal-call hop deep because
        // the swap is usually delegated to a private helper
        // (`deposit` -> `swapExactInputSingleHop` -> `exactInputSingle`). To stay
        // conservative we fire ONLY when no deadline is plumbed anywhere on the
        // path: neither the entry point nor the swap-bearing function carries a
        // `deadline`/`expiry` parameter or even mentions `deadline`/`expiry`/
        // `block.timestamp` (a V2 router's trailing deadline arg and a V3 struct's
        // `deadline:` field both show up as one of those tokens). This keeps every
        // dogfood router caller silent — comet's `OnChainLiquidator` passes
        // `deadline: block.timestamp` / `block.timestamp` into each swap helper,
        // and universal-router's swap primitives are named `v3SwapExactInput` /
        // `_swap` (not the canonical router entry names), so neither matches.
        fn is_router_swap_method(name: &str) -> bool {
            let n = name.to_ascii_lowercase();
            // Uniswap V3 SwapRouter (no deadline field on V2-era *02* structs):
            n == "exactinputsingle"
                || n == "exactinput"
                || n == "exactoutputsingle"
                || n == "exactoutput"
                // Uniswap V2 / Sushi router family (deadline is a trailing arg):
                || n == "swapexacttokensfortokens"
                || n == "swaptokensforexacttokens"
                || n == "swapexactethfortokens"
                || n == "swapethforexacttokens"
                || n == "swapexacttokensforeth"
                || n == "swaptokensforexacteth"
                // Common project wrapper names for a single-hop router swap:
                || n == "swapexactinputsinglehop"
                || n == "swapexactinput"
                || n == "swapexactoutput"
        }
        // Does a function's source plumb *any* deadline/timestamp bound? Used as
        // the conservative "already protected" gate for both the entry point and
        // the swap-bearing helper.
        let plumbs_deadline = |g: &Function| -> bool {
            if g.params.iter().any(|p| {
                let n = p.name.as_deref().unwrap_or("").to_ascii_lowercase();
                n.contains("deadline") || n.contains("expiry") || n == "validuntil" || n.contains("expiration")
            }) {
                return true;
            }
            let s = cx.source_text(g.span);
            s.contains("deadline") || s.contains("expiry") || s.contains("block.timestamp")
        };
        for f in cx.functions() {
            if !f.has_body || !f.is_externally_reachable() || !f.is_state_mutating() {
                continue;
            }
            // The entry point must not itself plumb a deadline.
            if plumbs_deadline(f) {
                continue;
            }
            // Find a router-swap call site: either directly in `f`, or one hop
            // into a same-contract internal helper (the usual delegation shape).
            // The swap-bearing function must itself not plumb a deadline.
            let direct = f
                .effects
                .call_sites
                .iter()
                .any(|cs| cs.func_name.as_deref().map(is_router_swap_method).unwrap_or(false));
            let swap_site = if direct {
                Some(f)
            } else {
                f.callees
                    .iter()
                    .filter_map(|cid| cx.scir.function(*cid))
                    .filter(|g| g.contract == f.contract)
                    .find(|g| {
                        g.effects
                            .call_sites
                            .iter()
                            .any(|cs| cs.func_name.as_deref().map(is_router_swap_method).unwrap_or(false))
                            && !plumbs_deadline(g)
                    })
            };
            let Some(_swap_fn) = swap_site else { continue };
            // Don't double-report if arm B already flagged this function.
            if out
                .iter()
                .any(|fnd| fnd.category == Category::MissingDeadline && fnd.function == f.name)
            {
                continue;
            }
            out.push(cx.finish(
                FindingBuilder::new("signature", Category::MissingDeadline)
                    .title("Swap on an AMM router takes no deadline (stale-price execution)")
                    .severity(Severity::Medium)
                    .confidence(0.5)
                    .dimension(Dimension::ValueFlow)
                    .message(format!(
                        "`{}` swaps on a Uniswap-style router (e.g. `exactInputSingle`/`swapExactTokensForTokens`) \
                         without supplying any `deadline`, and enforces no `block.timestamp` bound. The submitted \
                         transaction can linger in the mempool and be executed much later at a stale, unfavorable \
                         price (e.g. after the pool has moved), with only the slippage `amountOutMinimum` — computed \
                         at submission time — as protection.",
                        f.name
                    ))
                    .recommendation(
                        "Pass a caller-supplied `deadline` to the router swap (Uniswap V3 `SwapRouter`'s params, or \
                         the V2 router's trailing `deadline` argument) so a delayed transaction reverts instead of \
                         executing at a stale price.",
                    ),
                f.id,
                f.span,
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use crate::{analyze_sources, Config};
    use sluice_findings::Category;

    fn run(src: &str) -> Vec<sluice_findings::Finding> {
        analyze_sources(vec![("t.sol".into(), src.into())], &Config::default()).findings
    }

    fn has(fs: &[sluice_findings::Finding], cat: Category, func: &str) -> bool {
        fs.iter().any(|f| f.category == cat && f.function == func)
    }

    // --- Broadening A: time-windowed signed-message replay --------------------

    // Vulnerable (Tigris `verifyPrice` shape): a `view` *library* recovers a
    // node-signed price via OZ `ECDSA.recover` and accepts it within a freshness
    // window with no nonce / single-use marker → replayable.
    const REPLAY_VULN: &str = r#"
        library ECDSA {
            function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) { return h; }
            function recover(bytes32 h, bytes memory s) internal pure returns (address) { return address(0); }
        }
        struct PriceData { address provider; uint256 price; uint256 timestamp; }
        library TradingLibrary {
            using ECDSA for bytes32;
            function verifyPrice(
                uint256 _validSignatureTimer,
                PriceData calldata _priceData,
                bytes calldata _signature,
                mapping(address => bool) storage _isNode
            ) external view {
                address _provider = keccak256(abi.encode(_priceData)).toEthSignedMessageHash().recover(_signature);
                require(_provider == _priceData.provider, "BadSig");
                require(_isNode[_provider], "!Node");
                require(block.timestamp <= _priceData.timestamp + _validSignatureTimer, "ExpSig");
            }
        }
    "#;

    // Safe: same recovery, but a per-signer `nonce` is bound into the digest and
    // consumed → not replayable. Must stay silent.
    const REPLAY_SAFE_NONCE: &str = r#"
        library ECDSA {
            function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) { return h; }
            function recover(bytes32 h, bytes memory s) internal pure returns (address) { return address(0); }
        }
        contract Verifier {
            using ECDSA for bytes32;
            mapping(address => uint256) public nonces;
            uint256 public validSignatureTimer;
            function verify(address signer, uint256 ts, uint256 nonce, bytes calldata sig) external {
                address rec = keccak256(abi.encode(signer, ts, nonce)).toEthSignedMessageHash().recover(sig);
                require(rec == signer, "BadSig");
                require(nonce == nonces[signer]++, "BadNonce");
                require(block.timestamp <= ts + validSignatureTimer, "ExpSig");
            }
        }
    "#;

    // Safe: a pure recovery helper (balancer/lido `isValidSignature` shape) with
    // NO timestamp/freshness logic — not an "accept-because-recent" verifier.
    const REPLAY_SAFE_PURE: &str = r#"
        library ECDSA {
            function recover(bytes32 h, bytes memory s) internal pure returns (address) { return address(0); }
        }
        contract SigCheck {
            function isValidSignature(address signer, bytes32 digest, bytes calldata sig)
                external pure returns (bool)
            {
                return ECDSA.recover(digest, sig) == signer;
            }
        }
    "#;

    #[test]
    fn replay_fires_on_windowed_no_nonce() {
        let fs = run(REPLAY_VULN);
        assert!(has(&fs, Category::SignatureReplay, "verifyPrice"), "{:#?}", fs);
    }

    #[test]
    fn replay_silent_when_nonce_consumed() {
        let fs = run(REPLAY_SAFE_NONCE);
        assert!(!has(&fs, Category::SignatureReplay, "verify"), "{:#?}", fs);
    }

    #[test]
    fn replay_silent_on_pure_recovery_helper() {
        let fs = run(REPLAY_SAFE_PURE);
        assert!(!has(&fs, Category::SignatureReplay, "isValidSignature"), "{:#?}", fs);
    }

    // --- Broadening B: AMM trade with no deadline -----------------------------

    // Vulnerable (Caviar `PrivatePool` shape): an AMM pool (reserves state vars +
    // `price`/`*Quote` views) whose `buy` settles a value transfer at the curve
    // price with NO deadline parameter.
    const DEADLINE_VULN: &str = r#"
        interface IERC721 { function safeTransferFrom(address f, address t, uint256 id) external; }
        contract PrivatePool {
            uint128 public virtualBaseTokenReserves;
            uint128 public virtualNftReserves;
            address public nft;
            function buyQuote(uint256 outputAmount) public view returns (uint256 netInputAmount) {
                netInputAmount = outputAmount * virtualBaseTokenReserves / (virtualNftReserves - outputAmount);
            }
            function price() public view returns (uint256) {
                return virtualBaseTokenReserves * 1e18 / virtualNftReserves;
            }
            function buy(uint256[] calldata tokenIds, uint256 weightSum)
                public payable returns (uint256 netInputAmount)
            {
                netInputAmount = buyQuote(weightSum);
                virtualBaseTokenReserves += uint128(netInputAmount);
                virtualNftReserves -= uint128(weightSum);
                for (uint256 i = 0; i < tokenIds.length; i++) {
                    IERC721(nft).safeTransferFrom(address(this), msg.sender, tokenIds[i]);
                }
            }
        }
    "#;

    // Safe: identical AMM `buy` but it takes a `deadline` and enforces it. Must
    // stay silent.
    const DEADLINE_SAFE: &str = r#"
        interface IERC721 { function safeTransferFrom(address f, address t, uint256 id) external; }
        contract PrivatePool {
            uint128 public virtualBaseTokenReserves;
            uint128 public virtualNftReserves;
            address public nft;
            function buyQuote(uint256 outputAmount) public view returns (uint256 netInputAmount) {
                netInputAmount = outputAmount * virtualBaseTokenReserves / (virtualNftReserves - outputAmount);
            }
            function price() public view returns (uint256) {
                return virtualBaseTokenReserves * 1e18 / virtualNftReserves;
            }
            function buy(uint256[] calldata tokenIds, uint256 weightSum, uint256 deadline)
                public payable returns (uint256 netInputAmount)
            {
                require(block.timestamp <= deadline, "expired");
                netInputAmount = buyQuote(weightSum);
                virtualBaseTokenReserves += uint128(netInputAmount);
                virtualNftReserves -= uint128(weightSum);
                for (uint256 i = 0; i < tokenIds.length; i++) {
                    IERC721(nft).safeTransferFrom(address(this), msg.sender, tokenIds[i]);
                }
            }
        }
    "#;

    // Safe: an owner-only admin setter on the same pool moves no trade and needs
    // no deadline → must stay silent even though the contract is an AMM pool.
    const DEADLINE_SAFE_ADMIN: &str = r#"
        contract PrivatePool {
            uint128 public virtualBaseTokenReserves;
            uint128 public virtualNftReserves;
            address public owner;
            modifier onlyOwner() { require(msg.sender == owner); _; }
            function price() public view returns (uint256) {
                return virtualBaseTokenReserves * 1e18 / virtualNftReserves;
            }
            function buyQuote(uint256 o) public view returns (uint256) { return o; }
            function setVirtualReserves(uint128 a, uint128 b) public onlyOwner {
                virtualBaseTokenReserves = a;
                virtualNftReserves = b;
            }
        }
    "#;

    #[test]
    fn deadline_fires_on_amm_trade_without_deadline() {
        let fs = run(DEADLINE_VULN);
        assert!(has(&fs, Category::MissingDeadline, "buy"), "{:#?}", fs);
    }

    #[test]
    fn deadline_silent_when_deadline_present() {
        let fs = run(DEADLINE_SAFE);
        assert!(!has(&fs, Category::MissingDeadline, "buy"), "{:#?}", fs);
    }

    #[test]
    fn deadline_silent_on_owner_only_setter() {
        let fs = run(DEADLINE_SAFE_ADMIN);
        assert!(!has(&fs, Category::MissingDeadline, "setVirtualReserves"), "{:#?}", fs);
    }

    // --- Broadening C: AMM *router* swap with no deadline ----------------------

    // Vulnerable (Asymmetry `Reth.deposit` shape): a public entry point delegates
    // to a private helper that swaps on a Uniswap V3 router via `exactInputSingle`
    // (whose params struct has no `deadline` field). Neither the entry nor the
    // helper plumbs a deadline → the stake tx can execute at a stale price. The
    // contract holds no `reserves` var, so arm B never sees it; arm C must.
    const ROUTER_DEADLINE_VULN: &str = r#"
        interface IERC20 { function approve(address s, uint256 a) external returns (bool); }
        interface ISwapRouter {
            struct ExactInputSingleParams {
                address tokenIn; address tokenOut; uint24 fee; address recipient;
                uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
            }
            function exactInputSingle(ExactInputSingleParams calldata params)
                external payable returns (uint256 amountOut);
        }
        contract Reth {
            address constant ROUTER = address(0x1234);
            function swapExactInputSingleHop(
                address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint256 minOut
            ) private returns (uint256 amountOut) {
                IERC20(tokenIn).approve(ROUTER, amountIn);
                ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
                    tokenIn: tokenIn, tokenOut: tokenOut, fee: fee, recipient: address(this),
                    amountIn: amountIn, amountOutMinimum: minOut, sqrtPriceLimitX96: 0
                });
                amountOut = ISwapRouter(ROUTER).exactInputSingle(params);
            }
            function deposit(uint256 minOut) external payable returns (uint256) {
                return swapExactInputSingleHop(address(1), address(2), 500, msg.value, minOut);
            }
        }
    "#;

    // Safe: identical router swap, but the helper passes a real `deadline` into
    // the router params and the entry takes a `deadline` parameter → protected,
    // must stay silent.
    const ROUTER_DEADLINE_SAFE: &str = r#"
        interface IERC20 { function approve(address s, uint256 a) external returns (bool); }
        interface ISwapRouter {
            struct ExactInputSingleParams {
                address tokenIn; address tokenOut; uint24 fee; address recipient;
                uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96;
            }
            function exactInputSingle(ExactInputSingleParams calldata params)
                external payable returns (uint256 amountOut);
        }
        contract Reth {
            address constant ROUTER = address(0x1234);
            function swapExactInputSingleHop(
                address tokenIn, address tokenOut, uint24 fee, uint256 amountIn, uint256 minOut, uint256 deadline
            ) private returns (uint256 amountOut) {
                IERC20(tokenIn).approve(ROUTER, amountIn);
                ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
                    tokenIn: tokenIn, tokenOut: tokenOut, fee: fee, recipient: address(this),
                    deadline: deadline, amountIn: amountIn, amountOutMinimum: minOut, sqrtPriceLimitX96: 0
                });
                amountOut = ISwapRouter(ROUTER).exactInputSingle(params);
            }
            function deposit(uint256 minOut, uint256 deadline) external payable returns (uint256) {
                return swapExactInputSingleHop(address(1), address(2), 500, msg.value, minOut, deadline);
            }
        }
    "#;

    #[test]
    fn deadline_fires_on_router_swap_without_deadline() {
        let fs = run(ROUTER_DEADLINE_VULN);
        assert!(has(&fs, Category::MissingDeadline, "deposit"), "{:#?}", fs);
    }

    #[test]
    fn deadline_silent_on_router_swap_with_deadline() {
        let fs = run(ROUTER_DEADLINE_SAFE);
        assert!(!has(&fs, Category::MissingDeadline, "deposit"), "{:#?}", fs);
    }
}

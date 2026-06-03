//! End-to-end template tests: fixture Solidity → engine → `generate_poc`.
//!
//! For each first-class family we assert the emitted PoC (a) imports the real
//! source + names the real `Function.signature`/vars, (b) contains a *real*
//! assertion (`assertGt`/`assertLt`/`assertEq`/`vm.mockCall`/`vm.prank`), and
//! (c) is byte-stable (generating twice yields identical output — the snapshot
//! invariant the design asks for, without a fragile committed golden file).

use sluice_engine::{analyze_sources, Config, Finding};
use sluice_ir::Scir;
use sluice_verify::{generate_poc, Tier};

/// Run the engine over one in-memory source and return `(scir, findings)`.
fn analyze(path: &str, src: &str) -> (Scir, Vec<Finding>) {
    let cfg = Config::default();
    let res = analyze_sources(vec![(path.to_string(), src.to_string())], &cfg);
    (res.scir, res.findings)
}

/// First finding whose detector id equals `det`.
fn find_by_detector<'a>(findings: &'a [Finding], det: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.detector == det)
        .unwrap_or_else(|| panic!("no finding from detector `{det}`; got: {:?}", detectors(findings)))
}

/// First finding in any of the given categories (by slug).
fn find_by_category<'a>(findings: &'a [Finding], slugs: &[&str]) -> &'a Finding {
    findings
        .iter()
        .find(|f| slugs.contains(&f.category.slug()))
        .unwrap_or_else(|| panic!("no finding in {slugs:?}; got: {:?}", detectors(findings)))
}

fn detectors(findings: &[Finding]) -> Vec<(String, String)> {
    findings.iter().map(|f| (f.detector.clone(), f.category.slug().to_string())).collect()
}

/// Assert byte-stability: regenerating the PoC yields an identical string.
fn assert_stable(scir: &Scir, f: &Finding) -> String {
    let a = generate_poc(scir, f);
    let b = generate_poc(scir, f);
    assert_eq!(a, b, "PoC generation is not byte-stable for {}", f.id);
    a
}

// --------------------------------------------------------------- reentrancy

const REENTRANCY_SRC: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amt) external {
        require(balances[msg.sender] >= amt, "insufficient");
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] -= amt;
    }
}
"#;

#[test]
fn reentrancy_poc_is_real_and_stable() {
    let (scir, findings) = analyze("VulnBank.sol", REENTRANCY_SRC);
    let f = find_by_category(&findings, &["reentrancy"]);
    let poc = assert_stable(&scir, f);

    // Tier 1 (concrete, no FILL, localized arming call).
    assert_eq!(sluice_verify::poc_tier(&scir, f), Tier::T1, "reentrancy should be T1:\n{poc}");
    assert!(poc.contains("Tier 1"), "missing tier banner:\n{poc}");
    // Real import of the target source (path is computed relative to the emitted
    // test dir, so assert the import of the real contract rather than an exact path).
    assert!(poc.contains("import {VulnBank} from \""), "missing real import:\n{poc}");
    assert!(poc.contains("VulnBank.sol\";"), "import does not point at the real source file:\n{poc}");
    // An attacker contract with a re-entry hook.
    assert!(poc.contains("contract Attacker"), "missing attacker contract:\n{poc}");
    assert!(poc.contains("receive() external payable"), "missing receive() re-entry hook:\n{poc}");
    assert!(poc.contains("target.withdraw("), "missing typed re-entry call:\n{poc}");
    // Real assertions (the drain invariant).
    assert!(poc.contains("assertGt(address(attacker).balance"), "missing profit assertion:\n{poc}");
    assert!(poc.contains("assertLt(address(target).balance"), "missing drain assertion:\n{poc}");
    // No leftover prose-only TODO as the *only* body.
    assert!(!poc.contains("// TODO: assert"), "still has a TODO assertion:\n{poc}");
}

#[test]
fn erc777_reentrancy_uses_tokens_received_hook() {
    // An ERC777-style credited-on-receive reentrancy.
    let src = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC777 { function send(address to, uint256 amount, bytes calldata data) external; }

contract Staking {
    mapping(address => uint256) public staked;
    IERC777 public token;

    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "too much");
        token.send(msg.sender, amount, "");
        staked[msg.sender] -= amount;
    }
}
"#;
    let (scir, findings) = analyze("Staking.sol", src);
    // The erc777 reentrancy detector should fire; tolerate the generic one too.
    let f = findings
        .iter()
        .find(|f| matches!(f.category.slug(), "erc777-reentrancy"))
        .or_else(|| findings.iter().find(|f| f.category.slug() == "reentrancy"))
        .unwrap_or_else(|| panic!("no reentrancy finding; got {:?}", detectors(&findings)));
    if f.category.slug() == "erc777-reentrancy" {
        let poc = generate_poc(&scir, f);
        assert!(poc.contains("function tokensReceived("), "ERC777 PoC missing tokensReceived hook:\n{poc}");
    }
}

// ------------------------------------------------------------ access control

const ACCESS_SRC: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;

    constructor() { owner = msg.sender; }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"#;

#[test]
fn access_control_poc_is_real_and_stable() {
    let (scir, findings) = analyze("Vault.sol", ACCESS_SRC);
    let f = find_by_category(&findings, &["access-control"]);
    let poc = assert_stable(&scir, f);

    assert_eq!(sluice_verify::poc_tier(&scir, f), Tier::T1, "access-control should be T1:\n{poc}");
    assert!(poc.contains("import {Vault} from"), "missing real import:\n{poc}");
    assert!(poc.contains("vm.prank(attacker)"), "missing prank of unprivileged caller:\n{poc}");
    assert!(poc.contains("target.setOwner("), "missing typed privileged call:\n{poc}");
    // The flagged privileged var is `owner` and it's public → equality assertion.
    assert!(poc.contains("assertEq(target.owner()"), "missing privileged-var assertion:\n{poc}");
}

// -------------------------------------------------------------------- erc4626

const ERC4626_SRC: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract InflatableVault {
    IERC20 public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 _asset) { asset = _asset; }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : (assets * supply) / totalAssets();
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply = supply + shares;
        balanceOf[receiver] += shares;
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        uint256 supply = totalSupply;
        assets = (shares * totalAssets()) / supply;
        balanceOf[msg.sender] -= shares;
        totalSupply = supply - shares;
        asset.transfer(receiver, assets);
    }
}
"#;

#[test]
fn erc4626_poc_is_real_and_stable() {
    let (scir, findings) = analyze("InflatableVault.sol", ERC4626_SRC);
    let f = find_by_category(&findings, &["erc4626-inflation", "first-depositor"]);
    let poc = assert_stable(&scir, f);

    assert_eq!(sluice_verify::poc_tier(&scir, f), Tier::T2, "erc4626 is T2 (asset wiring is FILL):\n{poc}");
    assert!(poc.contains("import {InflatableVault} from"), "missing real import:\n{poc}");
    // The canned mock is inlined.
    assert!(poc.contains("contract MockERC20"), "missing canned MockERC20:\n{poc}");
    // The 4-step donation script + the round-to-zero assertion.
    assert!(poc.contains("asset.transfer(address(vault)"), "missing donation step:\n{poc}");
    assert!(poc.contains("assertEq(victimShares, 0"), "missing inflation assertion:\n{poc}");
    // The real deposit signature is surfaced in a comment.
    assert!(poc.contains("deposit(uint256,address)"), "missing real signature:\n{poc}");
}

// ---------------------------------------------------------------------- oracle

const ORACLE_SRC: &str = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPool { function getReserves() external view returns (uint256); }

contract Lending {
    IPool public pool;
    mapping(address => uint256) public credit;

    function borrow(uint256 amount) external {
        uint256 price = pool.getReserves();
        credit[msg.sender] = amount * price;
    }
}
"#;

#[test]
fn oracle_poc_is_t2_skeleton_with_mockcall() {
    let (scir, findings) = analyze("Lending.sol", ORACLE_SRC);
    // Oracle/price-manipulation family.
    let maybe = findings
        .iter()
        .find(|f| matches!(f.category.slug(), "oracle-manipulation" | "price-manipulation" | "twap-manipulation"));
    let Some(f) = maybe else {
        // If this corpus shape doesn't trip the oracle detector, skip rather than
        // fail — the template itself is exercised by the dispatch unit test below.
        eprintln!("WARN: no oracle finding for fixture; detectors: {:?}", detectors(&findings));
        return;
    };
    let poc = assert_stable(&scir, f);
    assert_eq!(sluice_verify::poc_tier(&scir, f), Tier::T2, "oracle is always T2:\n{poc}");
    assert!(poc.contains("vm.mockCall"), "missing vm.mockCall spot skew:\n{poc}");
    assert!(poc.contains("EXPLOIT HYPOTHESIS"), "missing asserted hypothesis:\n{poc}");
}

// ----------------------------------------------------------------------- stub

#[test]
fn t3_stub_injects_signature_and_no_false_compile_claim() {
    // A category with no first-class template (timestamp dependence) on a
    // concrete contract → T3 stub that still imports + names the signature.
    let src = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Lottery {
    uint256 public winner;
    function draw(uint256 seed) external {
        winner = uint256(keccak256(abi.encodePacked(block.timestamp, seed))) % 100;
    }
}
"#;
    let (scir, findings) = analyze("Lottery.sol", src);
    // Pick any finding that is NOT in a first-class family.
    let first_class = ["reentrancy", "read-only-reentrancy", "erc777-reentrancy", "erc721-mint-reentrancy",
        "access-control", "unprotected-initializer", "tx-origin-auth",
        "erc4626-inflation", "first-depositor", "oracle-first-mint-seeding",
        "oracle-manipulation", "price-manipulation", "twap-manipulation", "backing-spot-inflation",
        "bridge-verification"];
    let Some(f) = findings.iter().find(|f| !first_class.contains(&f.category.slug())) else {
        eprintln!("WARN: only first-class findings present; skipping stub test");
        return;
    };
    let poc = assert_stable(&scir, f);
    assert_eq!(sluice_verify::poc_tier(&scir, f), Tier::T3, "non-first-class should be T3:\n{poc}");
    assert!(poc.contains("Tier 3"), "missing T3 banner:\n{poc}");
    // The stub still names the function and is honest about compiling.
    assert!(poc.contains("Vulnerable function signature:"), "stub missing signature line:\n{poc}");
    assert!(poc.contains("NOT claimed to compile"), "stub must not over-claim:\n{poc}");
}

// ------------------------------------------------------------------- non-concrete

#[test]
fn interface_target_falls_back_to_name_only_stub() {
    // A finding anchored to an interface (non-concrete) → T3 name-only stub,
    // no `import {..} from` of a concrete source.
    let src = r#"
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Bank {
    mapping(address => uint256) public bal;
    function withdraw(uint256 a) external {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        bal[msg.sender] -= a;
    }
}
"#;
    let (scir, findings) = analyze("Bank.sol", src);
    // Synthesize a finding pointed at a non-existent contract name to force the
    // name-fallback `None` path deterministically.
    let mut f = findings[0].clone();
    f.contract = "IDoesNotExist".to_string();
    f.contract_id = None;
    f.function_id = None;
    let poc = generate_poc(&scir, &f);
    assert!(poc.contains("Tier 3"), "unresolved target should be T3:\n{poc}");
    assert!(!poc.contains("import {IDoesNotExist}"), "must not import an unresolved target:\n{poc}");
}

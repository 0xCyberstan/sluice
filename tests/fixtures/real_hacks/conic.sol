// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Conic Finance (Omnipool) — July 21, 2023
// Approximate loss:  ~$3,200,000 (CRV/ETH-side ConicPool drained)
// Expected detector: reentrancy
//
// Root cause: Conic's Omnipool allocated user deposits across several Curve LP
// positions. The deposit path added liquidity to a *native-ETH* Curve pool, and
// that Curve call transferred ETH back to the Omnipool — handing control to the
// Omnipool's `receive()` BEFORE the deposit finished updating its own share /
// allocation accounting (`totalUnderlying` and minted LP shares). This is the
// classic read-only / cross-contract reentrancy window: a view getter that
// values the pool (`exchangeRate()`, used to size minted shares and to price the
// LP token for other integrators) reads `totalUnderlying` / `totalShares` while
// they are still STALE — the new deposit's underlying has been pulled and the
// Curve position grown, but `totalUnderlying`/`totalShares` have not yet been
// written. An attacker re-entering during the ETH callback observes the inflated
// per-share value and mints/redeems against the manipulated `exchangeRate`,
// extracting more than they deposited.
//
// The defect is the checks-effects-interactions inversion with NO reentrancy
// guard: the external (control-transferring) Curve/ETH call happens BEFORE the
// share/allocation state is settled, and a public view consumes that state
// mid-update.

interface ICurvePool {
    // Adds liquidity; on a native-ETH pool this transfers ETH and can hand
    // control back to the depositor (the read-only-reentrancy trigger).
    function add_liquidity(uint256[2] calldata amounts, uint256 minMint)
        external
        payable
        returns (uint256 lpMinted);
}

contract ConicOmnipool {
    ICurvePool public immutable curvePool; // underlying Curve LP allocation

    uint256 public totalUnderlying;               // accounting: assets backing the pool
    uint256 public totalShares;                   // Conic LP token supply
    mapping(address => uint256) public balanceOf; // Conic LP shares per holder

    constructor(ICurvePool _curvePool) {
        curvePool = _curvePool;
    }

    // VULNERABLE read-only getter: per-share value from live accounting. During a
    // deposit's Curve/ETH callback, `totalUnderlying`/`totalShares` are stale, so
    // this returns a manipulated value to any re-entrant consumer.
    function exchangeRate() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalUnderlying * 1e18) / totalShares;
    }

    // VULNERABLE deposit: makes the external Curve call (which transfers ETH and
    // re-enters via receive()) and only AFTER that updates share/allocation
    // accounting. No nonReentrant guard.
    function deposit(uint256 amount) external payable returns (uint256 shares) {
        uint256 rate = exchangeRate();

        // ---- INTERACTION first: allocate to Curve; native-ETH pool sends ETH
        // back, handing control to the caller's receive() with state still stale.
        uint256[2] memory amounts = [amount, uint256(0)];
        curvePool.add_liquidity{value: msg.value}(amounts, 0);

        // ---- EFFECTS settled too late: shares priced off pre-update accounting,
        // and totalUnderlying/totalShares written only now.
        shares = (amount * 1e18) / rate;
        totalUnderlying += amount;
        totalShares += shares;
        balanceOf[msg.sender] += shares;
    }

    function withdraw(uint256 shares) external returns (uint256 amount) {
        amount = (shares * exchangeRate()) / 1e18;
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;
        totalUnderlying -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
    }

    receive() external payable {}
}

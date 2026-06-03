// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for the `internal-share-pricing-rounding` detector.
//
// The pro-rata stake/share pricing lives in INTERNAL helpers (`_stakeAt`,
// `_activeBalanceOf`) that the name-gated `rounding-direction` detector never
// inspects (it only looks at externally-reachable, conversion-named functions
// such as deposit/withdraw/redeem/mint/burn). These helpers floor-divide a
// stake/share quantity with no rounding control, so the truncation rounds
// against the protocol — the Symbiotic `NetworkRestakeDelegator._stakeAt` /
// `_sharesAt` shape.

contract NetworkRestakeDelegator {
    uint256 internal activeStake;        // total stake currently active
    uint256 internal activeShares;       // total active shares
    mapping(address => uint256) internal activeSharesOf;

    // Thin public surface: forwards to the internal pricing helpers. The
    // rounding decision is NOT made here.
    function stakeAt(address operator) external view returns (uint256) {
        return _stakeAt(operator);
    }

    function activeBalanceOf(address operator) external view returns (uint256) {
        return _activeBalanceOf(operator);
    }

    // VULNERABLE: pro-rata stake = activeStake * shareOf / activeShares, floored.
    // Internal + not a conversion name => invisible to `rounding-direction`.
    function _stakeAt(address operator) internal view returns (uint256) {
        return activeStake * activeSharesOf[operator] / activeShares;
    }

    // VULNERABLE: a second internal pro-rata helper, same floor hazard.
    function _activeBalanceOf(address operator) private view returns (uint256 bal) {
        bal = activeSharesOf[operator] * activeStake / activeShares;
    }
}

// SAFE counterpart: the internal helper pins the rounding direction with the
// `+ activeShares - 1` ceil idiom, so rounding was deliberately handled.
contract SafeRestakeDelegator {
    uint256 internal activeStake;
    uint256 internal activeShares;
    mapping(address => uint256) internal activeSharesOf;

    function stakeAt(address operator) external view returns (uint256) {
        return _stakeAt(operator);
    }

    function _stakeAt(address operator) internal view returns (uint256) {
        return (activeStake * activeSharesOf[operator] + activeShares - 1) / activeShares;
    }
}

// SAFE negative control: an internal helper with the exact mul-then-div shape
// but operating on fee/time quantities unrelated to stake/share accounting.
contract FeeAccrual {
    uint256 internal feeBps;
    uint256 internal duration;
    uint256 internal period;

    function _accruedFee() internal view returns (uint256) {
        return feeBps * duration / period;
    }
}

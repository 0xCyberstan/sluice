// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture for the `proportional-split-residual` detector.
//
// Bug class (Symbiotic `Vault.onSlash`): an amount is split across two or more
// buckets with FLOOR division (`amount * weight / total`), and the leftover
// rounding dust is then FORCE-assigned to a single bucket via a
// `amount - a - b` residual. Each floor division truncates toward zero, so the
// summed buckets fall short of `amount`; the residual sink silently eats all of
// that dust, systematically over-allocating one bucket. Because the weights and
// `amount` are caller/stake-influenced, the residual size is attacker-steerable.

// ---------------------------------------------------------------------------
// VULNERABLE: two floor-divided buckets, remainder forced onto a third bucket.
// ---------------------------------------------------------------------------
contract VulnerableSlasher {
    uint256 public activeStake;
    uint256 public withdrawals;
    uint256 public totalStake;
    uint256 public nextEpochWithdrawals;
    mapping(uint256 => uint256) public slashedOf;

    // Splits `amount` proportionally between the active and withdrawing stake,
    // then dumps the floor-division remainder onto `nextSlashed` — one bucket
    // absorbs every wei of rounding dust.
    function onSlash(uint256 amount, uint256 epoch) external {
        uint256 activeSlashed   = amount * activeStake / totalStake;   // floor
        uint256 withdrawSlashed = amount * withdrawals / totalStake;   // floor
        uint256 nextSlashed     = amount - activeSlashed - withdrawSlashed; // forced residual
        slashedOf[epoch] = nextSlashed;
        nextEpochWithdrawals -= nextSlashed;
    }
}

// ---------------------------------------------------------------------------
// SAFE: same two-bucket split, but the buckets round UP via the
// `(.. + denom - 1) / denom` ceil idiom, so no single bucket silently eats the
// dust. The detector suppresses (rounding direction is pinned fairly).
// ---------------------------------------------------------------------------
contract SafeSlasher {
    uint256 public activeStake;
    uint256 public withdrawals;
    uint256 public totalStake;
    uint256 public nextEpochWithdrawals;
    mapping(uint256 => uint256) public slashedOf;

    function onSlash(uint256 amount, uint256 epoch) external {
        uint256 activeSlashed   = (amount * activeStake + totalStake - 1) / totalStake;
        uint256 withdrawSlashed = (amount * withdrawals + totalStake - 1) / totalStake;
        uint256 nextSlashed     = amount - activeSlashed - withdrawSlashed;
        slashedOf[epoch] = nextSlashed;
        nextEpochWithdrawals -= nextSlashed;
    }
}

// ---------------------------------------------------------------------------
// SAFE (negative control): a single division and a single subtraction
// (`amount - fee`) — an ordinary net-amount split, not a >= 2-bucket forced
// residual. The division-count and subtraction-spine gates keep this silent.
// ---------------------------------------------------------------------------
contract SafeSplitter {
    uint256 public feeBps;
    uint256 public treasury;
    mapping(address => uint256) public credit;

    function pay(uint256 amount) external {
        uint256 fee = amount * feeBps / 10000;
        uint256 net = amount - fee;
        treasury += fee;
        credit[msg.sender] += net;
    }
}

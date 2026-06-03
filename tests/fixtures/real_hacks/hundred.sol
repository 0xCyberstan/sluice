// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Hundred Finance — March 16, 2022 (Gnosis Chain); recurred April 15, 2023 (Optimism)
// Approximate loss:  ~$6-7M (~$2M collateral deposited, >$6M of liquidity drained)
// Expected detector: reentrancy
//
// Root cause: Hundred Finance is a Compound v2 fork. Its markets (hTokens) followed
// Compound's classic checks-effects ordering BUG: redeemFresh()/borrowFresh() send
// the underlying out to the user (doTransferOut) BEFORE writing the user's updated
// supply / total-supply accounting, and there is no nonReentrant guard. On a plain
// ERC20 underlying this is harmless, but Hundred listed a Gnosis-bridge token whose
// transfer is ERC677-style: transferring to a contract invokes the recipient's
// onTokenTransfer() callback mid-transfer. The attacker's callback re-entered the
// market while the recorded balances were still stale, redeeming/borrowing again
// against the same not-yet-debited shares to drain all available liquidity.

// ERC677: like ERC20, but transferring to a contract fires onTokenTransfer() on the
// recipient — a control-transferring call in the middle of the token move.
interface IERC677 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract HundredMarket {
    IERC677 public immutable underlying; // Gnosis-bridge ERC677 token (onTokenTransfer hook)

    mapping(address => uint256) public supplyShares; // hToken balance per user (1:1 here)
    uint256 public totalSupplyShares;

    constructor(IERC677 _underlying) {
        underlying = _underlying;
    }

    function mint(uint256 amount) external {
        underlying.transferFrom(msg.sender, address(this), amount);
        supplyShares[msg.sender] += amount;
        totalSupplyShares += amount;
    }

    // VULNERABLE (Compound redeemFresh ordering): the underlying is transferred OUT to
    // the redeemer FIRST — firing the ERC677 onTokenTransfer callback into attacker code —
    // and only AFTER that does the market debit supplyShares / totalSupplyShares. The
    // re-entered call sees the old, larger balance and redeems the same shares again.
    // No nonReentrant modifier guards this path.
    function redeem(uint256 shares) external {
        require(supplyShares[msg.sender] >= shares, "insufficient shares");

        // EFFECTS-AFTER-INTERACTION: external transfer (hook) precedes state update.
        underlying.transfer(msg.sender, shares); // onTokenTransfer -> attacker re-enters

        supplyShares[msg.sender] -= shares;       // stale by the time it runs
        totalSupplyShares -= shares;
    }
}

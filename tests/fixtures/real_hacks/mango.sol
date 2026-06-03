// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Mango Markets — October 11, 2022
// Approximate loss: ~$115M
// Expected detector: oracle-manipulation
//
// Root cause: Mango valued a trader's account (collateral + unrealized perp PnL)
// using the live spot price of the thinly-traded MNGO market. The attacker funded
// two accounts, opened a large long perp on one against a matching short on the
// other, then spent ~$5M buying MNGO on low-liquidity spot venues to ramp the
// oracle price ~10x within minutes. Because the long position was marked to that
// pumped spot price, its UNREALIZED PnL exploded and was counted directly as
// borrowing power, letting the attacker borrow/withdraw ~$115M of other assets
// against collateral that was only momentarily "worth" that much. There is NO
// deviation bound, NO liquidity/depth check, and NO TWAP on the price feed.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// Thinly-traded market whose spot price an attacker can ramp within one tx/block.
interface ISpotMarket {
    function getPrice() external view returns (uint256); // spot, attacker-movable; no depth/TWAP
}

contract MangoPerpMargin {
    ISpotMarket public immutable market; // MNGO-style thin market feeding the price
    IERC20 public immutable quoteToken;  // borrowable/withdrawable quote asset (e.g. USDC)

    mapping(address => uint256) public deposits;     // quote collateral posted
    mapping(address => uint256) public perpBaseLong; // long size (base units)
    mapping(address => uint256) public perpEntry;    // avg entry price of the long
    mapping(address => uint256) public borrowed;     // outstanding debt

    constructor(ISpotMarket _market, IERC20 _quoteToken) {
        market = _market;
        quoteToken = _quoteToken;
    }

    function deposit(uint256 amount) external {
        deposits[msg.sender] += amount;
        require(quoteToken.transferFrom(msg.sender, address(this), amount), "transfer failed");
    }

    // Open a long perp at the current spot price. Plumbing for the bug under test.
    function openLong(uint256 baseSize) external {
        perpEntry[msg.sender] = market.getPrice();
        perpBaseLong[msg.sender] += baseSize;
    }

    // VULNERABLE: account value = deposits + unrealized PnL, where PnL is marked
    // to the live spot price of a thin market. Pumping getPrice() inflates this
    // borrow power instantly -- no deviation/liquidity bound, no TWAP.
    function accountValue(address user) public view returns (uint256) {
        uint256 mark = market.getPrice(); // manipulable spot read
        uint256 unrealizedPnl = perpBaseLong[user] * (mark - perpEntry[user]) / 1e18;
        return deposits[user] + unrealizedPnl;
    }

    // Borrow power is set directly by the manipulable spot valuation above.
    function borrow(uint256 amount) external {
        require(borrowed[msg.sender] + amount <= accountValue(msg.sender), "undercollateralized");
        borrowed[msg.sender] += amount;
        require(quoteToken.transfer(msg.sender, amount), "transfer failed");
    }
}

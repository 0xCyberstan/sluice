// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         xSURGE / SurgeToken (Safe T) reentrancy drain (August 16, 2021)
// Approximate loss:  ~$5,000,000 (~12,000 BNB on BSC)
// Expected detector: reentrancy
//
// Root cause: SurgeToken's sell()/sellAll() path computed the BNB payout from the
// seller's CURRENT token balance, then sent that BNB to msg.sender via a raw
// low-level call, and only AFTER the transfer returned did it debit the seller's
// balance and burn the tokens. The external call hands control to the seller's
// receive()/fallback BEFORE any state is updated, and there is NO reentrancy
// guard, so the attacker's receive() re-entered sell() over and over. Each
// re-entry re-read the still-undebited balance and the still-full contract BNB
// reserve, paying out the "full" amount again and again until the reserve drained.
//
// The defect is the checks-effects-interactions inversion itself: the balance is
// READ to size the payout, BNB is sent (control transfer), and the balance is
// ZEROED only afterward, with no guard.

contract SurgeToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    // Buy SURGE with BNB; the contract's BNB balance backs the token (reserve).
    function purchase() external payable {
        uint256 minted = msg.value; // 1:1 mint for the reconstruction
        balanceOf[msg.sender] += minted;
        totalSupply += minted;
    }

    // VULNERABLE: interactions-before-effects with no reentrancy guard.
    // The payout is sized from the seller's CURRENT balance, the BNB is sent
    // (handing control to msg.sender's receive()), and only THEN is the balance
    // zeroed and the supply burned. A re-entrant sell() sees the same undebited
    // balance and full reserve and is paid out again.
    function sell() external {
        // ---- read BEFORE the external call (stale value used for the payout) ----
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to sell");
        uint256 payout = (address(this).balance * amount) / totalSupply;

        // ---- INTERACTION: raw BNB transfer hands control to the caller ----
        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "transfer failed");

        // ---- EFFECTS: balance zeroed / supply burned AFTER the call (too late) ----
        balanceOf[msg.sender] = 0;
        totalSupply -= amount;
    }

    receive() external payable {}
}

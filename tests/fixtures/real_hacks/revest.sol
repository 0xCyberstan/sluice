// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:         Revest Finance — March 27, 2022
// Approximate loss:  ~$2M
// Expected detector: reentrancy
//
// Root cause: Revest minted ERC-1155 "FNFT" tokens to represent locked deposits.
// The ERC-1155 _mint() spec sends an onERC1155Received() acceptance callback to
// the recipient AFTER the recipient's balance is increased but BEFORE Revest had
// finished updating its own FNFT supply/deposit accounting. With no reentrancy
// guard, the attacker (a contract) re-entered mint() from inside the callback
// while the per-FNFT `supply` and `depositAmount` were still mid-update / stale.
// Each reentrant mint credited the SAME deposit again, so a single token's worth
// of collateral minted many FNFTs (double/triple mint). The attacker then redeemed
// the inflated supply to withdraw far more value than was ever deposited.

interface IERC1155Receiver {
    // ERC-1155 acceptance hook: control is handed to `msg.sender` (the recipient)
    // during the mint, before the caller has settled its own accounting.
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);
}

contract RevestFNFTHandler {
    // Per-FNFT-id bookkeeping the protocol relies on when minting & redeeming.
    mapping(uint256 => uint256) public supply;        // how many of FNFT `id` exist
    mapping(uint256 => uint256) public depositAmount; // value backing each unit of `id`
    mapping(address => mapping(uint256 => uint256)) public balanceOf; // holder balances

    uint256 public nextId;

    // Minimal ERC-1155-style mint that fires the acceptance callback.
    // VULNERABLE: the external onERC1155Received() call to the recipient runs
    // BEFORE `supply`/`depositAmount` are written, and there is no nonReentrant
    // guard. A contract recipient re-enters mint() here with stale accounting,
    // minting additional FNFTs against the same `value` (double-mint).
    function mint(uint256 id, uint256 quantity, uint256 value) external returns (uint256) {
        // Credit the recipient's raw balance first (as ERC-1155 _mint does)...
        balanceOf[msg.sender][id] += quantity;

        // ...then hand control to the recipient via the acceptance callback,
        // BEFORE protocol supply/deposit accounting is finalized.
        IERC1155Receiver(msg.sender).onERC1155Received(
            msg.sender,
            address(0),
            id,
            quantity,
            ""
        );

        // State updated only AFTER the external call: read-before / write-after.
        // On reentry these run against the pre-update values, so the same `value`
        // backs multiple mints.
        supply[id] += quantity;
        depositAmount[id] = value; // overwritten/duplicated per reentrant call

        return id;
    }

    // Redeem burns FNFTs and pays out `depositAmount` per unit; because `supply`
    // was inflated by the reentrant mints, total payout exceeds the real deposit.
    function redeem(uint256 id, uint256 quantity) external returns (uint256 payout) {
        require(balanceOf[msg.sender][id] >= quantity, "insufficient");
        balanceOf[msg.sender][id] -= quantity;
        supply[id] -= quantity;
        payout = depositAmount[id] * quantity; // over-pays on inflated supply
    }
}

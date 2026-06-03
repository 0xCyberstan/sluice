// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:         Grim Finance (Fantom yield vault) — December 18, 2021
// Approximate loss:  ~$30,000,000
// Expected detector: erc777-reentrancy
//
// Root cause: GrimBoostVault.depositFor() let the caller pass in the `token`
// (the underlying "want") to deposit. Because the token was attacker-chosen, it
// could be a hook-bearing / ERC777-style token whose `safeTransferFrom` hands
// control back to the sender mid-transfer. The vault pulled the tokens FIRST
// (firing the hook), computed minted shares from the balance delta, and only
// THEN minted — with NO reentrancy guard. The attacker's transfer hook re-entered
// depositFor() while `totalSupply` / pooled balance were still stale, so each
// nested deposit minted shares against an under-counted pool. Unwinding the
// recursion credited far more shares than tokens supplied, which were redeemed
// to drain the vault's strategy.
//
// The dominant vulnerable pattern: token.safeTransferFrom(msg.sender, this, amount)
// on a caller-supplied, hook-bearing token executed BEFORE shares are minted,
// with shares derived from a balance snapshot and no nonReentrant lock.
//
interface IERC777Like {
    // Looks like a vanilla ERC20 pull, but on a hook-bearing / ERC777 token this
    // fires the sender's `tokensToSend` hook mid-transfer — a control transfer
    // back to the attacker before `deposit` has minted anything.
    function safeTransferFrom(address from, address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract GrimBoostVault {
    // Caller-supplied shares accounting (vault "moo" tokens).
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    // Total underlying the vault believes it controls (strategy + idle).
    function balance(IERC777Like token) public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    // VULNERABLE: `token` is chosen by the caller, so it can be a hook-bearing
    // ERC777-style token. The pull fires that hook BEFORE shares are minted, and
    // there is no reentrancy guard. The hook re-enters depositFor() while `pool`
    // and `totalSupply` are stale, minting inflated shares on unwind.
    function depositFor(IERC777Like token, uint256 amount, address recipient) public {
        uint256 pool = balance(token);                          // snapshot (stale on reentry)
        uint256 before = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount); // hook -> attacker re-enters
        uint256 received = token.balanceOf(address(this)) - before;

        uint256 minted;
        if (totalSupply == 0) {
            minted = received;
        } else {
            // shares priced against the pre-deposit pool, which the reentrant
            // call already mutated — under-counts the pool, over-mints shares.
            minted = (received * totalSupply) / pool;
        }
        totalSupply += minted;
        shares[recipient] += minted; // effect applied only after reentry
    }
}

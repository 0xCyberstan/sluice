// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        PancakeBunny (BUNNY) — May 19, 2021
// Approximate loss: ~$45M (≈697k BUNNY minted and dumped)
// Expected detector: oracle-manipulation
//
// Root cause: PancakeBunny's vault paid performance rewards in newly MINTED
// BUNNY, and the mint amount was scaled by the SPOT price of the BNB-BUNNY
// PancakeSwap LP — derived live from the pair's `getReserves()` and the vault's
// LP `balanceOf`. The attacker flash-loaned a large amount of BNB, swapped it
// into the BNB-BUNNY pool to pump the reported LP/BUNNY price, called the vault
// so it minted reward BUNNY valued at that inflated spot price, then dumped the
// BUNNY and unwound the swap. There is NO TWAP and NO Chainlink feed: the price
// is an instantaneous, single-transaction-movable reserve read.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IPancakePair {
    // Instantaneous pool reserves -> attacker-movable inside one transaction.
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function totalSupply() external view returns (uint256);
}

contract BunnyVault {
    IPancakePair public immutable bnbBunnyLP; // BNB-BUNNY PancakeSwap pair
    IERC20 public immutable bunny;            // BUNNY reward token (mintable)

    mapping(address => uint256) public lpBalanceOf; // staked LP per user
    uint256 public mintedBunny;                     // accounting: total reward minted

    constructor(IPancakePair _lp, IERC20 _bunny) {
        bnbBunnyLP = _lp;
        bunny = _bunny;
    }

    // VULNERABLE: value one LP token in BUNNY terms from the pool's SPOT
    // reserves. reserve0 = BNB, reserve1 = BUNNY. Both `getReserves()` and the
    // LP `totalSupply()` are live, single-transaction-movable reads — no TWAP,
    // no robust oracle.
    function lpPriceInBunny() public view returns (uint256) {
        (uint112 reserveBnb, uint112 reserveBunny, ) = bnbBunnyLP.getReserves(); // spot, attacker-movable
        uint256 lpSupply = bnbBunnyLP.totalSupply();
        // BUNNY-equivalent value of the BNB side, expressed per whole LP token.
        return (uint256(reserveBnb) * uint256(reserveBunny) / uint256(reserveBnb)) * 1e18 / lpSupply;
    }

    // Reward is freshly MINTED BUNNY scaled by the manipulable spot LP price.
    // External entry point: the attacker pumps the pool, then calls this so the
    // vault mints reward BUNNY at the inflated valuation.
    function getReward() external {
        uint256 staked = lpBalanceOf[msg.sender];
        uint256 valueInBunny = (staked * lpPriceInBunny()) / 1e18; // spot-priced reward
        uint256 mintAmount = valueInBunny;                          // 1:1 perf mint
        mintedBunny += mintAmount;                                  // accounting write
        require(bunny.transfer(msg.sender, mintAmount), "mint/transfer failed");
    }

    function stake(uint256 amount) external {
        require(IERC20(address(bnbBunnyLP)).transfer(address(this), amount), "stake failed");
        lpBalanceOf[msg.sender] += amount;
    }
}

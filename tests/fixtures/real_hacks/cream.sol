// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Incident:        Cream Finance (Iron Bank) — October 27, 2021
// Approximate loss: ~$130M
// Expected detector: oracle-manipulation
//
// Root cause: Cream's price oracle valued a Yearn yVault token (yUSD) used as
// collateral as `underlying.balanceOf(vault) / vault.totalSupply()` — the live
// share price ("price per full share"). That ratio is an instantaneous on-chain
// spot value: an attacker took a flash loan, donated the underlying directly to
// the vault to inflate `balanceOf(vault)` (and held the supply roughly fixed),
// doubling the reported share price, then borrowed far more than the collateral
// was worth. There is NO Chainlink feed and NO TWAP guarding the price.

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IYVault {
    function totalSupply() external view returns (uint256);
    function token() external view returns (address); // the underlying ERC20
}

contract CreamYVaultLending {
    IYVault public immutable yVault;     // yUSD-style share token used as collateral
    IERC20 public immutable underlying;  // the asset the vault holds (e.g. yCRV/USD)
    IERC20 public immutable debtToken;   // borrowable stable

    mapping(address => uint256) public collateralShares; // yVault shares posted
    mapping(address => uint256) public debtOf;

    constructor(IYVault _yVault, IERC20 _debtToken) {
        yVault = _yVault;
        underlying = IERC20(_yVault.token());
        debtToken = _debtToken;
    }

    // VULNERABLE: share price = underlying held by the vault / total shares.
    // `balanceOf(yVault)` is a manipulable spot read (flash-loan donation).
    function pricePerShare() public view returns (uint256) {
        uint256 vaultAssets = underlying.balanceOf(address(yVault)); // spot, attacker-movable
        uint256 shares = yVault.totalSupply();
        return (vaultAssets * 1e18) / shares; // USD value of one share; spot only, no robust feed
    }

    function collateralValue(address user) public view returns (uint256) {
        return (collateralShares[user] * pricePerShare()) / 1e18;
    }

    function depositCollateral(uint256 shares) external {
        IERC20(address(yVault)).transferFrom(msg.sender, address(this), shares);
        collateralShares[msg.sender] += shares;
    }

    function borrow(uint256 amount) external {
        // Borrow power set by the manipulable spot valuation of the collateral.
        require(debtOf[msg.sender] + amount <= collateralValue(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

abstract contract ReentrancyGuard {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

/// @notice ERC4626-style vault using OpenZeppelin's inflation-attack mitigation:
///         a decimals offset creates "virtual shares/assets" so a first-depositor
///         donation cannot meaningfully skew the share price. It also follows
///         checks-effects-interactions and a reentrancy guard, so the vault,
///         reentrancy, and read-only-reentrancy detectors all stay silent.
contract SafeERC4626Vault is ReentrancyGuard {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    // Virtual shares/assets offset (OZ default pattern).
    uint8 private constant _DECIMALS_OFFSET = 6;

    constructor(IERC20 _asset) {
        asset = _asset;
    }

    function _decimalsOffset() internal pure returns (uint256) {
        return _DECIMALS_OFFSET;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // Conversions include + 10**offset (virtual shares) and + 1 (virtual assets),
    // which is the canonical inflation-attack mitigation.
    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalShares + 10 ** _decimalsOffset())) / (totalAssets() + 1);
    }

    function convertToAssets(uint256 shareAmount) public view returns (uint256) {
        return (shareAmount * (totalAssets() + 1)) / (totalShares + 10 ** _decimalsOffset());
    }

    function deposit(uint256 assets, address receiver) external nonReentrant returns (uint256 minted) {
        minted = convertToShares(assets);
        require(minted > 0, "zero shares");
        // checks-effects-interactions: state is updated BEFORE the external call.
        totalShares += minted;
        shares[receiver] += minted;
        require(asset.transferFrom(msg.sender, address(this), assets), "transfer failed");
    }
}

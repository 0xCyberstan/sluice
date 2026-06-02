// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address,uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }

contract VulnBank {
    mapping(address => uint256) public balances;
    address public owner;
    IERC20 public token;

    // classic reentrancy: external call before state update
    function withdraw(uint256 amt) external {
        require(balances[msg.sender] >= amt, "insufficient");
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] -= amt;
    }

    // missing access control on privileged state
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // unchecked ERC20 transfer
    function sweep(address to, uint256 amt) external {
        token.transfer(to, amt);
    }

    // spot price used for valuation (oracle manipulation)
    function collateralValue(address pool) external returns (uint256) {
        uint256 price = token.balanceOf(pool);
        balances[msg.sender] = price * 2;
        return price;
    }
}

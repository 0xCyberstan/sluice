// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// Minimal OZ-style SafeERC20: reverts if the token returns false or the call fails,
// and tolerates non-standard tokens that return no data.
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");
        if (returndata.length > 0) {
            require(abi.decode(returndata, (bool)), "SafeERC20: operation did not succeed");
        }
    }
}

/// @notice Distributor that moves tokens using SafeERC20.safeTransfer, so a token
///         returning false (or non-standard) cannot silently fail.
///         unchecked-return detector must stay silent.
contract SafeERC20Distributor {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;

    constructor(IERC20 _token) {
        token = _token;
    }

    function payout(address to, uint256 amount) external {
        token.safeTransfer(to, amount);
    }

    function pullIn(address from, uint256 amount) external {
        token.safeTransferFrom(from, address(this), amount);
    }
}

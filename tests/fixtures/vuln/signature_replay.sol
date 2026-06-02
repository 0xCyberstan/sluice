// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title SignedClaim
/// @notice Lets users claim tokens by presenting an operator-signed message.
///         VULNERABLE: the signed digest has no nonce and no deadline, so a
///         valid signature can be REPLAYED to claim repeatedly. It also does
///         not check `ecrecover` returned address(0), so a malformed signature
///         that recovers to zero can pass if `signer` is ever unset.
contract SignedClaim {
    IERC20 public immutable token;
    address public signer;

    constructor(IERC20 _token, address _signer) {
        token = _token;
        signer = _signer;
    }

    /// @notice VULNERABLE: no nonce, no deadline, no address(0) guard, no
    ///         replay protection. The same (to, amount, v, r, s) tuple works
    ///         an unlimited number of times.
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad signature");
        token.transfer(to, amount);
    }

    /// @notice Variant that recovers an EIP-191 prefixed hash but is equally
    ///         replayable (still no nonce/deadline tracking).
    function claimPrefixed(address to, uint256 amount, bytes32 r, bytes32 s, uint8 v) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address recovered = ecrecover(ethHash, v, r, s);
        require(recovered == signer, "bad signature");
        token.transfer(to, amount);
    }
}

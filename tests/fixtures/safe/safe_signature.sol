// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal OZ-style ECDSA library with malleability + zero-address protection.
library ECDSA {
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        // Reject upper-range s values (signature malleability) and bad v.
        require(
            uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "invalid s value"
        );
        require(v == 27 || v == 28, "invalid v value");
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "invalid signature");
        return signer;
    }
}

/// @notice Verifies an EIP-712 claim with nonce + deadline replay protection.
///         signature detector must stay silent.
contract SafeSignatureClaimer {
    using ECDSA for bytes32;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 private constant CLAIM_TYPEHASH =
        keccak256("Claim(address owner,uint256 amount,uint256 nonce,uint256 deadline)");

    mapping(address => uint256) public nonces;

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SafeClaimer")),
                block.chainid,
                address(this)
            )
        );
    }

    function claim(address owner, uint256 amount, uint256 deadline, bytes calldata sig) external {
        require(block.timestamp <= deadline, "signature expired");
        uint256 nonce = nonces[owner];
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, owner, amount, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address recovered = digest.recover(sig);
        require(recovered == owner, "bad signer");
        nonces[owner] = nonce + 1; // consume nonce to prevent replay
    }
}

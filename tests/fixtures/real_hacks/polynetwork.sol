// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
//
// Incident:  Poly Network cross-chain bridge hack (August 2021)
// Loss:      ~$611,000,000 (later returned by the attacker)
// Detector:  bridge-verification (Poly arbitrary-relay class)
//
// Root cause: EthCrossChainManager.verifyHeaderAndExecuteTx relayed an inbound
// cross-chain message and then executed an arbitrary low-level call whose target
// contract and method payload were decoded straight out of the attacker-supplied
// message. There was no permitted-target list, so the attacker crafted a message
// that called a privileged function on the destination chain
// (putCurEpochConPubKeyBytes on EthCrossChainData), rotated the bridge "keepers"
// to their own key, and then authorized draining every locked asset.
//
// The dominant vulnerable pattern: dest.call(payload) where BOTH the destination
// address and the call payload come from decoded message data.
//
interface IEthCrossChainData {
    // The privileged keeper-rotation sink the attacker reached through the relay.
    function putCurEpochConPubKeyBytes(bytes calldata curEpochPkBytes) external;
}

contract EthCrossChainManager {
    // Bridge-shaped state: a trusted cross-chain data store and a replay guard.
    IEthCrossChainData public ccData;
    mapping(bytes32 => bool) public processedTx;

    function verifyHeaderAndExecuteTx(bytes calldata message) external returns (bool) {
        bytes32 txId = keccak256(message);
        require(!processedTx[txId], "replayed");
        processedTx[txId] = true;

        // Attacker chooses the destination and the payload, both decoded from the
        // inbound cross-chain message.
        address dest = abi.decode(message, (address));
        bytes memory payload = abi.decode(message, (bytes));

        // Arbitrary low-level call: attacker-chosen destination AND payload reach
        // any privileged function on this chain via a relayed message.
        (bool ok, ) = dest.call(payload);
        require(ok, "exec failed");
        return ok;
    }
}

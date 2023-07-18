// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

interface Bip340Verifier {
    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and a pubkey's x coord `px`.
    ///
    /// px - public key x coordinate
    /// rx - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) external returns (bool);
}


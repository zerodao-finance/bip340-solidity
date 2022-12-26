// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./EllipticCurve.sol";
import "./Secp256k1.sol";

library Bip340 {
    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and a pubkey's x coord `px`.
    ///
    /// p - public key x coordinate
    /// r - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) public pure returns (bool) {
        // TODO DEAL WITH ENDIANNESS

        // Let P = lift_x(int(pk)); fail if that fails.
        uint256 py = EllipticCurve.deriveY(0x02, px, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        bytes32 rxSwap = bytes32(swizzle(rx));
        bytes32 pxSwap = bytes32(swizzle(px));
        uint256 e = computeChallenge(rxSwap, pxSwap, m);

        // Let R = s⋅G - e⋅P.
        (uint256 sgx, uint256 sgy) = EllipticCurve.ecMul(s, Secp256k1.GX, Secp256k1.GY, Secp256k1.AA, Secp256k1.BB);
        (uint256 epx, uint256 epy) = EllipticCurve.ecMul(e, px, py, Secp256k1.AA, Secp256k1.BB);
        (uint256 rvx, uint256 rvy) = EllipticCurve.ecSub(sgx, epx, sgy, epy, Secp256k1.AA, Secp256k1.BB);

        // Fail if is_infinite(R).
        require(rvx != 0 && rvy != 0, "invalid signature 1");
        //if (rvx == 0 && rvy == 0) {
        //    return false;
        //}

        // Fail if not has_even_y(R).
        require((rvy % 2) == 0, "invalid signature 2");
        //if ((rvy % 2) != 0) {
        //    return false;
        //}

        // Fail if x(R) ≠ r.
        require(rvx == rx, "invalid signature 3");

        // All good!
        return true;
    }

    /// BIP340 challenge function.
    ///
    /// Hopefully the first SHA256 call gets inlined.
    function computeChallenge(bytes32 rx, bytes32 px, bytes32 m) internal pure returns (uint256) {
        bytes32 tag = sha256("BIP0340/challenge");
        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        return swizzle(uint256(sha256(abi.encodePacked(tag, tag, rx, px, m)))) % Secp256k1.PP;
    }

    /// Reverses endianness of the value.
    ///
    /// Adapted from: https://ethereum.stackexchange.com/questions/83626
    function swizzle(uint256 inp) internal pure returns (uint256) {
        uint256 v = inp;
        
        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte sequences
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte sequences
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte sequences
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        
        return (v >> 128) | (v << 128);
    }
}


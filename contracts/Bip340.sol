pragma solidity ^0.6.0;

import "witnet/elliptic-curve-solidity@0.2.1/contracts/EllipticCurve.sol";
import "witnet/elliptic-curve-solidity@0.2.1/examples/Secp256k1.sol";

library Bip340 {
    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and a pubkey's x coord `px`.
    ///
    /// p - public key x coordinate
    /// r - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verify(uint256 px, uint256 rx, uint256 s, uint256 m) internal pure returns (bool) {
        // TODO DEAL WITH ENDIANNESS
    
        // Let P = lift_x(int(pk)); fail if that fails.
        uint256 py = EllipticCurve.deriveY(0x02, px, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        uint256 e = uint256(sha256(abi.encodePacked(rx, px, m))) % Secp256k1.PP;

        // Let R = s⋅G - e⋅P.
        uint256 (sgx, sgy) = EllipticCurve.ecMul(s, Secp256k1.GX, Secp256k1.GY, Secp256k1.AA, Secp256k1.BB);
        uint256 (epx, epy) = EllipticCurve.ecMul(e, px, py, Secp256k1.AA, Secp256k1.BB);
        uint256 (rvx, rvy) = EllipticCurve.ecSub(egx, epx, sgy, epy, Secp256k1.AA, Secp256k1.BB);

        // Fail if is_infinite(R).
        if (rvx == 0 && rvy == 0) {
            return false;
        }

        // Fail if not has_even_y(R).
        if ((rvy % 2) != 0) {
            return false;
        }

        // Fail if x(R) ≠ r.
        return rvx == rx;
    }

    // Reverses endianness of the value.
    //
    // Adapted from: https://ethereum.stackexchange.com/questions/83626
    function swapEndianness(uint256 inp) internal pure returns (uint256) {
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


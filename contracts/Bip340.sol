// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./EllipticCurve.sol";
import "./Secp256k1.sol";

contract Bip340 {
    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and a pubkey's x coord `px`.
    ///
    /// px - public key x coordinate
    /// rx - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) public pure returns (bool) {
        // Let P = lift_x(int(pk)); fail if that fails.
        //
        // This *could* be precomputed and stored.
        uint256 py = EllipticCurve.deriveY(0x02, px, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);
        return verifyFull(px, py, rx, s, m);
    }

    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and pubkey coords `px` and `py`.
    ///
    /// px, py - public key coordinates
    /// rx - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verifyFull(uint256 px, uint256 py, uint256 rx, uint256 s, bytes32 m) public pure returns (bool) {
        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        uint256 e = computeChallenge(bytes32(rx), bytes32(px), m);

        // Let R = s⋅G - e⋅P.
        (uint256 rvx, uint256 rvy) = computeRv(s, e, px, py);

        // Fail if is_infinite(R).
        if (rvx == 0 && rvy == 0) { // this could be simpler
            return false;
        }

        // Fail if not has_even_y(R).
        if ((rvy % 2) != 0) {
            return false;
        }

        // Fail if x(R) ≠ r.
        return rvx == rx; // if they match then all good!
    }

    /// Special combination to compute r_v.
    ///
    /// Done with jacobian coordinates to save gas.  Split out to avoid making
    /// the stack too deep.
    function computeRv(uint256 s, uint256 e, uint256 px, uint256 py) internal pure returns (uint256, uint256) {
        // s⋅G - e⋅P.
        (uint256 sgx, uint256 sgy, uint256 sgz) = EllipticCurve.jacMul(s, Secp256k1.GX, Secp256k1.GY, 1, Secp256k1.AA, Secp256k1.PP);
        (uint256 epx, uint256 epy, uint256 epz) = EllipticCurve.jacMul(e, px, py, 1, Secp256k1.AA, Secp256k1.PP);
        uint256 epy_inv = (Secp256k1.PP - epy) % Secp256k1.PP; // only have to flip the y coordinate
        (uint256 rvx, uint256 rvy, uint256 rvz) = EllipticCurve.jacAdd(sgx, sgy, sgz, epx, epy_inv, epz, Secp256k1.PP);

        // Convert back to affine now that we're done.  I don't think we
        // actually have to compute the y coordinate.
        //
        // TODO check on how infinities work here
        return EllipticCurve.toAffine(rvx, rvy, rvz, Secp256k1.PP);
    }

    /// BIP340 challenge function.
    ///
    /// Hopefully the first SHA256 call gets inlined.
    function computeChallenge(bytes32 rx, bytes32 px, bytes32 m) internal pure returns (uint256) {
        // Precomputed `sha256("BIP0340/challenge")`.
        //
        // Saves ~10k gas, mostly from byte shuffling to prepare the call.
        bytes32 tag = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        return uint256(sha256(abi.encodePacked(tag, tag, rx, px, m))) % Secp256k1.PP;
    }
}


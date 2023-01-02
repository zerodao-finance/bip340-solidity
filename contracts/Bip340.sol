// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./EllipticCurve.sol";
import "./Secp256k1.sol";

contract Bip340 {
    event Debug(string ty, bytes32 val);
    event Check(string ty, bool v);

    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and a pubkey's x coord `px`.
    ///
    /// px - public key x coordinate
    /// rx - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) public returns (bool) {
        // Check pubkey is in range.
        if (px >= Secp256k1.PP) {
            return false;
        }

        // Let P = lift_x(int(pk)); fail if that fails.
        //
        // This *could* be precomputed and stored.
        uint256 py = EllipticCurve.deriveY(0x02, px, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);

        // Check pubkey is on curve.
        if (!EllipticCurve.isOnCurve(px, py, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP)) {
            return false;
        }

        return verifyFull(px, py, rx, s, m);
    }

    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and pubkey coords `px` and `py`.  The pubkey must already be on the
    /// curve because we skip some checks with it.
    ///
    /// px, py - public key coordinates
    /// rx - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verifyFull(uint256 px, uint256 py, uint256 rx, uint256 s, bytes32 m) public returns (bool) {
        // Check rx and s are in-range.
        if (rx >= Secp256k1.PP || s >= Secp256k1.NN) {
            return false;
        }

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        uint256 e = computeChallenge(bytes32(rx), bytes32(px), m);

        // Let R = s⋅G - e⋅P.
        // Weird scoping because we have to manipulate the stack here.
        (uint256 rvx, uint256 rvy) = (0, 0);
        {
            uint256 px = px;
            uint256 py = py;
            (uint256 sgx, uint256 sgy, uint256 sgz) = EllipticCurve.jacMul(s, Secp256k1.GX, Secp256k1.GY, 1, Secp256k1.AA, Secp256k1.PP);
            (uint256 epx, uint256 epy, uint256 epz) = EllipticCurve.jacMul(e, px, py, 1, Secp256k1.AA, Secp256k1.PP);

            // Check if it's safe to use jacAdd.
            if (_xToAffine(sgx, sgz, Secp256k1.PP) == _xToAffine(epx, epz, Secp256k1.PP)) {
                return false;
            }

            uint256 epy_inv = (Secp256k1.PP - epy) % Secp256k1.PP; // only have to flip the y coordinate
            (uint256 jrvx, uint256 jrvy, uint256 jrvz) = EllipticCurve.jacAdd(sgx, sgy, sgz, epx, epy_inv, epz, Secp256k1.PP);

            // Convert back to affine now that we're done.
            (rvx, rvy) = EllipticCurve.toAffine(jrvx, jrvy, jrvz, Secp256k1.PP);
        }

        emit Debug("rvx", bytes32(rvx));
        emit Debug("rvy", bytes32(rvy));

        // Fail if is_infinite(R).
        if (rvx == 0 && rvy == 0) { // this could be simpler
            return false;
        }

        // Fail if not has_even_y(R).
        if ((rvy % 2) != 0) {
            return false;
        }

        // Fail if x(R) ≠ r.
        bool res = (rvx == rx);
        return res; // if they match then all good!
    }

    /// BIP340 challenge function.
    ///
    /// Hopefully the first SHA256 call gets inlined.
    function computeChallenge(bytes32 rx, bytes32 px, bytes32 m) internal returns (uint256) {
        // Precomputed `sha256("BIP0340/challenge")`.
        //
        // Saves ~10k gas, mostly from byte shuffling to prepare the call.
        //bytes32 tag = sha256("BIP0340/challenge");
        bytes32 tag = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        return uint256(sha256(abi.encodePacked(tag, tag, rx, px, m))) % Secp256k1.NN;
    }

    /// Internal function for doing the affine conversion for only the x coordinate.
    function _xToAffine(uint256 _x, uint256 _z, uint256 _pp) internal returns (uint256) {
        uint256 zInv = EllipticCurve.invMod(_z, _pp);
        uint256 zInv2 = mulmod(zInv, zInv, _pp);
        return mulmod(_x, zInv2, _pp);
    }
}


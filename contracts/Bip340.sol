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

        // Convert back to affine now that we're done.
        return EllipticCurve.toAffine(rvx, rvy, rvz, Secp256k1.PP);
    }

    /// Batch verification.  Just like the above.  Pass everything as lists of
    /// all the same length.
    ///
    /// The av vector should be independently randomly sampled variables, with
    /// length 1 less than the other vectors.  These should be sampled *after*
    /// the signature verification to be safe, otherwise there's tricks a
    /// malicious signer could screw things up.
    function verifyBatch(uint256 px, uint256 py, uint256[] memory rxv, uint256[] memory sv, bytes32[] memory mv, uint256[] memory av) public pure returns (bool) {
        // Verify lengths so we don't have to check things again.
        //
        // Scoped weirdly because of stack constraints.
        {
            uint256 l = rxv.length;
            uint256 lm1 = l - 1;
            require(l > 1, "VB:XVL");
            require(sv.length == l, "VB:SVL");
            require(mv.length == l, "VB:MVL");
            require(av.length == lm1, "VB:AVL");
        }

        // Again more stack window manipulation.
        (uint256 rhsx, uint256 rhsy) = (0, 0);
        {
            // Order is important for stack constraints.
            (uint256 rhs2x, uint256 rhs2y, uint256 rhs2z) = _computeSum_aieiPi(px, py, rxv, mv, av);
            (uint256 rhs1x, uint256 rhs1y, uint256 rhs1z) = _computeSum_aiRi(rxv, mv, av);
            (uint256 srhsx, uint256 srhsy, uint256 srhsz) = EllipticCurve.jacAdd(rhs1x, rhs1y, rhs1z, rhs2x, rhs2y, rhs2z, Secp256k1.PP);
            (rhsx, rhsy) = EllipticCurve.toAffine(srhsx, srhsy, srhsz, Secp256k1.PP);
        }
        
        (uint256 lhsx, uint256 lhsy) = _computeSum_aisiG(sv, av);

        // Assert equality.
        return (lhsx == rhsx) && (lhsy == rhsy);
    }

    function _computeSum_aisiG(uint256[] memory sv, uint256[] memory av) public pure returns (uint256, uint256) {
        uint256 sumas = sv[0];
        for (uint256 i = 1; i < av.length; i++) {
            sumas += mulmod(av[i - 1], sv[i], Secp256k1.PP);
        }
        
        return EllipticCurve.ecMul(sumas, Secp256k1.GX, Secp256k1.GY, Secp256k1.AA, Secp256k1.PP);
    }

    function _computeSum_aiRi(uint256[] memory rxv, bytes32[] memory mv, uint256[] memory av) public pure returns (uint256, uint256, uint256) {
        uint256 r0y = EllipticCurve.deriveY(0x02, rxv[0], Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);
        (uint256 sumrx, uint256 sumry, uint256 sumrz) = (rxv[0], r0y, 1);

        for (uint256 i = 1; i < av.length; i++) {
            // Split these out so we don't blow the stack window.
            uint256 rxi = rxv[i];
            bytes32 mi = mv[i];
            uint256 ai = av[i - 1];

            // au⋅Ru
            uint256 ryi = EllipticCurve.deriveY(0x02, rxi, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);
            (uint256 arxi, uint256 aryi, uint256 arzi) = EllipticCurve.jacMul(ai, rxi, ryi, 1, Secp256k1.AA, Secp256k1.PP);
            (sumrx, sumry, sumrz) = EllipticCurve.jacAdd(sumrx, sumry, sumrz, arxi, aryi, arzi, Secp256k1.PP);
        }

        return (sumrx, sumry, sumrz);
    }

    function _computeSum_aieiPi(uint256 px, uint256 py, uint256[] memory rxv, bytes32[] memory mv, uint256[] memory av) public pure returns (uint256, uint256, uint256) {
        uint256 e0 = computeChallenge(bytes32(rxv[0]), bytes32(px), mv[0]);
        (uint256 sumepx, uint256 sumepy, uint256 sumepz) = EllipticCurve.jacMul(e0, px, py, 1, Secp256k1.AA, Secp256k1.PP);

        for (uint256 i = 1; i < av.length; i++) {
            // Make some copies so we don't blow the stack window.
            uint256 px2 = px;
            uint256 py2 = py;
            uint256 rxi = rxv[i];
            bytes32 mi = mv[i];
            uint256 ai = av[i - 1];

            // (aueu)⋅Pu
            (uint256 epxi, uint256 epyi, uint256 epzi) = (0, 0, 0);

            // More stack scoping.
            {
                uint256 ei = computeChallenge(bytes32(rxi), bytes32(px2), mi);
                uint256 aiei = mulmod(ai, ei, Secp256k1.PP);
                (epxi, epyi, epzi) = EllipticCurve.jacMul(aiei, px2, py2, 1, Secp256k1.AA, Secp256k1.PP);
            }

            (sumepx, sumepy, sumepz) = EllipticCurve.jacAdd(sumepx, sumepy, sumepz, epxi, epyi, epzi, Secp256k1.PP);
        }

        return (sumepx, sumepy, sumepz);
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


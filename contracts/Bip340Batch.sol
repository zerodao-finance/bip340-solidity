// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./EllipticCurve.sol";
import "./Secp256k1.sol";

contract Bip340Batch {

    event Debug(string ty, uint256 i, bytes32 val);
    event Debug2(string ty, bytes val);

    /// Batch verification.  Just like the above.  Pass everything as lists of
    /// all the same length.
    ///
    /// The av vector should be independently randomly sampled variables, with
    /// length 1 less than the other vectors.  These should be sampled *after*
    /// the signature verification to be safe, otherwise there's tricks a
    /// malicious signer could screw things up.  This can be done by hashing
    /// pubkeys and messages and sigs, perhaps with some other randomness.
    function verifyBatch(uint256 px, uint256 py, uint256[] memory rxv, uint256[] memory sv, bytes32[] memory mv, uint256[] memory av) public returns (bool) {
        // Verify lengths so we don't have to check things again.
        //
        // Scoped weirdly because of stack constraints.
        {
            uint256 l = rxv.length;
            require(l >= 1, "VB:XVL");
            require(rxv.length == l, "VB:RVL");
            require(sv.length == l, "VB:SVL");
            require(mv.length == l, "VB:MVL");
            require(av.length == l - 1, "VB:AVL");
        }

        // Again more stack window manipulation.
        (uint256 rhsx, uint256 rhsy) = (0, 0);
        {
            // Order is important for stack constraints.
            (uint256 rhs2x, uint256 rhs2y) = _computeSum_aieiPi(px, py, rxv, mv, av);
            (uint256 rhs1x, uint256 rhs1y) = _computeSum_aiRi(rxv, av);
            (rhsx, rhsy) = EllipticCurve.ecAdd(rhs1x, rhs1y, rhs2x, rhs2y, Secp256k1.AA, Secp256k1.PP);
        }

        (uint256 lhsx, uint256 lhsy) = _computeSum_aisiG(sv, av);

        emit Debug("lhsx", 0, bytes32(lhsx));
        //emit Debug("lhsy", bytes32(lhsy));
        emit Debug("rhsx", 0, bytes32(rhsx));
        //emit Debug("rhsy", bytes32(rhsy));

        // Assert equality.
        bool res = (lhsx == rhsx) && (lhsy == rhsy);
        if (res) {
            emit Debug("RES", 0, bytes32(uint256(-1) / 0xf));
        } else {
            emit Debug("RES", 0, bytes32(0));
        }

        return res;
    }

    function _computeSum_aisiG(uint256[] memory sv, uint256[] memory av) public returns (uint256, uint256) {
        uint256 sumas = sv[0];
        emit Debug("s", 0, bytes32(sumas));
        for (uint256 i = 1; i <= av.length; i++) {
            emit Debug("s", i,  bytes32(sv[i]));
            emit Debug("a_G", i, bytes32(av[i - 1]));
            uint256 aisi = mulmod(av[i - 1], sv[i], Secp256k1.NN);
            sumas = addmod(sumas, aisi, Secp256k1.NN);
        }

        return EllipticCurve.ecMul(sumas, Secp256k1.GX, Secp256k1.GY, Secp256k1.AA, Secp256k1.PP);
    }

    function _computeSum_aiRi(uint256[] memory rxv, uint256[] memory av) public returns (uint256, uint256) {
        // TODO check that all the R values computed here are even

        // Weird ordering because stack.
        (uint256 sumrx, uint256 sumry) = (rxv[0], 0);
        emit Debug("rx", 0, bytes32(sumrx));
        sumry = EllipticCurve.deriveY(0x02, rxv[0], Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);

        for (uint256 i = 1; i <= av.length; i++) {
            // Split these out so we don't blow the stack window.
            uint256 rxi = rxv[i];
            uint256 ai = av[i - 1];
            emit Debug("rx", i, bytes32(rxi));
            emit Debug("a_R", i, bytes32(ai));

            // au⋅Ru
            uint256 ryi = EllipticCurve.deriveY(0x02, rxi, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);
            (uint256 arxi, uint256 aryi) = EllipticCurve.ecMul(ai, rxi, ryi, Secp256k1.AA, Secp256k1.PP);
            (sumrx, sumry) = EllipticCurve.ecAdd(sumrx, sumry, arxi, aryi, Secp256k1.AA, Secp256k1.PP);
        }

        emit Debug("sumrx", 0, bytes32(sumrx));

        return (sumrx, sumry);
    }

    function _computeSum_aieiPi(uint256 px, uint256 py, uint256[] memory rxv, bytes32[] memory mv, uint256[] memory av) public returns (uint256, uint256) {
        // More stack scoping.
        (uint256 sumepx, uint256 sumepy) = (0, 0);
        {
            emit Debug("rx", 0, bytes32(rxv[0]));
            emit Debug("px", 0, bytes32(px));
            emit Debug("m", 0, bytes32(mv[0]));
            uint256 e0 = computeChallenge(bytes32(rxv[0]), bytes32(px), mv[0]);
            emit Debug("e", 0, bytes32(e0));
            (sumepx, sumepy) = EllipticCurve.ecMul(e0, px, py, Secp256k1.AA, Secp256k1.PP);
        }

        for (uint256 i = 1; i <= av.length; i++) {
            // Make some copies so we don't blow the stack window.
            uint256 px2 = px;
            uint256 py2 = py;
            uint256 rxi = rxv[i];
            bytes32 mi = mv[i];
            uint256 ai = av[i - 1];
            emit Debug("rx", i, bytes32(rxi));
            emit Debug("px", i, bytes32(px2));
            emit Debug("m", i, mi);
            emit Debug("a_P", i, bytes32(ai));

            // (aueu)⋅Pu
            (uint256 epxi, uint256 epyi) = (0, 0);

            // Stack stuff.
            {
                uint256 ei = computeChallenge(bytes32(rxi), bytes32(px2), mi);
                emit Debug("ei", i, bytes32(ei));
                uint256 aiei = mulmod(ai, ei, Secp256k1.NN);
                (epxi, epyi) = EllipticCurve.ecMul(aiei, px2, py2, Secp256k1.AA, Secp256k1.PP);
            }

            (sumepx, sumepy) = EllipticCurve.ecAdd(sumepx, sumepy, epxi, epyi, Secp256k1.AA, Secp256k1.PP);
        }

        emit Debug("sumepx", 0, bytes32(sumepx));

        return (sumepx, sumepy);
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
}


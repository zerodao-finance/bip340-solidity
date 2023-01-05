// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./EllipticCurve.sol";
import "./Secp256k1.sol";

import "./Bip340Util.sol";

contract Bip340Batch {

    uint256 public constant ERRX = uint256(-1);

    event Debug(string ty, uint256 i, bytes32 val);
    event Debug2(string ty, bytes val);

    /// Same as `verifyBatch`, but derives the Y coordinate on the fly.  You
    /// probably don't want to use this and should just precompute the y
    /// coordinate on-chain.
    function verifyBatchXonly(uint256 px, uint256[] memory rxv, uint256[] memory sv, bytes32[] memory mv, uint256[] memory av) public returns (bool) {
        (uint256 py, bool liftOk) = Bip340Util.liftX(px);
        if (!liftOk) {
            return false;
        }

        return verifyBatch(px, py, rxv, sv, mv, av);
    }

    /// Batch verification.  Just like the above.  Pass everything as lists of
    /// all the same length.
    ///
    /// The av vector should be independently randomly sampled variables, with
    /// length 1 less than the other vectors.  These should be sampled *after*
    /// the signature verification to be safe, otherwise there's tricks a
    /// malicious signer could screw things up.  This can be done by hashing
    /// pubkeys and messages and sigs, perhaps with some other randomness.
    ///
    /// In a few places, we use functions returning (-1, 0) to signal a check
    /// failed and the full signature verification is wrong, but we don't
    /// propagate up where.  Although checking with a typical verifier should
    /// be able to infer.
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
            (uint256 rhs1x, uint256 rhs1y) = _computeSum_aiRi(rxv, av);
            if (rhs1x == ERRX) {
                return false;
            }

            (uint256 rhs2x, uint256 rhs2y) = _computeSum_aieiPi(px, py, rxv, mv, av);            
            if (rhs2x == ERRX) {
                return false;
            }

            //(rhs1x, rhs1y);//

            (rhsx, rhsy) = EllipticCurve.ecAdd(rhs1x, rhs1y, rhs2x, rhs2y, Secp256k1.AA, Secp256k1.PP);
        }

        //(0, 0);//
        (uint256 lhsx, uint256 lhsy) = _computeSum_aisiG(sv, av);
        if (lhsx == ERRX) {
            return false;
        }

        emit Debug("lhsx", 0, bytes32(lhsx));
        emit Debug("rhsx", 0, bytes32(rhsx));

        // Assert equality.
        bool res = (lhsx == rhsx) && (lhsy == rhsy);
        if (res) {
            emit Debug("RES", 0, bytes32(uint256(-1) / 0xf));
        } else {
            emit Debug("RES", 0, bytes32(0));
        }

        return res;
    }

    function _computeSum_aiRi(uint256[] memory rxv, uint256[] memory av) public returns (uint256, uint256) {
        // Weird ordering because stack.
        (uint256 sumrx, uint256 sumry) = (rxv[0], 0);
        emit Debug("rx", 0, bytes32(sumrx));
        
        // Check in range.
        {
            (uint256 ry, bool liftOk) = Bip340Util.liftX(sumrx);
            if (!liftOk) {
                return (ERRX, 0);
            }
            sumry = ry;
        }

        for (uint256 i = 1; i <= av.length; i++) {
            // Split these out so we don't blow the stack window.
            uint256 rxi = rxv[i];
            uint256 ai = av[i - 1];

            if (rxi >= Secp256k1.PP) {
                return (ERRX, 0);
            }

            emit Debug("rx", i, bytes32(rxi));
            emit Debug("a_R", i, bytes32(ai));

            // au⋅Ru (with some checks)
            (uint256 ryi, bool liftOk) = Bip340Util.liftX(rxi);
            if (!liftOk) {
                return (ERRX, 0);
            }

            // I shouldn't need this, but apparently we do to pass test vector 9.
            //
            // I believe this is somehow related to the x equality check near line 71 in the single verification.
            if (!EllipticCurve.isOnCurve(rxi, ryi, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP)) {
                return (ERRX, 0);
            }

            (uint256 arxi, uint256 aryi) = EllipticCurve.ecMul(ai, rxi, ryi, Secp256k1.AA, Secp256k1.PP);
            (sumrx, sumry) = EllipticCurve.ecAdd(sumrx, sumry, arxi, aryi, Secp256k1.AA, Secp256k1.PP);
        }

        emit Debug("sumrx", 0, bytes32(sumrx));

        return (sumrx, sumry);
    }

    function _computeSum_aieiPi(uint256 px, uint256 py, uint256[] memory rxv, bytes32[] memory mv, uint256[] memory av) public returns (uint256, uint256) {
        // We don't need to do any range checks in this function since we
        // already did them in the above one.
    
        // More stack scoping.
        (uint256 sumepx, uint256 sumepy) = (0, 0);
        {
            emit Debug("rx", 0, bytes32(rxv[0]));
            emit Debug("px", 0, bytes32(px));
            emit Debug("m", 0, bytes32(mv[0]));
            uint256 e0 = Bip340Util.computeChallenge(bytes32(rxv[0]), bytes32(px), mv[0]);
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
                uint256 ei = Bip340Util.computeChallenge(bytes32(rxi), bytes32(px2), mi);
                emit Debug("ei", i, bytes32(ei));
                uint256 aiei = mulmod(ai, ei, Secp256k1.NN);
                (epxi, epyi) = EllipticCurve.ecMul(aiei, px2, py2, Secp256k1.AA, Secp256k1.PP);
            }

            (sumepx, sumepy) = EllipticCurve.ecAdd(sumepx, sumepy, epxi, epyi, Secp256k1.AA, Secp256k1.PP);
        }

        emit Debug("sumepx", 0, bytes32(sumepx));

        return (sumepx, sumepy);
    }

    function _computeSum_aisiG(uint256[] memory sv, uint256[] memory av) public returns (uint256, uint256) {
        uint256 sumas = sv[0];
        if (sumas >= Secp256k1.NN) {
            return (ERRX, 0);
        }

        emit Debug("s", 0, bytes32(sumas));
        for (uint256 i = 1; i <= av.length; i++) {
            uint256 si = sv[i];
            uint256 ai = av[i - 1];
            if (si >= Secp256k1.NN || ai >= Secp256k1.NN) {
                return (ERRX, 0);
            }

            emit Debug("s", i,  bytes32(si));
            emit Debug("a_G", i, bytes32(ai));
            uint256 aisi = mulmod(ai, si, Secp256k1.NN);
            sumas = addmod(sumas, aisi, Secp256k1.NN);
        }

        return EllipticCurve.ecMul(sumas, Secp256k1.GX, Secp256k1.GY, Secp256k1.AA, Secp256k1.PP);
    }
}


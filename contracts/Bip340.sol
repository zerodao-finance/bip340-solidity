// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

import "./EllipticCurve.sol";
import "./Secp256k1.sol";

contract Bip340 {

    /// Verifies a BIP340 signature parsed as `(rx, s)` form against a message
    /// `m` and a pubkey's x coord `px`.
    ///
    /// p - public key x coordinate
    /// r - signature r commitment
    /// s - signature s proof
    /// m - message hash
    function verify(uint256 px, uint256 rx, uint256 s, bytes32 m) public pure {
        // Let P = lift_x(int(pk)); fail if that fails.
        uint256 py = EllipticCurve.deriveY(0x02, px, Secp256k1.AA, Secp256k1.BB, Secp256k1.PP);

        // Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
        uint256 e = computeChallenge(bytes32(rx), bytes32(px), m);

        // Let R = s⋅G - e⋅P.
        (uint256 sgx, uint256 sgy) = EllipticCurve.ecMul(s, Secp256k1.GX, Secp256k1.GY, Secp256k1.AA, Secp256k1.PP);
        (uint256 epx, uint256 epy) = EllipticCurve.ecMul(e, px, py, Secp256k1.AA, Secp256k1.PP);
        (uint256 rvx, uint256 rvy) = EllipticCurve.ecSub(sgx, sgy, epx, epy, Secp256k1.AA, Secp256k1.PP);

        // Fail if is_infinite(R).
        require(rvx != 0 && rvy != 0, "invalid signature 1");

        // Fail if not has_even_y(R).
        require((rvy % 2) == 0, "invalid signature 2");

        // Fail if x(R) ≠ r.
        require(rvx == rx, "invalid signature 3");

        // All good!
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


# sol-bip340

Solidity implementation of BIP340 Schnorr signatures, to be able to verify
Taproot-compliant signatures on Ethereum.

## Usage

At a high level, we need to pass 3 things to verify a BIP340 signature are
structured as follows:

* public key, as 32 byte X coordinate ("xonly" pubkey)
* signature, 64 bytes
  * `r` commitment, 32 bytes
  * `s` proof, 32 bytes
* message hash, arbitrary 32 bytes

We typically refer to these in code as `px`, `rx`, `s`, and `m`.  If there's a
list of them, we add a `v` suffix for "vector".

All of these values being 32 bytes is convenient on the EVM, as they exactly
occupy a stack element or storage slot.

The main functions of interest are:

* `Bip340`
  * `verify(uint256 px, uint256 rx, uint256 s, bytes32 m)`
  * `verifyFull(uint256 px, uint256 py, uint256 rx, uint256 s, bytes32 m)
* `Bip340Batch`
  * `verifyBatch(uint256 px, uint256[] memory rxv, uint256[] memory sv, bytes32[] memory mv, uint256[] memory av)`
  * `verifyBatchFull(uint256 px, uint256 py, uint256[] memory rxv, uint256[] memory sv, bytes32[] memory mv, uint256[] memory av)`
* `Bip340Util`
  * `liftX(uint256 px)` returning Y coordinate and success

The `Full` variants of the functions vary from the non-`Full` ones in that they
require the y coordinate of the public key to be provided precomputed.  This
can be done safely by using the `liftX` function from the `Bip340Util` library.

## Testing

The tests run on the standard BIP340 test vectors in various configurations, as
well as some other messages in a few configurations.

For some reason, Ganache does not like how the test scripts were configured, so
this was tested using Anvil as below.

```
cd tests/
brownie test --network anvil
```

You must run the test from the directory because the Python scripts look to the
adjacent `test-vectors.csv` to find them.

## Gas costs

Verifying a single signature with this library costs ~610k gas.  Verifying a
batch of signatures is hard to measure directly, but it seems safe to verify
up to 20 signatures before reaching whatever the default limit Anvil sets.


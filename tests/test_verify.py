#from brownie import *

from brownie.network import priority_fee

import json
import binascii
import pytest
import random

import csv

# 04
#   47938d402bc1a2824c8a9ea3f906845d64d6fb4d9f227b3cc8034c682890eceb - x
#   cf36ad5177a1c58e1867d91a977e2e38b59aae4346cb58cf5b97907672690cc4 - y
PK_X = '47938d402bc1a2824c8a9ea3f906845d64d6fb4d9f227b3cc8034c682890eceb'
PK_Y = 'cf36ad5177a1c58e1867d91a977e2e38b59aae4346cb58cf5b97907672690cc4'

# if this is less than the size of the list we only pass up to this many in the batch lists
BATCH_SIZE = 2

BATCH_SIGS = [
    # deadbeef (e=2e184f02e782c7b15b8fede26da057bc90c881dd332e78714e9a26a1a44d92ba)
    '47d96ea78440a958a37a0d8d828e78534d8d0d992feff8e57edbca8f127d3a31aafe267387faee4ce165d5e4b7875d33b19a46603aa18202db5d7cd5fb3f976d',

    # cafebabe (e=56ce52f71df03d5d15df6bf8fc4cc3f45c75ab4b9580de7ee20a5ca59c81db19)
    'ca8b8a2bbd71adba3e0fe91aad284827220f714299769f5d02d6dc175ed761e8d0cd776b347bcba19670872150134151944a45374aef25b2b9756da30c5f86dd',

    # 12345678 (e=9255adc4e6fe5991eb1f15181c4e5b2c872b7ea7b0fdeb82c0ed27c11715b8b1)
    'f8e03a5e4d1baec4660346a699d47c6f37b46b2ba6753324b0ddff2cb2c6a0ecff3a241c4ad1a1c6e003e2d6cf94c385f83a0f19ccf85c615bd144134cd1b6ef',
]

BATCH_MSG_HASHES = [
    # deadbeef
    '5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953',

    # cafebabe
    '65ab12a8ff3263fbc257e5ddf0aa563c64573d0bab1f1115b9b107834cfa6971',

    # 12345678
    'b2ed992186a5cb19f6668aade821f502c1d00970dfd0e35128d51bac4649916c',
]

# e = 72dcfd80a93844c4413d153a5c5203bdb93515f3d35ec6158bd46895a25dbef0
# rv = 02 7674d4cbe57e69dea138a3e87ad9acb935019b30a276d6afcff73b1b608c97d9

def test_verify_single(Bip340, accounts):
    priority_fee('10 gwei')

    pkx = int.from_bytes(binascii.unhexlify(PK_X), 'big')

    lib = accounts[0].deploy(Bip340)

    for check_idx in range(3):
        sig = binascii.unhexlify(BATCH_SIGS[check_idx])
        assert len(sig) == 64, 'sig not 64 bytes'
        sig_rx = int.from_bytes(sig[:32], 'big')
        sig_s = int.from_bytes(sig[32:], 'big')
        msghash = binascii.unhexlify(BATCH_MSG_HASHES[check_idx])

        print(pkx, sig_rx, sig_s, BATCH_MSG_HASHES[check_idx])

        res = lib.verify.transact(pkx, sig_rx, sig_s, msghash, {'from': accounts[0]})
        print('RES', check_idx, res)

        # TODO actually check passed

"""
def test_verify_invalid(Bip340, accounts):
    priority_fee('10 gwei')

    pkx = int.from_bytes(binascii.unhexlify(PK_X), 'big')

    lib = accounts[0].deploy(Bip340)

    for check_idx in range(3):
        sig = binascii.unhexlify(BATCH_SIGS[check_idx])
        assert len(sig) == 64, 'sig not 64 bytes'

        # Modify the sig to be slightly wrong.
        flip_at = random.randint(0, 63)
        sig = sig[:flip_at] + bytes(sig[flip_at] ^ 0xff) + sig[(flip_at + 1):]

        sig_rx = int.from_bytes(sig[:32], 'big')
        sig_s = int.from_bytes(sig[32:64], 'big')
        msghash = binascii.unhexlify(BATCH_MSG_HASHES[check_idx])

        print(pkx, sig_rx, sig_s, BATCH_MSG_HASHES[check_idx])

        res = lib.verify.transact(pkx, sig_rx, sig_s, msghash, {'from': accounts[0]})
        print('RES', check_idx, res)
        print('RES2', res.return_value)

        # TODO actually check failed
"""

def test_vectors(Bip340, accounts):
    priority_fee('10 gwei')

    lib = accounts[0].deploy(Bip340)

    with open('test-vectors.csv', 'r') as csvfile:
        tvs = csv.DictReader(csvfile)

        for row in tvs:
            print('CHECK TEST VECTOR', row['index'], '(', row['comment'] or 'no comment', ')')

            pkx_bytes = binascii.unhexlify(row['public key'])
            msghash = binascii.unhexlify(row['message'])
            sig = binascii.unhexlify(row['signature'])
            exp_res = row['verification result'] == 'TRUE'

            #print(row)

            pkx = int.from_bytes(pkx_bytes, 'big')
            sig_rx = int.from_bytes(sig[:32], 'big')
            sig_s = int.from_bytes(sig[32:], 'big')

            res = lib.verify.call(pkx, sig_rx, sig_s, msghash, {'from': accounts[0]})
            print('RES', res)
            #for ev in res.events:
            #    print('event', ev)

            print('RES', row['index'], 'exp', exp_res, 'got', res)
            if res != exp_res:
                raise RuntimeError('discrepancy with test vector: ' + row['comment'])


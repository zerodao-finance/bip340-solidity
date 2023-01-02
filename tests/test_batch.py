#from brownie import *

from brownie.network import priority_fee

import json
import binascii
import pytest
import random

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

def test_verify_batch(Bip340Batch, accounts):
    priority_fee('10 gwei')

    pkx = int.from_bytes(binascii.unhexlify(PK_X), 'big')
    pky = int.from_bytes(binascii.unhexlify(PK_Y), 'big')

    rv = []
    sv = []
    mv = []
    for i in range(BATCH_SIZE):
        sig = binascii.unhexlify(BATCH_SIGS[i])
        assert len(sig) == 64, 'sig not 64 bytes'
        rv.append(int.from_bytes(sig[:32], 'big'))
        sv.append(int.from_bytes(sig[32:], 'big'))
        mv.append(binascii.unhexlify(BATCH_MSG_HASHES[i]))

    av = []
    for i in range(BATCH_SIZE - 1):
        # close enough to the correct range to be correct
        av.append(random.randint(0, 2 ** 254))

    #print(pkx, pky, rv, sv, mv, av)

    lib = accounts[0].deploy(Bip340Batch)
    print('BEFORE VERIFYBATCH')
    res = lib.verifyBatch.transact(pkx, pky, rv, sv, mv, av, {'from': accounts[0]})
    for ev in res.events:
        print('event', ev)
    #raise RuntimeError('check things')
    print('AFTER VERIFYBATCH')


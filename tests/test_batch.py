#from brownie import *

from brownie.network import priority_fee

import json
import binascii
import pytest
import random
import itertools
import csv

# 04
#   47938d402bc1a2824c8a9ea3f906845d64d6fb4d9f227b3cc8034c682890eceb - x
#   cf36ad5177a1c58e1867d91a977e2e38b59aae4346cb58cf5b97907672690cc4 - y
PK_X = '47938d402bc1a2824c8a9ea3f906845d64d6fb4d9f227b3cc8034c682890eceb'
PK_Y = 'cf36ad5177a1c58e1867d91a977e2e38b59aae4346cb58cf5b97907672690cc4'

# if this is less than the size of the list we only pass up to this many in the batch lists
BATCH_SIZE = 3

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

    av = [random.randint(0, 2 ** 254) for _ in range(BATCH_SIZE - 1)]
    assert len(av) == len(mv) - 1, 'av wrong length'

    #print(pkx, pky, rv, sv, mv, av)

    lib = accounts[0].deploy(Bip340Batch)
    res = lib.verifyBatch.call(pkx, pky, rv, sv, mv, av, {'from': accounts[0]})
    if type(res) is bool:
        print('test_verify_batch RES', res)
        assert res, 'batch did not verify correctly'
    else:
        for ev in res.events:
            print('event', ev)

def test_vectors_singular(Bip340Batch, accounts):
    priority_fee('10 gwei')

    lib = accounts[0].deploy(Bip340Batch)

    rows = None
    with open('test-vectors.csv', 'r') as csvfile:
        tvs = csv.DictReader(csvfile)
        rows = list(tvs)

    print('there are', len(rows), 'ok rows')

    BATCHDUPS = 20 # can't go much higher or we run out of gas

    # This is kinda a weak test.  We're not trying multiple signatures from the
    # same privkey on *different messsages*, it's the same signature on the#
    # same message for every call we do, just multiple times.  The math works
    # the same way regardless, but we don't really *want* to do it this way.
    for row in rows:
        print('== CHECKING VECTOR', row['index'], '(', row['comment'] or 'no comment', ')')
        pkx_bytes = binascii.unhexlify(row['public key'])
        msghash = binascii.unhexlify(row['message'])
        sig = binascii.unhexlify(row['signature'])

        pkx = int.from_bytes(pkx_bytes, 'big')
        sig_rx = int.from_bytes(sig[:32], 'big')
        sig_s = int.from_bytes(sig[32:], 'big')

        rxv = [sig_rx] * BATCHDUPS
        sv = [sig_s] * BATCHDUPS
        mv = [msghash] * BATCHDUPS
        av = [random.randint(0, 2 ** 254) for _ in range(BATCHDUPS - 1)]
        assert len(av) == len(mv) - 1, 'av wrong length'

        exp = row['verification result'] == 'TRUE'
        res = lib.verifyBatchXonly.call(pkx, rxv, sv, mv, av, {'from': accounts[0]})
        if type(res) is bool:
            assert res == exp, 'batch did not verify (%s) as expected (%s)' % (res, exp)

def test_vectors_bad(Bip340Batch, accounts):
    priority_fee('10 gwei')

    lib = accounts[0].deploy(Bip340Batch)

    rows = None
    with open('test-vectors.csv', 'r') as csvfile:
        tvs = csv.DictReader(csvfile)
        rows = list(tvs)

    # Hardcoded, taken from the test vectors file, it's fine.
    badgroups = [[rows[5]], rows[6:14], [rows[14]]]

    for fullgroup in badgroups:
        for i in range(len(fullgroup) + 1):
            if i == 0: continue
            group = fullgroup[:i]
            if len(group) == 0: continue
            
            idxs = ' '.join(map(lambda r: r['index'], group))
            comments = ', '.join(map(lambda r: r['comment'] or 'no comment', group))
            print('== CHECKING ROWS', idxs, '(', comments, ')')

            row0 = group[0]
            pkx_bytes = binascii.unhexlify(row0['public key'])
            pkx = int.from_bytes(pkx_bytes, 'big')

            rxv = []
            sv = []
            mv = []
            for r in group:
                assert r['public key'] == row0['public key'], 'bad grouping'
                sig = binascii.unhexlify(r['signature'])
                rxv.append(int.from_bytes(sig[:32], 'big'))
                sv.append(int.from_bytes(sig[32:], 'big'))
                mv.append(binascii.unhexlify(r['message']))

            av = [random.randint(0, 2 ** 254) for _ in range(len(group) - 1)]
            assert len(av) == len(mv) - 1, 'av wrong length'

            res = lib.verifyBatchXonly.call(pkx, rxv, sv, mv, av, {'from': accounts[0]})

            if type(res) is not bool:
                for ev in res.events: print('event', ev)
            else:
                assert not res, 'batch verified when it should have not'


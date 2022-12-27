#from brownie import *

from brownie.network import priority_fee

import json
import binascii
import pytest

PK_X = 'f47eb96e8590b858d5522c4c4489d9870bffdf97136f3a5a8ba0d0930620fa72'
SIG = '7674d4cbe57e69dea138a3e87ad9acb935019b30a276d6afcff73b1b608c97d9ecdd80142c99ceedd72936c6c57965966eab3d8ef7078dd3bbba292c874ea1e6'
MSG_HASH = '3977fff1f0521218d0ae4bfbbc556eaea6fc29146290fa108588c3f7d2672fab'

# e = 72dcfd80a93844c4413d153a5c5203bdb93515f3d35ec6158bd46895a25dbef0
# rv = 02 7674d4cbe57e69dea138a3e87ad9acb935019b30a276d6afcff73b1b608c97d9

def test_verify(Bip340, accounts):
    priority_fee('10 gwei')

    pkx = int.from_bytes(binascii.unhexlify(PK_X), 'big')
    sig = binascii.unhexlify(SIG)
    assert len(sig) == 64, 'sig not 64 bytes'
    sig_rx = int.from_bytes(sig[:32], 'big')
    sig_s = int.from_bytes(sig[32:], 'big')
    msghash = binascii.unhexlify(MSG_HASH)

    print(pkx, sig_rx, sig_s, MSG_HASH)

    lib = accounts[0].deploy(Bip340)
    print('BEFORE VERIFY')
    res = lib.verify(pkx, sig_rx, sig_s, msghash, {'from': accounts[0]})
    print('res', res)
    print('AFTER VERIFY')


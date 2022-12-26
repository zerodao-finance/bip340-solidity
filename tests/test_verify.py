import binascii
import pytest

PK_X = '550256b7f5f571652a4bc2bdf8f50d05cf4b45a3821c75eaf2583dab74101bc3'
SIG = 'e727159d38e1cd3f6293f1b837ca5a3fb700a2ec7b83e12b22b2d9cc6c17209cc0881332649cb23934384b63b48ef8efcd9faa52e7c422df2a16842351b9ddd4'
MSG_HASH = '3977fff1f0521218d0ae4bfbbc556eaea6fc29146290fa108588c3f7d2672fab'

def test_verify(Bip340, accounts):
    pkx = int.from_bytes(binascii.unhexlify(PK_X), 'big')
    sig = binascii.unhexlify(SIG)
    assert len(sig) == 64, 'sig not 64 bytes'
    sig_rx = int.from_bytes(sig[:32], 'big')
    sig_s = int.from_bytes(sig[32:], 'big')
    msghash = binascii.unhexlify(MSG_HASH)

    print(pkx, sig_rx, sig_s, MSG_HASH)

    lib = accounts[0].deploy(Bip340)
    res = lib.verify(pkx, sig_rx, sig_s, msghash)

    print(res)


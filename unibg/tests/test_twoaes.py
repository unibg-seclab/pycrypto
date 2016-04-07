from Crypto.Cipher import AES, TWOAES
from timeit import timeit
from os import urandom

KILO = 1024
MEGA = 1024 * KILO
GIGA = 1024 * MEGA
TERA = 1024 * GIGA

k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'

def twoaes(use_aesni):
    a1 = AES.new(k1, mode=AES.MODE_ECB, use_aesni=use_aesni)
    a2 = AES.new(k2, mode=AES.MODE_ECB, use_aesni=use_aesni)
    ta = TWOAES.new(k1 + k2, mode=TWOAES.MODE_ECB, use_aesni=use_aesni)

    st = '_this-is-a-test_'
    ct = a1.encrypt(st)
    print('CT: %s' % ct)

    rt = ta.encrypt(ct)
    print('RT: %s' % rt)
    assert rt == a2.encrypt(st)

    pt = a2.decrypt(rt)
    print('PT: %s' % pt)
    assert st == pt.decode('ascii')


def test_twoaes():
    twoaes(use_aesni=False)

def test_twoaesni():
    twoaes(use_aesni=True)

from Crypto.Cipher import AES, TWOAES
from functools import partial
from timeit import default_timer
from os import urandom

KiB = 2**10
MiB = 2**10 * KiB
GiB = 2**10 * MiB

# bytegenerator = lambda size: urandom(size)
bytegenerator = lambda size: bytes(bytearray(size))

#OCCUPYRAM = bytegenerator(5 * GiB)

k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'

def mean(lst, outliers):
    lst = sorted(lst)[outliers:-outliers]
    return float(sum(lst)) / len(lst)

def repeat(fn, times, outliers):
    return mean([fn() for _ in range(times)], outliers)

def test(use_aesni, size, window):
    a1 = AES.new(k1, mode=AES.MODE_ECB, use_aesni=use_aesni)
    a2 = AES.new(k2, mode=AES.MODE_ECB, use_aesni=use_aesni)
    ta = TWOAES.new(k1 + k2, mode=TWOAES.MODE_ECB, use_aesni=use_aesni, window=window)

    def single_test(size, recrypt):
        # setup
        plain = bytegenerator(size)
        cipher = a1.encrypt(plain)

        # test
        start = default_timer()
        cipher2 = recrypt(cipher)
        time = default_timer() - start
        assert a2.decrypt(cipher2) == plain
        return time

    def recrypt_aesaes(cipher):
        plain = a1.decrypt(cipher)
        return a2.encrypt(plain)

    pattern = '{:<22} | {:<22} | {:<22}'
    results = (
            repeat(partial(single_test, size, recrypt_aesaes), 20, 5),
            repeat(partial(single_test, size, ta.encrypt), 20, 5))
    print(pattern.format(window, *results))

if __name__ == '__main__':
    print('\n' + "WITH AESNI".center(72, '='))
    for window in range(1, 20):
        test(use_aesni=True, size=4*MiB, window=window)
#    print('\n' + "WITHOUT AESNI".center(72, '='))
#    test(use_aesni=False)


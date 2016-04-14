#!/usr/bin/env python

from Crypto.Cipher import AES, TWOAES
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

def test(use_aesni):

    a1 = AES.new(k1, mode=AES.MODE_ECB, use_aesni=use_aesni)
    a2 = AES.new(k2, mode=AES.MODE_ECB, use_aesni=use_aesni)
    ta = TWOAES.new(k1 + k2, mode=TWOAES.MODE_ECB, use_aesni=use_aesni)

    sizes = [1*KiB, 10*KiB, 100*KiB,
             1*MiB, 10*MiB, 100*MiB]
#            1*GiB]


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

    pattern = '{:^22} | {:^22} | {:^22}'
    print(pattern.format('SIZE', 'TIME AES+AES', 'TIME TWOAES'))
    print(pattern.format('-'*22, '-'*22, '-'*22))
    pattern = pattern.replace('^', '<')

    for size in sizes:
        print(pattern.format(size,
              single_test(size, lambda cipher: a2.encrypt(a1.decrypt(cipher))),
              single_test(size, ta.encrypt)))

if __name__ == '__main__':
    print('\n' + "WITH AESNI".center(72, '='))
    test(use_aesni=True)
    print('\n' + "WITHOUT AESNI".center(72, '='))
    test(use_aesni=False)


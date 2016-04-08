from Crypto.Cipher import AES, TWOAES
from timeit import timeit
from os import urandom

import numpy as np

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

KiB = 2**10
MiB = 2**10 * KiB
GiB = 2**10 * MiB

# bytegenerator = lambda size: urandom(size)
bytegenerator = lambda size: bytes(bytearray(size))

k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'

def test(use_aesni):

    logger.info('Instantiating ciphers ...')
    a1 = AES.new(k1, mode=AES.MODE_ECB, use_aesni=use_aesni)
    a2 = AES.new(k2, mode=AES.MODE_ECB, use_aesni=use_aesni)
    ta = TWOAES.new(k1 + k2, mode=TWOAES.MODE_ECB, use_aesni=use_aesni)

    logger.info('Generating data ...')
    sizes = np.array([1*KiB, 10*KiB, 100*KiB,
                      1*MiB, 10*MiB, 100*MiB])

    logger.info('Running tests ...')
    pattern = '{:^22} | {:^22} | {:^22}'
    print(pattern.format('SIZE', 'TIME AES+AES', 'TIME TWOAES'))
    print(pattern.format('-'*22, '-'*22, '-'*22))
    pattern = '{:<22} | {:<22,.5f} | {:<22,.5f}'

    def single_test(size):
        data = a1.encrypt(bytegenerator(size))
        result = (timeit(lambda: a2.encrypt(a1.decrypt(data)), number=2),
                  timeit(lambda: ta.encrypt(data), number=2))
        print(pattern.format(size, *result))
        return result

    times = [single_test(size) for size in sizes]

if __name__ == '__main__':
    print('\n' + "WITH AESNI".center(72, '='))
    test(use_aesni=True)
    print('\n' + "WITHOUT AESNI".center(72, '='))
    test(use_aesni=False)


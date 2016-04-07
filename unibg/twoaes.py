from Crypto.Cipher import AES, TWOAES
from timeit import timeit
from os import urandom

import numpy as np

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

KB = 1024
MB = 1024 * KB
GB = 1024 * MB
TB = 1024 * GB

# bytegenerator = lambda size: urandom(size)
bytegenerator = lambda size: bytes(bytearray(size))

k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'
use_aesni = False

logger.info('Instantiating ciphers ...')
a1 = AES.new(k1, mode=AES.MODE_ECB, use_aesni=use_aesni)
a2 = AES.new(k2, mode=AES.MODE_ECB, use_aesni=use_aesni)
ta = TWOAES.new(k1 + k2, mode=TWOAES.MODE_ECB, use_aesni=use_aesni)

logger.info('Generating data ...')
sizes = np.array([1*KB, 10*KB, 100*KB,
                  1*MB, 10*MB, 100*MB])

logger.info('Running tests ...')
pattern = '{:^22} | {:^22} | {:^22}'
print(pattern.format('SIZE', 'TIME AES+AES', 'TIME TWOAES'))
print(pattern.format('-'*22, '-'*22, '-'*22))
pattern = '{:<22} | {:<22,.5f} | {:<22,.5f}'

def test(size):
    data = a1.encrypt(bytegenerator(size))
    result = (timeit(lambda: a2.encrypt(a1.decrypt(data)), number=2),
              timeit(lambda: ta.encrypt(data), number=2))
    print(pattern.format(size, *result))
    return result

times = [test(size) for size in sizes]

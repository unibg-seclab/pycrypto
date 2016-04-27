#!/usr/bin/env python

import matplotlib
matplotlib.use('Agg') # do not use X
from matplotlib import pyplot as plt

from humanize.filesize import naturalsize
from Crypto.Cipher import AES, TWOAES
from functools import partial
from timeit import default_timer
import numpy as np
from os import urandom

## PARAMETERS ##
EXPMIN = 10
EXPMAX = 30
RUNS = 10
OUT = 2

# bytegenerator = lambda size: urandom(size)
bytegenerator = lambda size: bytes(bytearray(size))

#OCCUPYRAM = bytegenerator(5 * GiB)

k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'

sizes = [2**exp for exp in range(EXPMIN, EXPMAX+1)]
pattern = '{:<22} | {:<22} | {:<22}'

def remove_outliers(data, outliers):
    data.sort()
    return data if not outliers else data[outliers:-outliers]

def repeat(fn, times, outliers):
    data = [fn() for _ in range(times)]
    data = remove_outliers(data, outliers)
    return np.mean(data), np.std(data)

def test(size, use_aesni):

    a1 = AES.new(k1, mode=AES.MODE_ECB, use_aesni=use_aesni)
    a2 = AES.new(k2, mode=AES.MODE_ECB, use_aesni=use_aesni)

    if use_aesni:
        ta = TWOAES.new(k1+k2, mode=TWOAES.MODE_ECB, use_aesni=True, window=10)
    else:
        ta = TWOAES.new(k1+k2, mode=TWOAES.MODE_ECB, use_aesni=False)

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

    results = ( repeat(partial(single_test, size, recrypt_aesaes), RUNS, OUT)
              + repeat(partial(single_test, size, ta.encrypt), RUNS, OUT))
    print(pattern.format(naturalsize(size,binary=True), results[0], results[2]))
    return results

def plot(results):
    xs = sizes
    ys_aesaes, std_aesaes, ys_twoaes, std_twoaes = map(np.array, zip(*results))

    fig, ax1 = plt.subplots()

    ax1.set_xscale('log')
    ax1.set_xlabel('file size')
    ax1.set_xlim(xs[0], xs[-1])
    ax1.set_xticks(xs)
    ax1.set_xticklabels([naturalsize(x, binary=True) for x in xs], rotation=90)

    ax1.set_yscale('log')
    ax1.set_ylabel('re-encryption time')
    ax1.set_ylim(0, max(max(ys_aesaes), max(ys_twoaes)) * 1.2)

    ax1.errorbar(xs, ys_aesaes, yerr=std_aesaes, fmt='r^--', label='AES+AES')
    ax1.errorbar(xs, ys_twoaes, yerr=std_twoaes, fmt='b-',  label='TWOAES')
    ax1.fill_between(xs, ys_aesaes, ys_twoaes, where=ys_aesaes>ys_twoaes,
                     facecolor='g', alpha=.2, interpolate=True)
    ax1.fill_between(xs, ys_aesaes, ys_twoaes, where=ys_aesaes<ys_twoaes,
                     facecolor='r', alpha=.2, interpolate=True)

    plt.legend(loc='lower right')
    plt.tight_layout()


if __name__ == '__main__':
    print(pattern.format('SIZE', 'TIME AES+AES', 'TIME TWOAES'))

    print('\n' + "WITH AESNI".center(72, '='))
    results = [test(size, use_aesni=True) for size in sizes]
    plot(results)
    plt.savefig('figures/twoaes_with_aesni.png')
    plt.savefig('figures/twoaes_with_aesni.pdf')

    print('\n' + "WITHOUT AESNI".center(72, '='))
    results = [test(size, use_aesni=False) for size in sizes]
    plot(results)
    plt.savefig('figures/twoaes_without_aesni.png')
    plt.savefig('figures/twoaes_without_aesni.pdf')

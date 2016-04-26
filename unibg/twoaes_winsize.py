#!/usr/bin/env python

import matplotlib
matplotlib.use('Agg') # do not use X
from matplotlib import pyplot as plt

from numpy import std, mean, array

from Crypto.Cipher import AES, TWOAES
from functools import partial
from timeit import default_timer
from os import urandom

KiB = 2**10
MiB = 2**10 * KiB
GiB = 2**10 * MiB

## PARAMETERS ##
SIZE = 1*MiB
MINWIN = 1
MAXWIN = 10
RUNS = 10
OUT = 2

# bytegenerator = lambda size: urandom(size)
bytegenerator = lambda size: bytes(bytearray(size))

#OCCUPYRAM = bytegenerator(5 * GiB)

k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'

def remove_outliers(lst, outliers):
    return sorted(lst)[outliers:-outliers]

def repeat(fn, times, outliers):
    data = [fn() for _ in range(times)]
    data = remove_outliers(data, outliers)
    return mean(data), std(data)

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
    results = ( repeat(partial(single_test, size, recrypt_aesaes), RUNS, OUT)
              + repeat(partial(single_test, size, ta.encrypt), RUNS, OUT))
    print(pattern.format(window, results[0], results[2]))
    return results

def show(results, outfile='test.png'):
    xs = range(MINWIN, MAXWIN+1)
    ys_aesaes, std_aesaes, ys_twoaes, std_twoaes = map(array, zip(*results))
    ys_aesaes = array([mean(ys_aesaes) for _ in xrange(len(xs))])
    std_aesaes = array([mean(std_aesaes) for _ in xrange(len(xs))])

    plt.xlabel('TWOAES windows size (blocks)')
    plt.xlim(xs[0]-.1, xs[-1]+.1)
    plt.xticks(xs, xs)

    plt.ylabel('time (s)')
    plt.ylim(0, max(max(ys_aesaes), max(ys_twoaes)) * 1.2)

    plt.errorbar(xs, ys_aesaes, yerr=std_aesaes, fmt='r--', label='AES+AES')
    plt.errorbar(xs, ys_twoaes, yerr=std_twoaes, fmt='b-',  label='TWOAES')
    plt.fill_between(xs, ys_aesaes, ys_twoaes, where=ys_aesaes>ys_twoaes,
                     facecolor='g', alpha=.2, interpolate=True)
    plt.fill_between(xs, ys_aesaes, ys_twoaes, where=ys_aesaes<ys_twoaes,
                     facecolor='r', alpha=.2, interpolate=True)

    plt.legend()
    plt.savefig(outfile)

if __name__ == '__main__':
    #print('\n' + "WITH AESNI".center(72, '='))
    #results = [test(use_aesni=True, size=SIZE, window=window)
    #           for window in range(MINWIN, MAXWIN+1)]
    #show(results)

    print('\n' + "WITHOUT AESNI".center(72, '='))
    results = [test(use_aesni=False, size=SIZE, window=window)
               for window in range(MINWIN, MAXWIN+1)]
    show(results, 'without_aesni.pdf')

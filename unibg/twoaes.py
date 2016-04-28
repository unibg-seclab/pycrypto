#!/usr/bin/env python

import matplotlib
matplotlib.use('Agg') # do not use X
from matplotlib import pyplot as plt

from humanize.filesize import naturalsize
from Crypto.Cipher import AES, TWOAES
from functools import partial
from tempfile import NamedTemporaryFile
from argparse import ArgumentParser
from timeit import default_timer
import numpy as np
import os.path


bytegenerator = lambda size: bytes(bytearray(size))
pattern = '{:<22} | {:<22} | {:<22}'
k1 = '1234567890123456'
k2 = 'abcdefghijklmnop'


def remove_outliers(data, outliers):
    data.sort()
    return data if not outliers else data[outliers:-outliers]

def repeat(fn, times, outliers):
    data = [fn() for _ in range(times)]
    data = remove_outliers(data, outliers)
    return np.mean(data), np.std(data)

def test(size, use_aesni, runs, out, tempdir, rate=False):

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
        return (size / (2. ** 20)) / time if rate else time

    def recrypt_aesaes(cipher):
        plain = a1.decrypt(cipher)
        if tempdir:
            with NamedTemporaryFile(dir=tempdir) as temp:
                temp.write(plain)
                temp.flush()
                temp.seek(0)
                plain = temp.read()
        return a2.encrypt(plain)

    results = ( repeat(partial(single_test, size, recrypt_aesaes), runs, out)
              + repeat(partial(single_test, size, ta.encrypt), runs, out))
    print(pattern.format(naturalsize(size,binary=True), results[0], results[2]))
    return results

def suite(aesni, sizes, runs, out, outdir, tempdir=None, rate=False):
    name = 'with_aesni' if aesni else 'without_aesni'
    print('\n' + name.center(80, '='))
    print(pattern.format('SIZE', 'TIME AES+AES', 'TIME TWOAES'))
    results = [test(size, aesni, runs, out, tempdir, rate) for size in sizes]
    plot(results, rate)
    for ext in ('pdf', 'png'):
        plt.savefig(os.path.join(outdir, 'twoaes_%s.%s' % (name, ext)))

def plot(results, rate=False):
    xs = np.array(sizes)
    ys_aesaes, std_aesaes, ys_twoaes, std_twoaes = map(np.array, zip(*results))

    plt.xscale('log')
    plt.xlabel('file size')
    plt.xlim(xs[0], xs[-1])
    plt.xticks(xs, [naturalsize(x, binary=True) for x in xs], rotation=90)

    plt.ylabel('re-encryption ' + ('rate ($MB/s$)' if rate else 'time ($s$)'))
    plt.yscale('linear' if rate else 'log')

    plt.ylim(0, max(max(ys_aesaes), max(ys_twoaes)) * 1.2)

    plt.errorbar(xs, ys_aesaes, yerr=std_aesaes, fmt='r^--', label='AES+AES')
    plt.errorbar(xs, ys_twoaes, yerr=std_twoaes, fmt='b-',  label='TWOAES')

    plt.fill_between(xs, ys_aesaes, ys_twoaes, where=ys_aesaes>ys_twoaes,
                     facecolor='g', alpha=.2, interpolate=True)
    plt.fill_between(xs, ys_aesaes, ys_twoaes, where=ys_aesaes<ys_twoaes,
                     facecolor='r', alpha=.2, interpolate=True)

    plt.legend(loc='lower right')
    plt.tight_layout()


if __name__ == '__main__':
    parser = ArgumentParser(description='test TWOAES with different file sizes')
    parser.add_argument('--expmin', type=int, default=10, help='start from 2**expmin')
    parser.add_argument('--expmax', type=int, default=30, help='stop to  2**expmax')
    parser.add_argument('--runs', type=int, default=10, help='iterations per test')
    parser.add_argument('--outliers', type=int, default=2, help='tests to drop per tail')
    parser.add_argument('--outdir', default='.', help='output directory')
    parser.add_argument('--tempdir', help='where to place tempfile in AES+AES')
    parser.add_argument('--rate', action='store_true', help='plot MB/s')
    args = parser.parse_args()

    sizes = [2**exp for exp in range(args.expmin, args.expmax+1)]
    suite_args = {'sizes': sizes, 'runs': args.runs, 'out': args.outliers,
            'outdir': args.outdir, 'tempdir': args.tempdir, 'rate': args.rate}

    suite(True,  **suite_args)
    suite(False, **suite_args)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  pct-speedtest.py: Speed test for the Python Cryptography Toolkit
#
# Written in 2009 by Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

import time
import os
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import Crypto.Util.Counter
from Crypto.Util.number import bytes_to_long

# os.urandom() is less noisy when profiling, but it doesn't exist in Python < 2.4
try:
    urandom = os.urandom
except AttributeError:
    urandom = get_random_bytes

from Crypto.Random import random as pycrypto_random
import random as stdlib_random

class Benchmark:

    def __init__(self):
        self.__random_data = None

    def random_keys(self, bytes, n=10**5):
        """Return random keys of the specified number of bytes.

        If this function has been called before with the same number of bytes,
        cached keys are used instead of randomly generating new ones.
        """
        return self.random_blocks(bytes, n)

    def random_blocks(self, bytes_per_block, blocks):
        bytes = bytes_per_block * blocks
        data = self.random_data(bytes)
        retval = []
        for i in range(blocks):
            p = i * bytes_per_block
            retval.append(data[p:p+bytes_per_block])
        return retval

    def random_data(self, bytes):
        if self.__random_data is None:
            self.__random_data = self._random_bytes(bytes)
            return self.__random_data
        elif bytes == len(self.__random_data):
            return self.__random_data
        elif bytes < len(self.__random_data):
            return self.__random_data[:bytes]
        else:
            self.__random_data += self._random_bytes(bytes - len(self.__random_data))
            return self.__random_data

    def _random_bytes(self, b):
        return urandom(b)

    def announce_start(self, test_name):
        sys.stdout.write("%s: " % (test_name,))
        sys.stdout.flush()

    def announce_result(self, value, units):
        sys.stdout.write("%.2f %s\n" % (value, units))
        sys.stdout.flush()

    def test_random_module(self, module_name, module):
        self.announce_start("%s.choice" % (module_name,))
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        t0 = time.time()
        for i in range(5000):
            module.choice(alphabet)
        t = time.time()
        invocations_per_second = 5000 / (t - t0)
        self.announce_result(invocations_per_second, "invocations/sec")

    def test_pubkey_setup(self, pubkey_name, module, key_bytes):
        self.announce_start("%s pubkey setup" % (pubkey_name,))
        keys = self.random_keys(key_bytes)[:5]

        t0 = time.time()
        for k in keys:
            module.generate(key_bytes*8)
        t = time.time()
        pubkey_setups_per_second = len(keys) / (t - t0)
        self.announce_result(pubkey_setups_per_second, "Keys/sec")

    def test_key_setup(self, cipher_name, module, key_bytes, mode, **kwargs):
        self.announce_start("%s key setup" % (cipher_name,))

        # Generate random keys for use with the tests
        keys = self.random_keys(key_bytes, n=5000)

        if hasattr(module, "MODE_CCM") and mode==module.MODE_CCM:
            iv = b"\xAA"*8
        else:
            iv = b"\xAA"*module.block_size

        # Perform key setups
        if mode is None:
            t0 = time.time()
            for k in keys:
                module.new(k, **kwargs)
            t = time.time()
        else:
            t0 = time.time()

            if mode==module.MODE_CTR:
                for k in keys:
                    ctr = Crypto.Util.Counter.new(module.block_size*8,
                        initial_value=bytes_to_long(iv))
                    module.new(k, module.MODE_CTR, counter=ctr, **kwargs)
            else:
                for k in keys:
                    module.new(k, mode, iv, **kwargs)
            t = time.time()

        key_setups_per_second = len(keys) / (t - t0)
        self.announce_result(key_setups_per_second/1000, "kKeys/sec")

    def test_encryption(self, cipher_name, module, key_bytes, mode, **kwargs):
        self.announce_start("%s encryption" % (cipher_name,))

        # Generate random keys for use with the tests
        rand = self.random_data(key_bytes + module.block_size)
        key, iv = rand[:key_bytes], rand[key_bytes:]
        blocks = self.random_blocks(16384, 1000)
        if mode is None:
            cipher = module.new(key, **kwargs)
        elif mode == "CTR-BE":
            from Crypto.Util import Counter
            cipher = module.new(key, module.MODE_CTR, counter=Counter.new(module.block_size*8, little_endian=False), **kwargs)
        elif mode == "CTR-LE":
            from Crypto.Util import Counter
            cipher = module.new(key, module.MODE_CTR, counter=Counter.new(module.block_size*8, little_endian=True), **kwargs)
        elif hasattr(module, 'MODE_CCM') and mode==module.MODE_CCM:
            cipher = module.new(key, mode, iv[:8], msg_len=len(rand)*len(blocks), **kwargs)
        elif mode==module.MODE_CTR:
            ctr = Crypto.Util.Counter.new(module.block_size*8,
                    initial_value=bytes_to_long(iv),
                    allow_wraparound=True)
            cipher = module.new(key, module.MODE_CTR, counter=ctr, **kwargs)
        elif mode==module.MODE_ECB:
            cipher = module.new(key, module.MODE_ECB, **kwargs)
        else:
            cipher = module.new(key, mode, iv, **kwargs)

        # Perform encryption
        t0 = time.time()
        for b in blocks:
            cipher.encrypt(b)
        t = time.time()

        encryption_speed = (len(blocks) * len(blocks[0])) / (t - t0)
        self.announce_result(encryption_speed / 10**6, "MBps")

    def run(self):
        block_specs = [
            ("AES128", AES, 16),
#            ("AES192", AES, 24),
            ("AES256", AES, 32),
        ]

        for aesni in (False, True):
            print('=== WITH%s AESNI ===' % ('   ' if aesni else 'OUT'))

            for cipher_name, module, key_bytes in block_specs:
                self.test_encryption("%s-ECB" % (cipher_name,), module, key_bytes, module.MODE_ECB, use_aesni=aesni)
#               self.test_key_setup("%s-CBC" % (cipher_name,), module, key_bytes, module.MODE_CBC, use_aesni=aesni)
                self.test_encryption("%s-CBC" % (cipher_name,), module, key_bytes, module.MODE_CBC, use_aesni=aesni)
#                self.test_encryption("%s-OFB" % (cipher_name,), module, key_bytes, module.MODE_OFB, use_aesni=aesni)

#               self.test_key_setup("%s-CTR" % (cipher_name,), module, key_bytes, module.MODE_CTR, use_aesni=aesni)
                self.test_encryption("%s-CTR" % (cipher_name,), module, key_bytes, module.MODE_CTR, use_aesni=aesni)

if __name__ == '__main__':
    Benchmark().run()

# vim:set ts=4 sw=4 sts=4 expandtab:

# -*- coding: utf-8 -*-

__revision__ = "$Id$"

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Cipher import blockalgo
from Crypto.Cipher import _TWOAES
from Crypto.Util import cpuid

# Import _TWOAESNI. If TWOAES-NI is not available or _TWOAESNI has not been built, set
# _TWOAESNI to None.
try:
    if cpuid.have_aes_ni():
        from Crypto.Cipher import _TWOAESNI
    else:
        _TWOAESNI = None
except ImportError:
    _TWOAESNI = None

class TWOAESCipher (blockalgo.BlockAlgo):
    """TWOAES cipher object"""

    def __init__(self, key, *args, **kwargs):
        """Initialize an AES cipher object

        See also `new()` at the module level."""

        # Check if the use_aesni was specified.
        use_aesni = True
        if kwargs.has_key('use_aesni'):
            use_aesni = kwargs['use_aesni']
            del kwargs['use_aesni']

        # Use _TWOAESNI if the user requested TWOAES-NI and it's available
        if _TWOAESNI is not None and use_aesni:
            blockalgo.BlockAlgo.__init__(self, _TWOAESNI, key, *args, **kwargs)
        else:
            blockalgo.BlockAlgo.__init__(self, _TWOAES, key, *args, **kwargs)

def new(key, *args, **kwargs):
    """Create a new TWOAES cipher

    :Parameters:
      key : byte string
        The secret key to use in the symmetric cipher.
        It must be 32 (*AES-128*), 48 (*AES-192*), or 64 (*AES-256*) bytes long.

    :Keywords:
      mode : a *MODE_** constant
        The chaining mode to use for encryption or decryption.
        Default is `MODE_ECB`.
      use_aesni : boolean
        Use TWOAES-NI if available.

    :Return: an `TWOAESCipher` object
    """
    return TWOAESCipher(key, *args, **kwargs)

#: Electronic Code Book (ECB). See `blockalgo.MODE_ECB`.
MODE_ECB = 1
#: Size of a data block (in bytes)
block_size = 16
#: Size of a key (in bytes)
key_size = ( 16, 24, 32 )

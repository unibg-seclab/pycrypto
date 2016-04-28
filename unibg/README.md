# PyCrypto UniBG-Seclab Tests

## twoaes.py

The script compares the performances of *TWOAES* with *AES+AES* when the file
size changes.  It produces two graphs in the `figures` directory, one where
AES-NI is used and one where it is not. In the script you can configure the
parameters.

    usage: twoaes.py [-h] [--expmin EXPMIN] [--expmax EXPMAX] [--runs RUNS]
                     [--outliers OUTLIERS] [--outdir OUTDIR]

    test TWOAES with different file sizes

    optional arguments:
      -h, --help           show this help message and exit
      --expmin EXPMIN      start from 2**expmin
      --expmax EXPMAX      stop to 2**expmax
      --runs RUNS          iterations per test
      --outliers OUTLIERS  tests to drop per tail
      --outdir OUTDIR      output directory

## speedtest_small.py

Test `AES {128,256} {ECB,CBC,CTR}` encryption rate with and without AES-NI.

## py.test

`py.test` tests that:

    twoaes.encrypt == aes.encrypt(aes.decrypt)

## How to use cgroups

In order to cap memory and test the library in different scenarios you can use cgroups.

1. Create the cgroup

        cgcreate -a USER:USER -t USER:USER -g memory:YOURCGROUPNAME

2. Change the memory limit (in bytes) assigned to the cgroup (e.g. 2GB = 2147483648)

        echo '2147483648' > /sys/fs/cgroups/memory/YOURCGROUPNAME/memory.limit_in_bytes
        
    If you have the correct boot settings, you will also be able to change the file
    `memory.memsw.limit_in_bytes` to put constraints on swap usage.
    
3. Run what you want inside the cgroup:

        gcexec -g memory:YOURCGROUP python twoaes.py

## py.test

`py.test` tests that:

    twoaes.encrypt == aes.encrypt(aes.decrypt)

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

Test AES {128,256} {ECB,CBC,CTR} encryption rate with and without AES-NI.
The output is produced averaging 10 results.

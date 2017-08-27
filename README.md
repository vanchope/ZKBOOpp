# ZKBoo++


## Build C++ version

The work on a C++ extension to [ZKBoo](https://github.com/Sobuno/ZKBoo/) framework has been started in 2016, and the code was publicly released in August 2017.

Build and run in the release mode (-O2 compiler options)
```
    $ mkdir target
    $ cd target
    $ cmake ../
    $ make
```
   
Build and run in the debug mode (-g -O0 compiler options)
```
    $ mkdir target
    $ cd target
    $ cmake -DCMAKE_BUILD_TYPE=Debug ../
    $ make
```

## How to use the C++ version

First, you need to rewrite your function so that the framework could take care of the rest.  
Compare ./etc/sha3_original.c and ./inc/sha3.h source files.
Other examples include: sha256, trivium, xorshift128plus.

Test code for ZKBoo functions are in ./test directory.     
    

## Content of README file in the original C code (2016)

Zero Knowledge Prover and Verifier for Boolean Circuits. Currently available is a prover and verifier for SHA-1 and SHA-256. They on OpenSSL for doing commits and randomness generation and use OpenMP for parallelization.

When starting either prover, it will prompt for an input to hash. After entering the input, the proof will be generated as a file in the directory the program resides in. The file is named out<NUM_ROUNDS>.bin where <NUM_ROUNDS> is the number of rounds of the algorithm run (Set to 136 by defauly, but can be changed in shared.h. Likewise, the verifier will look for a file in its directory with the same naming syntax to verify.


## Credit
Contributions from Ivan Pryvalov <pryvalov (at) cs.uni-saarland.de>.

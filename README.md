
# SCL

The Small/simple C/C++ Library (SCL) provides various algorithms in a portable way, with little to no external dependencies.
The library is written in C++17 and uses the [MPL-2.0 License](http://mozilla.org/MPL/2.0) or [Public Domain](https://unlicense.org/) dedications.

The subdirectories are structured as follows:

* `mwc256/` contains a Public Domain 256 bit Multiply-With-Carry PRNG implementation for generic CPUs (ALU).
  With just a multiplication and add per round, this PRNG is as simple as it can get. On 64 bit machines it
  is probably the fastest single-data PRNG implementation, it passes PractRand at 32TB.
* `shishua/` contains a Public Domain Shishua PRNG implementation for generic CPUs (ALU), the SSE2/3 and AVX2 instruction set variants.
  This is currently the fastest known PRNG implementation, it passes PractRand at 32TB.
* `chacha/` contains a Public Domain ChaCha block cipher implementation for generic CPUs (ALU), the SSE2/3 and AVX2 instruction set variants.
  This is probably the fastest CSPRNG implementation, it passes PractRand at 32TB.
* `keccak/` contains a Public Domain Keccak PRNG implementation for generic CPUs (ALU) and system entropy gathering code according to the
  "Welcome to the Entropics: Boot-Time Entropy in Embedded Devices" paper.
  Using Keccak allows for a 1600 bit CSPRNG entropy pool, it passes PractRand at 32TB.

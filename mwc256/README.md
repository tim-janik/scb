
# Mwc256 C++ Implementation

The header file `mwc256.hh` contains a 256 bit Multiply-With-Carry PRNG
implementation for generic CPUs (ALU).

This is a Marsaglia multiply-with-carry generator with period
approximately 2^255. It is faster than a scrambled linear
generator, as its only 128-bit operations are a multiplication and sum;
it is an excellent generator based on congruential arithmetic.

Like all MWC generators, it simulates a multiplicative LCG with prime
modulus `M` and multiplier given by the inverse of 2^64 modulo `M`.
The modulus has a particular form, which creates some theoretical issues,
but at this size a generator of this kind passes all known statistical tests.

While very simple in construction, it is among the fastest single-data PRNG
implementations, and passes PractRand at 32TB due to the large state size.

The source code is dedicated to the Public Domain under the [Unlicense](https://unlicense.org/UNLICENSE).

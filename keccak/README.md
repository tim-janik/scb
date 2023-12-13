
# Keccak PRNG Implementation

The header file `keccak.hh` contains a Keccak sponge construction implementation for generic CPUs (ALU)
in the `class scl::Keccak::class KeccakRng`. The implementation is are based on the original
[Specification of Keccak](https://keccak.team/files/Keccak-reference-3.0.pdf) from 2011.
The header file can be used on its own for cryptographic hashing via Keccak.

However, the method `KeccakRng::auto_seed()` is implemented in the source file `keccak.cc`, it allows
the use of a `KeccakRng` sponge as an entropy pool for cryptographically secure random seeds for other PRNGs.

The code for `KeccakRng::auto_seed()` gathers entropy from various system sources such as
`/dev/urandom`, `getrandom(2)`, `getentropy(3)`, `arc4random(3bsd)`, `RDTSC`, `RDRAND` and high precision clocks.
The code performs detailed timing measurements to improve the quality of the gathered entropy, according to this
paper from 2013 that deals with entropy gathering in embedded systems at boot time:
[Welcome to the Entropics: Boot-Time Entropy in Embedded Devices](https://cseweb.ucsd.edu/~swanso/).
The entropy pool uses `class KeccakRng` with 1600 bits of state, of which 576 are hidden bits,
to guarantee cryptographically secure mixing.

The source file `main.cc` contains random number generation examples, benchmarks and unit test code based
on the Keccak test vectors.

The source code is dedicated to the Public Domain under the [Unlicense](https://unlicense.org/UNLICENSE).




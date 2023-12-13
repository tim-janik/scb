
# Shishua C++ Implementation

The header file `shishua.hh` contains a Shishua PRNG
implementation for generic CPUs (ALU), and it includes SSE2/3
and AVX2 instruction set veriants.
The implementations are all based on Public Domain code from
[Thaddée Tyl](https://github.com/espadrine): https://github.com/espadrine/shishua
It passes PractRand for at least 32TB.

The source code is dedicated to the Public Domain under the [Unlicense](https://unlicense.org/UNLICENSE).

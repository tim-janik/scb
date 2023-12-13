// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#include "shishua.hh"

#include <vector>
#include <cstdio>

static void
shishua_tests (const std::array<uint64_t, 4> &seeds)
{
  // check bit toggle stats
  const unsigned N = 12 * 1024 * 1024;
  std::vector<uint64_t> buffer (N, 0);
  Shishua::Scalar::prng_state orig_state{};
  Shishua::Scalar::prng_init (&orig_state, seeds.data());
  Shishua::Scalar::prng_gen (&orig_state, (uint8_t*) buffer.data(), sizeof (buffer[0]) * buffer.size());
  uint bits[64] = { 0, };
  uint64_t last = 0;
  for (size_t i = 0; i < buffer.size(); i++) {
    const uint64_t c = buffer[i];
    for (uint j = 0; j <= 63; j++) {
      const uint64_t b = uint64_t (1) << j;
      if ((c&b) != (last&b))
        bits[j]++;
    }
    last = c;
  }
  bool verbose = false;
  if (verbose)
    printf ("Toggles, N=%u\n", N);
  for (uint j = 0; j <= 63; j++) {
    const double bit_perc = bits[j] * 100.0 / N;
    if (verbose)
      printf ("%2u) %u => %.1f%%\n", j, bits[j], bit_perc);
    assert (bit_perc >= 49 && bit_perc <= 51);
  }
  printf ("  OK    bit toggles\n");
}

static void
shishua_stream_tests (const std::array<uint64_t, 4> &seeds)
{
  const unsigned N = 12 * 1024 * 1024;
  std::vector<uint8_t> buffer (N, 0);
  Shishua::Scalar::prng_state orig_state{};
  Shishua::Scalar::prng_init (&orig_state, seeds.data());
  Shishua::Scalar::prng_gen (&orig_state, buffer.data(), buffer.size());
  const std::vector<uint8_t> orig (buffer);
  if (1 /*sse2*/) {
    buffer.assign (N, 0);
    assert (orig != buffer);
    Shishua::Sse2::prng_state sse2_state{};
    Shishua::Sse2::prng_init (&sse2_state, seeds.data());
    Shishua::Sse2::prng_gen (&sse2_state, buffer.data(), buffer.size());
    assert (orig == buffer);
    printf ("  OK    (SSE3 validation)\n");
  }
  if (1 /*avx2*/) {
    buffer.assign (N, 0);
    assert (orig != buffer);
    Shishua::Avx2::prng_state avx2_state{};
    Shishua::Avx2::prng_init (&avx2_state, seeds.data());
    Shishua::Avx2::prng_gen (&avx2_state, buffer.data(), buffer.size());
    assert (orig == buffer);
    printf ("  OK    (AVX2 validation)\n");
  }
}

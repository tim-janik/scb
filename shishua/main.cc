// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#include <array>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <chrono>               // std::chrono
#include <sys/random.h>

#include "shishua.cc"

/// Return the current time as uint64 in nanoseconds.
extern inline uint64_t timestamp_nsecs() { return std::chrono::steady_clock::now().time_since_epoch().count(); }

static size_t
generate_bytes (const std::array<uint64_t, 4> &seeds, const uint64_t nbytes, unsigned kind, FILE *fout)
{
  const unsigned N = std::min (nbytes, 64 * 1024 * 1024ul);
  std::vector<uint8_t> buffer (N, 0);
  uint64_t nb;
  if (kind >= 4) { // Avx2
    Shishua::Avx2::prng_state state{};
    Shishua::Avx2::prng_init (&state, seeds.data());
    for (nb = 0; nb < nbytes; nb += buffer.size()) {
      Shishua::Avx2::prng_gen (&state, buffer.data(), buffer.size());
      if (fout)
        fwrite (buffer.data(), buffer.size(), 1, fout);
    }
  } else if (kind >= 2) { // Sse2
    Shishua::Sse2::prng_state state{};
    Shishua::Sse2::prng_init (&state, seeds.data());
    for (nb = 0; nb < nbytes; nb += buffer.size()) {
      Shishua::Sse2::prng_gen (&state, buffer.data(), buffer.size());
      if (fout)
        fwrite (buffer.data(), buffer.size(), 1, fout);
    }
  } else { // (kind >= 1) // scalar
    Shishua::Scalar::prng_state state{};
    Shishua::Scalar::prng_init (&state, seeds.data());
    for (nb = 0; nb < nbytes; nb += buffer.size()) {
      Shishua::Scalar::prng_gen (&state, buffer.data(), buffer.size());
      if (fout)
        fwrite (buffer.data(), buffer.size(), 1, fout);
    }
  }
  return nb;
}

int
main (int argc, const char *argv[])
{
  std::array<uint64_t, 4> seeds{};
  auto const dummy1 [[maybe_unused]] = getrandom (seeds.data(), seeds.size() * sizeof (seeds[0]), GRND_NONBLOCK);
  seeds[0] = timestamp_nsecs(); // "nonce"

  double streamlen = 0;
  unsigned kind = ~0; // ALU
  for (int i = 1; i < argc; i++)
    if (0 == strcasecmp (argv[i], "--check")) {
      shishua_tests (seeds);
      shishua_stream_tests (seeds);
      return 0;
    } else if (0 == strcasecmp (argv[i], "--sse"))
      kind = 2; // SSE
    else if (0 == strcasecmp (argv[i], "--alu"))
      kind = 1; // ALU
    else if (0 == strcasecmp (argv[i], "--avx"))
      kind = 4; // AVX2
    else if (0 == strcasecmp (argv[i], "--seed") && i+1 < argc) {
      seeds = std::array<uint64_t, 4>{};
      seeds[0] = strtoull (argv[++i], nullptr, 0);
    } else if (0 == strcmp (argv[i], "--bench")) {
      const char *arg = i+1 < argc ? argv[++i] : "1G";
      char *u = nullptr;
      streamlen = strtoull (arg, &u, 0);
      if (u && u[0])
        switch (u[0])
          {
          case 'K':     streamlen *= 1024;                              break;
          case 'M':     streamlen *= 1024 * 1024;                       break;
          case 'G':     streamlen *= 1024 * 1024 * 1024;                break;
          case 'T':     streamlen *= 1024 * 1024 * 1024 * 1024ull;      break;
          }
    }

  if (streamlen > 0) {
    streamlen = std::min (streamlen, 0x1p+63); // 2^63 = 9223372036854775808
    dprintf (2, "BENCH: %zu Bytes\n", size_t (streamlen));
    auto t1 = timestamp_nsecs();
    const size_t total = generate_bytes (seeds, uint64_t (streamlen), kind, nullptr);
    auto t2 = timestamp_nsecs();
    dprintf (2, " %.3f msecs (%zu Bytes), %f GB/sec\n", (t2 - t1) / 1000000.0, total, total * (1000000000.0 / (1024*1024*1024)) / (t2 - t1));
  }
  else
    generate_bytes (seeds, uint64_t (0x1p+63), kind, stdout);

  return 0;
}
// clang++ -std=gnu++17 -Wall -march=native -O3 main.cc -o shishua && ./shishua | dieharder -a -g 200

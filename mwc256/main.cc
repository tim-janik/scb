// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#include <vector>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <chrono>               // std::chrono
#include <sys/random.h>

#include "mwc256.hh"

/// Return the current time as uint64 in nanoseconds.
extern inline uint64_t timestamp_nsecs() { return std::chrono::steady_clock::now().time_since_epoch().count(); }

static size_t
generate_bytes (const std::array<uint64_t, 4> &seeds, const uint64_t nbytes, FILE *fout)
{
  using namespace scl;
  const unsigned N = 1024;
  alignas (64) uint64_t buffer[N];
  alignas (64) Mwc256 prng { seeds };
  uint64_t nb;
  for (nb = 0; nb < nbytes; nb += sizeof (buffer)) {
    for (uint i = 0; i < sizeof (buffer) / sizeof (buffer[0]); i++)
      buffer[i] = prng.next();
    fwrite (buffer, sizeof (buffer), 1, fout);
  }
  return nb;
}

static void
mwc256_tests()
{
  using namespace scl;
  Mwc256 a, b = a;
  assert (a.next() == b.next());
  assert (a.next() == b.next());
  assert (a.next() == b.next());
  assert (a.next() == b.next());
  Mwc256 c = a;
  c.jump_128();
  Mwc256 d = a;
  d.jump_192();
  assert (c.next() != d.next());
  assert (c.next() != d.next());
  assert (c.next() != d.next());
  assert (c.next() != d.next());
  c.jump_192();
  d.jump_128();
  assert (c.next() == d.next());
  assert (c.next() == d.next());
  assert (c.next() == d.next());
  assert (c.next() == d.next());
  a.jump_128();
  a.jump_192();
  assert (a.next() != a.next());
  assert (a.next() != a.next());
  assert (a.next() != a.next());
  assert (a.next() != a.next());
  assert (a.next() == c.next()); d.next();
  assert (a.next() == d.next()); c.next();
  printf ("  OK    Mwc256State next and jumps\n");
}


int
main (int argc, const char *argv[])
{
  std::array<uint64_t, 4> seeds{};
  auto const dummy1 [[maybe_unused]] = getrandom (seeds.data(), seeds.size() * sizeof (seeds[0]), GRND_NONBLOCK);
  seeds[0] = timestamp_nsecs(); // "nonce"

  double streamlen = 0;
  for (int i = 1; i < argc; i++)
    if (0 == strcasecmp (argv[i], "--check")) {
      mwc256_tests();
      return 0;
    } else if (0 == strcasecmp (argv[i], "--alu"))
      /**/; // ALU
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
    fclose (stdout); // not needed for benchmarks
    const size_t total = generate_bytes (seeds, uint64_t (streamlen), stdout);
    auto t2 = timestamp_nsecs();
    dprintf (2, " %.3f msecs (%zu Bytes), %f GB/sec\n", (t2 - t1) / 1000000.0, total, total * (1000000000.0 / (1024*1024*1024)) / (t2 - t1));
  }
  else
    generate_bytes (seeds, uint64_t (0x1p+63), stdout);

  return 0;
}
// clang++ -std=gnu++17 -Wall -march=native -O3 main.cc -o mwc256 && ./mwc256 | dieharder -a -g 200

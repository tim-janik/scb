// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#include <array>
#include <cstdint>
#include <cassert>
#include <cstring>

#include "keccak.hh"
#include "keccak.cc"

/// Return the current time as uint64 in nanoseconds.
extern inline uint64_t timestamp_nsecs() { return std::chrono::steady_clock::now().time_since_epoch().count(); }

static std::vector<uint8_t>
parse_hex (const char *hex)
{
  const unsigned l = strlen (hex);
  std::vector<uint8_t> bytes (l / 2, 0);
  for (size_t i = 0; i < bytes.size(); i++) {
    const char b[3] = { hex[i*2], hex[i*2+1], 0 };
    bytes[i] = strtoul (b, nullptr, 16);
  }
  return bytes;
}

static void
keccak_tests ()
{
  using namespace scl::Keccak;
  KeccakRng kr;
  const uint8_t tv[2][16] = { { 0x52, 0XA6, 0x08, 0XAB, 0x21, 0XCC, 0XDD, 0X8A, 0x44, 0x57, 0XA5, 0X7E, 0XDE, 0x78, 0x21, 0x76 },
                              { 0x73, 0XBF, 0XBF, 0x05, 0X8D, 0x08, 0x92, 0x50, 0x11, 0X5E, 0x86, 0x80, 0x82, 0XE0, 0XAE, 0X0F } };
  kr.reset();
  kr.update (tv[0], 16);
  for (unsigned i = 0; i < sizeof (tv[1]) / sizeof (tv[1][0]); i += 8) {
    const uint64_t r = kr.next();
    for (unsigned j = 0; j < 8; j++)
      // dprintf (2, "%2u) %02x == %02x\n", i+j, tv[1][i+j], uint8_t (r >> (j*8))),
      assert (tv[1][i+j] == uint8_t (r >> (j*8)));
  }
  printf ("  OK    msg-16\n");

#include "testvectors.c"       // const struct { const char *hexin, *hexout; } keccak_tests[] = {...};
  unsigned t;
  for (t = 0; t < sizeof (keccak_tests) / sizeof (keccak_tests[0]); t++) {
    const auto vin = parse_hex (keccak_tests[t].hexin), vout = parse_hex (keccak_tests[t].hexout);
    kr.reset();
    if (0 == vin.size() % 8)
      kr.update64 ((const uint64_t*) vin.data(), vin.size() / 8);
    else
      kr.update (vin.data(), vin.size());
    std::vector<uint8_t> r (vout.size(), 0);
    kr.generate (r.begin(), r.end());
    assert (vout == r);
    // printf ("  OK    msg-%d, ilen=%zd, olen=%zd\n", t, vin.size(), vout.size());
  }
  printf ("  OK    %u test vectors\n", t);

  KeccakRng k1, k2;
  assert (k1 == k2);
  assert (k1.next() == k2.next());
  printf ("  OK    KeccakRng equality\n");
  assert (k1 == k2);
  k1.auto_seed();
  assert (k1 != k2);
  k2.auto_seed();
  assert (k1 != k2);
  assert (k1.next() != k2.next());
  printf ("  OK    KeccakRng auto_seed()\n");
}

static uint64_t
generate_bytes (scl::Keccak::KeccakRng &kr, const uint64_t nbytes, FILE *fout)
{
  const unsigned N = std::min (nbytes, 4 * 1024 * 1024ul);
  std::vector<uint8_t> buffer (N, 0);
  uint64_t nb;
  for (nb = 0; nb < nbytes; nb += buffer.size()) {
    kr.generate (begin (buffer), end (buffer));
    if (fout)
      fwrite (buffer.data(), buffer.size(), 1, fout);
  }
  return nb;
}

int
main (int argc, const char *argv[])
{
  uint64_t custom_seed = 0;
  bool auto_seed = true;

  double streamlen = 0;
  for (int i = 1; i < argc; i++)
    if (0 == strcasecmp (argv[i], "--check")) {
      keccak_tests();
      return 0;
    } else if (0 == strcasecmp (argv[i], "--seed") && i+1 < argc) {
      custom_seed = strtoull (argv[++i], nullptr, 0);
      auto_seed = false;
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

  scl::Keccak::KeccakRng rg;
  if (auto_seed)
    rg.auto_seed();
  else
    rg.seed (custom_seed);

  if (streamlen > 0) {
    streamlen = std::min (streamlen, 0x1p+63); // 2^63 = 9223372036854775808
    dprintf (2, "BENCH: %zu Bytes\n", size_t (streamlen));
    auto t1 = timestamp_nsecs();
    const size_t total = generate_bytes (rg, uint64_t (streamlen), nullptr);
    auto t2 = timestamp_nsecs();
    dprintf (2, " %.3f msecs (%zu Bytes), %f GB/sec\n", (t2 - t1) / 1000000.0, total, total * (1000000000.0 / (1024*1024*1024)) / (t2 - t1));
  }
  else
    generate_bytes (rg, ~uint64_t (0), stdout);

  return 0;
}
// clang++ -std=gnu++17 -Wall -march=native -O3 main.cc -o keccak && ./keccak | dieharder -a -g 200

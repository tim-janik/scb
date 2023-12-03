// Licensed CC0 Public Domain

#include <chrono>               // std::chrono
#include <sys/random.h>

#include "chacha.cc"

/// Return the current time as uint64 in nanoseconds.
extern inline uint64_t timestamp_nsecs() { return std::chrono::steady_clock::now().time_since_epoch().count(); }

static uint64_t
generate_bytes (uint64_t nonce, const std::array<uint8_t, 32> &key, const uint64_t nbytes, const unsigned rounds, unsigned kind, FILE *fout)
{
  const unsigned N = std::min (nbytes, 64 * 1024 * 1024ul);
  std::vector<uint8_t> buffer (N, 0);
  std::array<uint32_t, 16> state;
  ChaCha::key_setup (state, 256, key, nonce);
  size_t total;
  for (total = 0; total < nbytes; /**/) {
    uint8_t *start = buffer.data(), *last = start + N - 64 * ChaCha::avx_blocks;
    while (start < last)
      start += ChaCha::generate_blocks (state, N, nullptr, start, rounds, kind);
    if (fout)
      fwrite (buffer.data(), start - buffer.data(), 1, fout);
    total += start - buffer.data();
  }
  return total;
}

int
main (int argc, const char *argv[])
{
  // ChaCha8 should be fine for CSPRNG purposes: https://github.com/rust-random/rand/issues/932
  std::array<uint8_t, 32> key{};
  auto const dummy1 [[maybe_unused]] = getrandom (key.data(), key.size(), GRND_NONBLOCK);
  uint64_t nonce = timestamp_nsecs();

  double streamlen = 0;
  unsigned kind = ~0; // ALU
  for (int i = 1; i < argc; i++)
    if (0 == strcasecmp (argv[i], "--check")) {
      chacha_tests();
      chacha_stream_tests (nonce, key);
      return 0;
    } else if (0 == strcasecmp (argv[i], "--sse"))
      kind = 2; // SSE
    else if (0 == strcasecmp (argv[i], "--alu"))
      kind = 1; // ALU
    else if (0 == strcasecmp (argv[i], "--avx"))
      kind = 4; // AVX2
    else if (0 == strcasecmp (argv[i], "--seed") && i+1 < argc) {
      nonce = strtoull (argv[++i], nullptr, 0);
      key = std::array<uint8_t, 32>{};
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
    const size_t total = generate_bytes (nonce, key, uint64_t (streamlen), 8, kind, nullptr);
    auto t2 = timestamp_nsecs();
    dprintf (2, " %.3f msecs (%zu Bytes), %f GB/sec\n", (t2 - t1) / 1000000.0, total, total * (1000000000.0 / (1024*1024*1024)) / (t2 - t1));
  }
  else
    generate_bytes (nonce, key, ~uint64_t (0), 8, kind, stdout);

  return 0;
}
// clang++ -std=gnu++17 -Wall -march=native -O3 main.cc -o chacha && ./chacha | dieharder -a -g 200

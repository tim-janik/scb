// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

// #include "keccak.hh"
#include <unistd.h>             // getentropy
#include <sys/random.h>         // getrandom
#include <stdlib.h>             // arc4random
#include <sys/time.h>           // gettimeofday
#include <time.h>               // clock_gettime
#include <random>               // std::random_device
#include <chrono>               // std::chrono
#include <sys/resource.h>       // getrusage
#if defined (__i386__) || defined (__x86_64__)
#  include <x86gprintrin.h>     // __rdtsc
#endif

namespace scl::Keccak {

static void
seed_addtime (KeccakRng &pool)
{
  // Gather entropy from execution time fluctuations, see:
  // "Welcome to the Entropics: Boot-Time Entropy in Embedded Devices",
  // https://cseweb.ucsd.edu/~swanson/papers/Oakland2013EarlyEntropy.pdf
  std::array<uint64_t, 25> xw{};
#if defined (__i386__) || defined (__x86_64__)
  xw[0] = __rdtsc();
#endif
  xw[1] = std::chrono::steady_clock::now().time_since_epoch().count();
  xw[2] = std::chrono::system_clock::now().time_since_epoch().count();
  xw[3] = clock();
  struct timeval timeval{};
  gettimeofday (&timeval, nullptr);
  xw[4] = timeval.tv_sec;
  xw[5] = timeval.tv_usec;
  struct timespec ts{};
  clock_gettime (CLOCK_REALTIME, &ts);
  xw[6] = ts.tv_sec;
  xw[7] = ts.tv_nsec;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  xw[8] = ts.tv_sec;
  xw[9] = ts.tv_nsec;
  clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &ts);
  xw[10] = ts.tv_sec;
  xw[11] = ts.tv_nsec;
#if defined (__i386__) || defined (__x86_64__)
  xw[12] = __rdtsc();
#endif
  pool.update64 (xw.data(), xw.size(), false);
}

static bool
seed_addfile (KeccakRng &pool, const char *filename, const size_t maxbytes = 200)
{
  FILE *file = fopen (filename, "r");
  if (file)
    {
      std::array<uint8_t, 200> xs{};
      const size_t l = fread (xs.data(), 1, maxbytes < xs.size() ? maxbytes : xs.size(), file);
      fclose (file);
      pool.update (xs.data(), xs.size(), false);
      seed_addtime (pool); // execution timing
      return l > 0;
    }
  return false;
}

static void
random_entropy (KeccakRng &pool)
{
  seed_addtime (pool); // execution timing

  std::array<uint64_t, 25> xw{}; // engouh state to feed Keccak1600

  // Peek at C++ random_device
  if (true) {
    // std::random_device easily throws for non-default sources
    // also some impls reopen devices for every 32bit operator() call.
    std::random_device cpprd;
    static_assert (sizeof (cpprd()) == 4);
    xw[0] = cpprd() + (uint64_t (cpprd()) << 32);
    pool.update64 (xw.data(), xw.size(), false);
    seed_addtime (pool); // execution timing
  }

  // HW counter if any
#if defined(__RDRND__)
  xw = std::array<uint64_t, 25>{};
  for (size_t i = 0; i < xw.size(); i++) {
    unsigned long long ull = 0;
    __builtin_ia32_rdrand64_step (&ull);
    xw[i] = ull;
  }
  pool.update64 (xw.data(), xw.size(), false);
  seed_addtime (pool); // execution timing
#endif

  xw = std::array<uint64_t, 25>{};
  xw[0] = time (nullptr);
  xw[1] = getpid();
  xw[2] = gettid();
  xw[10] = std::ptrdiff_t (&xw[23]);            // stack/thread location
  xw[11] = std::ptrdiff_t (&pool);              // instance location
  xw[12] = std::ptrdiff_t (random_entropy);     // code segment
  xw[13] = std::ptrdiff_t (&malloc);            // libc segment
  pool.update64 (xw.data(), xw.size(), false);
  seed_addtime (pool); // execution timing

  // read from frequently changing files
  seed_addfile (pool, "/dev/urandom");
  seed_addfile (pool, "/proc/stat");
  seed_addfile (pool, "/proc/uptime");
  seed_addfile (pool, "/proc/loadavg");
  seed_addfile (pool, "/proc/softirqs");
  seed_addfile (pool, "/proc/schedstat");
  seed_addfile (pool, "/proc/diskstats");
  seed_addfile (pool, "/proc/interrupts");
  seed_addfile (pool, "/proc/sys/kernel/random/uuid");
  // seed_addfile (pool, "/proc/vmstat");
  // seed_addfile (pool, "/proc/meminfo");
  // seed_addfile (pool, "/proc/zoneinfo");

  std::array<uint8_t, 200> xs{}; // engouh state to feed Keccak1600
#if defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
  auto const dummy1 [[maybe_unused]] = getrandom (xs.data(), xs.size(), GRND_NONBLOCK);
  pool.update (xs.data(), xs.size(), false);
#endif

#if defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
  auto const dummy2 [[maybe_unused]] = getentropy (xs.data(), xs.size());
  pool.update (xs.data(), xs.size(), false);
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
  arc4random_buf (xs.data(), xs.size());
  pool.update (xs.data(), xs.size(), false);
#endif

  // process statistics
  union {
    uint8_t         data[25 * 8];
    struct {
      struct rusage rusage;     // 144 bytes
    } stats;
    static_assert (sizeof (stats) <= sizeof (data));
  } u = { { 0 }, };
  getrusage (RUSAGE_SELF, &u.stats.rusage);
  pool.update (u.data, sizeof (u.data), false);

  seed_addtime (pool); // execution timing
}

/** Tap into various OS and runtime sources of entropy.
 * Gathering entropy from system and runtime sources may take a few microseconds
 * or milliseconds so it is recommended to call this once and use the KeccakRng
 * to reseed other PRNGs.
 */
void
KeccakRng::auto_seed()
{
  reset();
  random_entropy (*this);
  update (nullptr, 0, false); // finalize
  keccak1600_permute (state_.A, 37);
}

} // scl::Keccak

// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#ifndef __MWC256_HH__
#define __MWC256_HH__

#include <cstdint>
#include <array>

namespace scl {

/** Mwc256 - 256 Bit Multiply-With-Carry PRNG.
 *
 * This is a Marsaglia multiply-with-carry generator with period
 * approximately 2^255. It is faster than a scrambled linear
 * generator, as its only 128-bit operations are a multiplication and sum;
 * it is an excellent generator based on congruential arithmetic.
 *
 * Like all MWC generators, it simulates a multiplicative LCG with prime
 * modulus m = 0xff377e26f82da749ffffffffffffffffffffffffffffffffffffffffffffffff
 * and multiplier given by the inverse of 2^64 modulo m. The modulus has a
 * particular form, which creates some theoretical issues, but at this
 * size a generator of this kind passes all known statistical tests.
 */
class Mwc256 {
  alignas (64) std::array<uint64_t,4> state_ = { 0, 0, 0, 0 };
  static constexpr uint64_t MWC256_A3 = 0xff377e26f82da74a;
  void state_mul256 (const std::array<uint64_t,5> &b);
public:
  /// Construct an instance and call `seed (s)`.
  explicit Mwc256 (const std::array<uint64_t,4> &s) { seed (s); }
  /// Construct an instance with a fixed seed, dynamic seeding is recommended.
  explicit Mwc256 () { seed(); }
  /// Generate a 64 bit random integer using one multiplication and one addition.
  uint64_t
  next()
  {
    // Based on Public Domain code by Sebastiano Vigna, https://prng.di.unimi.it/
    const __uint128_t t = MWC256_A3 * __uint128_t (state_[0]) + state_[3];
    state_[0] = state_[1];
    state_[1] = state_[2];
    state_[2] = t;
    state_[3] = t >> 64;
    return state_[2];
  }
  /// Initialize and mix initial state, ensure the state is within required bounds.
  void
  seed (uint64_t s0 = 0x626E33B8D04B4331, uint64_t s1 = 0x85839D6EFFBD7DC6, uint64_t s2 = 0x01886F0928403002, uint64_t s3 = 0xF86C6A11D0C18E95)
  {
    // The state must be initialized so that 0 < state_[3] < MWC256_A3-1
    state_[0] = s0;
    state_[1] = s1;
    state_[2] = s2;
    state_[3] = s3 > 0 && s3 < MWC256_A3-1 ? s3 : s3 ^ 0xFEC507705E4AE6E5;
    // Initial shuffling so we do not generate seed as output
    for (size_t i = 0; i < 17; i++)
      next();
  }
  void
  seed (const std::array<uint64_t,4> &s)
  {
    seed (s[0], s[1], s[2], s[3]);
  }
  /// Advance the state by 2^128 calls to next(), offsets into up to 2^128 non-overlapping subsequences.
  void
  jump_128()
  {
    static constexpr std::array<uint64_t,5> jump128 = { 0x49ffebb8aed35da, 0x8aeb90fc17d34f8c, 0x3e78ff9958b436d9, 0x377fc42deaad8b46, 0 };
    state_mul256 (jump128);
  }
  /// Advance the state by 2^192 calls to next(), offsets into up to 2^64 non-overlapping subsequences.
  void
  jump_192()
  {
    static constexpr std::array<uint64_t,5> jump192 = { 0x7cbd7641a0db932f, 0x1eafd94d7d3ac65c, 0xf4fc97e3b80db1b, 0x630e9c671e238c8a, 0 };
    state_mul256 (jump192);
  }
};

/// Internal multi-precision multiplication for jumps.
inline void
Mwc256::state_mul256 (const std::array<uint64_t,5> &b)
{
  static constexpr int MPQWORDS = 5;
  using MpNum = std::array<uint64_t,MPQWORDS>;
  MpNum a = { state_[0], state_[1], state_[2], state_[3], 0 };
  static constexpr MpNum mwc256_mod = { 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, MWC256_A3 - 1, 0 };
  const auto mpc_cmp = [] (const MpNum &a, const MpNum &b) {
    for (int i = MPQWORDS; i-- != 0; ) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  };
  const auto mpc_bsub = [] (MpNum &a, const MpNum &b) {
    int borrow = 0;     // Assumes a >= b
    for (int i = 0; i < MPQWORDS; i++)
      {
        __int128_t d = __int128_t (a[i]) - __int128_t (b[i]) - __int128_t (borrow);
        borrow = d < 0;
        a[i] = __int128_t (UINT64_MAX) + 1 + d;
      }
  };
  const auto mpc_rem = [&] (MpNum &a, const MpNum &m) {
    for (;;)
      {
        if (mpc_cmp (a, m) < 0)
          return;
        mpc_bsub (a, m);
      }
  };
  const auto mpc_add = [&] (MpNum &a, const MpNum &b, const MpNum &m) {
    int carry = 0;
    for (int i = 0; i < MPQWORDS; i++)
      {
        __uint128_t s = __uint128_t (a[i]) + __uint128_t (b[i]) + __uint128_t (carry);
        carry = s > UINT64_MAX;
        a[i] = s;
      }
    mpc_rem (a, m);
  };
  MpNum r = {}, t = a;
  int d;
  for (d = MPQWORDS; d-- != 0 && b[d] == 0;)
    ;
  d++;
  for (int i = 0; i < d * 64; i++)
    {
      if (b[i >> 6] & (UINT64_C (1) << (i & 63)))
        mpc_add (r, t, mwc256_mod);
      mpc_add (t, t, mwc256_mod);
    }
  state_[0] = r[0];
  state_[1] = r[1];
  state_[2] = r[2];
  state_[3] = r[3];
}

} // scl

#endif // __MWC256_HH__

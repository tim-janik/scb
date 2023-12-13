// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE
#ifndef __KECCAK_HH__
#define __KECCAK_HH__

#include <limits>

namespace scl::Keccak {

extern inline void keccak1600_permute (std::array<uint64_t,25>&, uint32_t);

/** KeccakRng - A KeccakF1600 based pseudo-random number generator.
 * The permutation steps are derived from the Keccak specification @cite Keccak11 .
 * For further details about this implementation, see also: http://testbit.eu/
 * This class is primarily used to implement more fine tuned generators, such as:
 * KeccakCryptoRng, KeccakGoodRng and KeccakFastRng.
 */
class KeccakRng {
  const uint16_t          bit_rate_, n_rounds_;
  uint32_t                opos_ = 0;
  union {
    std::array<uint64_t,25> A;
    std::array<uint8_t,200> B;
  }                       state_;
  uint32_t                ipos_ = 0;
  void                    permute1600 () { keccak1600_permute (state_.A, n_rounds_);  opos_ = 0; }
public:
  /*copy*/            KeccakRng   (const KeccakRng&) = default;
  /// Integral type of the KeccakRng generator results.
  typedef uint64_t    result_type;
  /// Amount of 64 bit random numbers per generated block.
  inline size_t       n_nums      () const      { return bit_rate_ / 64; }
  /// Amount of bits used to store hidden random number generator state.
  inline size_t       bit_capacity() const      { return 1600 - bit_rate_; }
  /*dtor*/           ~KeccakRng   ()            { state_.A = std::array<uint64_t,25>{}; opos_ = 0; }
  /// Create an unseeded Keccak PRNG with specific capacity and number of rounds, for experts only.
  explicit
  KeccakRng (uint16_t hidden_state_capacity = 1600 - 1024, uint16_t n_rounds = 24) :
    bit_rate_ (1600 - hidden_state_capacity), n_rounds_ (n_rounds)
  {
    assert (hidden_state_capacity > 0 && hidden_state_capacity <= 1600 - 64);
    assert (64 * (hidden_state_capacity / 64) == hidden_state_capacity); // capacity must be 64bit aligned
    assert (n_rounds > 0 && n_rounds < 255);                             // see KECCAK_ROUND_CONSTANTS access
    reset();
  }
  void reset    () { state_.A = std::array<uint64_t,25>{}; ipos_ = 0; opos_ = 0; }
  void forget   ();
  void discard  (unsigned long long count);
  void update   (const uint8_t *bytes, size_t nbytes, bool finalize = true);
  void update64 (const uint64_t *seeds, size_t n_seeds, bool finalize = true);
  /// Reinitialize the generator state using a 64 bit @a seed_value.
  void seed     (uint64_t seed_value = 1)               { update64 (&seed_value, 1); }
  /// Generate next uniformly distributed 64 bit pseudo random number.
  uint64_t next () { return random(); }
  /// Reinitialize the generator state using a number of 64 bit @a seeds.
  void
  seed (const std::array<uint64_t, 25> &seeds)
  {
    reset();
    update64 (seeds.data(), seeds.size());
  }
  /// Seed the generator state from a @a seed_sequence.
  template<class SeedSeq> void
  seed (SeedSeq &seed_sequence)
  {
    uint32_t u32[50];                   // fill 50 * 32 = 1600 state bits
    seed_sequence.generate (&u32[0], &u32[50]);
    uint64_t u64[25];
    for (size_t i = 0; i < 25; i++)     // Keccak bit order: 1) LSB 2) MSB
      u64[i] = u32[i * 2] | (uint64_t (u32[i * 2 + 1]) << 32);
    update64 (u64, 25);
  }
  /// Generate uniformly distributed 64 bit pseudo random number.
  /// A new block permutation is carried out every n_nums() calls, see also update64().
  uint64_t
  random ()
  {
    if (opos_ >= n_nums())
      permute1600();
    return state_.A[opos_++];
  }
  /// Generate uniformly distributed 32 bit pseudo random number.
  result_type   operator() ()   { return random(); }
  /// Fill the range [begin, end) with random unsigned integer values.
  template<typename RandomAccessIterator> void
  generate (RandomAccessIterator begin, RandomAccessIterator end)
  {
    typedef typename std::iterator_traits<RandomAccessIterator>::value_type Value;
    while (begin != end)
      {
        const uint64_t rbits = operator()();
        switch (sizeof (Value))
          {
          case 1:
            *begin++ = Value (rbits >> 0);
            if (begin != end) *begin++ = Value (rbits >> 8);
            if (begin != end) *begin++ = Value (rbits >> 16);
            if (begin != end) *begin++ = Value (rbits >> 24);
            if (begin != end) *begin++ = Value (rbits >> 32);
            if (begin != end) *begin++ = Value (rbits >> 40);
            if (begin != end) *begin++ = Value (rbits >> 48);
            if (begin != end) *begin++ = Value (rbits >> 56);
            break;
          case 2:
            *begin++ = Value (rbits);
            if (begin != end) *begin++ = Value (rbits >> 16);
            if (begin != end) *begin++ = Value (rbits >> 32);
            if (begin != end) *begin++ = Value (rbits >> 48);
            break;
          case 4:
            *begin++ = Value (rbits);
            if (begin != end)
              *begin++ = Value (rbits >> 32);
            break;
          default: /*case 8*/
            *begin++ = Value (rbits);
            break;
          }
      }
  }
  /// Compare two generators for state equality.
  friend bool
  operator== (const KeccakRng &lhs, const KeccakRng &rhs)
  {
    if (lhs.state_.A != rhs.state_.A)
      return false;
    return lhs.opos_ == rhs.opos_ && lhs.bit_rate_ == rhs.bit_rate_;
  }
  /// Compare two generators for state inequality.
  friend bool
  operator!= (const KeccakRng &lhs, const KeccakRng &rhs)
  {
    return !(lhs == rhs);
  }
  /// Minimum of the result type, for uint64_t that is 0.
  result_type
  min() const
  {
    return std::numeric_limits<result_type>::min(); // 0
  }
  /// Maximum of the result type, for uint64_t that is 18446744073709551615.
  result_type
  max() const
  {
    return std::numeric_limits<result_type>::max(); // 18446744073709551615
  }
  /// Seed the generator from a system specific nondeterministic random source, needs keccak.cc.
  void auto_seed ();
};

/** Discard 2^256 bits of the current generator state.
 * This makes it practically infeasible to guess previous generator states or
 * deduce generated values from the past.
 * Use this for forward security @cite Security03 of generated security tokens like session keys.
 */
inline void
KeccakRng::forget()
{
  state_.A[24] = 0x5c5c5c5cacacacacull;
  state_.A[23] = 0x3a3a3a3a6c6c6c6cull;
  state_.A[22] = 0x96969696a9a9a9a9ull;
  state_.A[21] = 0x3535353565656565ull;
  permute1600();
}

/** Discard @a count consecutive random values.
 * This function is slightly faster than calling operator()() exactly @a count times.
 */
inline void
KeccakRng::discard (unsigned long long count)
{
  while (count)
    {
      if (opos_ >= n_nums())
        permute1600();
      const unsigned long long ull = std::min ((unsigned long long) n_nums() - opos_, count);
      opos_ += ull;
      count -= ull;
    }
}

/** Incorporate `bytes` into the current generator state.
 * A block permutation to advance the generator state is carried out per n_nums() seed values.
 * After calling this function, generating the next n_nums() random values will not need to
 * block for a new permutation. Unless `finalize==false`, the generator state is finalized.
 */
inline void
KeccakRng::update (const uint8_t *bytes, size_t nbytes, bool finalize)
{
  const uint32_t run_bytes = bit_rate_ / 8;
  if (ipos_) {
    for (; ipos_ < run_bytes && nbytes; ipos_++, nbytes--, bytes++)
      state_.B[ipos_] ^= bytes[0];
    if (ipos_ >= run_bytes) {
      ipos_ = 0;
      permute1600();
    }
  }
  while (nbytes >= run_bytes) {
    for (unsigned i = 0; i < run_bytes; i++)
      state_.B[i] ^= bytes[i];
    bytes += run_bytes;
    nbytes -= run_bytes;
    permute1600();
  }
  for (; ipos_ < run_bytes && nbytes; ipos_++, nbytes--, bytes++)
    state_.B[ipos_] ^= bytes[0];
  if (finalize) {
    state_.B[ipos_] ^= 0x01;        // Paddig bit at sequnce end
    ipos_ = 0;
    state_.B[run_bytes-1] ^= 0x80;  // Finalization bit
    permute1600();
  }
}

/** Incorporate `seed_values` into the current generator state.
 * This works similar to update() but accounts for big endian `uint64_t` values.
 */
inline void
KeccakRng::update64 (const uint64_t *seeds, size_t n_seeds, bool finalize)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN // ! __BIG_ENDIAN
  update ((const uint8_t*) seeds, n_seeds * 8, finalize);
#else
  constexpr unsigned N = 1024;
  uint64_t buff[N];
  while (n_seeds) {
    const unsigned M = n_seeds < N ? n_seeds : N;
    for (unsigned i = 0; i < M; i++)
      buff[i] =  __builtin_bswap64 (seeds[i]);
    n_seeds -= M;
    seeds += M;
    update ((const uint8_t*) buff, M * 8, false);
  }
  if (finalize)
    update (nullptr, 0, finalize);
#endif
}

/// The Keccak-f[1600] permutation for up to 254 rounds, see http://keccak.noekeon.org/Keccak-reference-3.0.pdf.
extern inline void
keccak1600_permute (std::array<uint64_t,25> &A, const uint32_t n_rounds)
{
  assert (n_rounds < 255);
  static constexpr const uint64_t KECCAK_ROUND_CONSTANTS[255] = {
    1, 32898, 0x800000000000808a, 0x8000000080008000, 32907, 0x80000001, 0x8000000080008081, 0x8000000000008009, 138, 136, 0x80008009,
    0x8000000a, 0x8000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 32778,
    0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008, 0x8000000080008082, 0x800000008000800a,
    0x8000000000000003, 0x8000000080000009, 0x8000000000008082, 32777, 0x8000000000000080, 32899, 0x8000000000000081, 1, 32779,
    0x8000000080008001, 128, 0x8000000000008000, 0x8000000080008001, 9, 0x800000008000808b, 129, 0x8000000000000082, 0x8000008b,
    0x8000000080008009, 0x8000000080000000, 0x80000080, 0x80008003, 0x8000000080008082, 0x8000000080008083, 0x8000000080000088, 32905,
    32777, 0x8000000000000009, 0x80008008, 0x80008001, 0x800000000000008a, 0x800000000000000b, 137, 0x80000002, 0x800000000000800b,
    0x8000800b, 32907, 0x80000088, 0x800000000000800a, 0x80000089, 0x8000000000000001, 0x8000000000008088, 0x8000000000000081, 136,
    0x80008080, 129, 0x800000000000000b, 0, 137, 0x8000008b, 0x8000000080008080, 0x800000000000008b, 0x8000000000008000,
    0x8000000080008088, 0x80000082, 11, 0x800000000000000a, 32898, 0x8000000000008003, 0x800000000000808b, 0x800000008000000b,
    0x800000008000008a, 0x80000081, 0x80000081, 0x80000008, 131, 0x8000000080008003, 0x80008088, 0x8000000080000088, 32768, 0x80008082,
    0x80008089, 0x8000000080008083, 0x8000000080000001, 0x80008002, 0x8000000080000089, 130, 0x8000000080000008, 0x8000000000000089,
    0x8000000080000008, 0x8000000000000000, 0x8000000000000083, 0x80008080, 8, 0x8000000080000080, 0x8000000080008080,
    0x8000000000000002, 0x800000008000808b, 8, 0x8000000080000009, 0x800000000000800b, 0x80008082, 0x80008000, 0x8000000000008008, 32897,
    0x8000000080008089, 0x80008089, 0x800000008000800a, 0x800000000000008a, 0x8000000000000082, 0x80000002, 0x8000000000008082, 32896,
    0x800000008000000b, 0x8000000080000003, 10, 0x8000000000008001, 0x8000000080000083, 0x8000000000008083, 139, 32778,
    0x8000000080000083, 0x800000000000800a, 0x80000000, 0x800000008000008a, 0x80000008, 10, 0x8000000000008088, 0x8000000000000008,
    0x80000003, 0x8000000000000000, 0x800000000000000a, 32779, 0x8000000080008088, 0x8000000b, 0x80000080, 0x8000808a,
    0x8000000000008009, 3, 0x80000003, 0x8000000000000089, 0x8000000080000081, 0x800000008000008b, 0x80008003, 0x800000008000800b,
    0x8000000000008008, 32776, 0x8000000000008002, 0x8000000000000009, 0x80008081, 32906, 0x8000800a, 128, 0x8000000000008089,
    0x800000000000808a, 0x8000000080008089, 0x80008000, 0x8000000000008081, 0x8000800a, 9, 0x8000000080008002, 0x8000000a, 0x80008002,
    0x8000000080000000, 0x80000009, 32904, 2, 0x80008008, 0x80008088, 0x8000000080000001, 0x8000808b, 0x8000000000000002,
    0x8000000080008002, 0x80000083, 32905, 32896, 0x8000000080000082, 0x8000000000000088, 0x800000008000808a, 32906, 0x80008083,
    0x8000000b, 0x80000009, 32769, 0x80000089, 0x8000000000000088, 0x8000000080008003, 0x80008001, 0x8000000000000003,
    0x8000000080000080, 0x8000000080008009, 0x8000000080000089, 11, 0x8000000000000083, 0x80008009, 0x80000083, 32768, 0x8000800b, 32770,
    3, 0x8000008a, 0x8000000080000002, 32769, 0x80000000, 0x8000000080000003, 131, 0x800000008000808a, 32771, 32776, 0x800000000000808b,
    0x8000000080000082, 0x8000000000000001, 0x8000000000008001, 0x800000008000000a, 0x8000000080008008, 0x800000008000800b,
    0x8000000000008081, 0x80008083, 0x80000082, 130, 0x8000000080000081, 0x8000000080000002, 32904, 139, 32899, 0x8000000000000008,
    0x8000008a, 0x800000008000008b, 0x8000808a, 0x8000000000008080, 0x80000088, 0x8000000000008083, 2, 0x80008081, 32771, 32897,
    0x8000000080008000, 32770, 138,
  };
  static constexpr const uint8_t KECCAK_RHO_OFFSETS[25] = { 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
                                                            25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };
  const auto bit_rotate64 = [] (uint64_t bits, unsigned int offset) -> uint64_t {
    if (offset == 0) [[unlikely]] return bits;
    // bitwise rotate-left pattern recognized by gcc & clang iff 64==sizeof (bits)
    return (bits << offset) | (bits >> (64 - offset));
  };

  // Keccak forward rounds
  for (size_t round_index = 0; round_index < n_rounds; round_index++)
    {
      // theta
      uint64_t C[5];
      for (size_t x = 0; x < 5; x++)
        {
          C[x] = A[x];
          for (size_t y = 1; y < 5; y++)
            C[x] ^= A[x + 5 * y];
        }
      for (size_t x = 0; x < 5; x++)
        {
          const uint64_t D = C[(5 + x - 1) % 5] ^ bit_rotate64 (C[(x + 1) % 5], 1);
          for (size_t y = 0; y < 5; y++)
            A[x + 5 * y] ^= D;
        }
      // rho
      for (size_t y = 0; y < 25; y += 5)
        {
          uint64_t *const plane = &A[y];
          for (size_t x = 0; x < 5; x++)
            plane[x] = bit_rotate64 (plane[x], KECCAK_RHO_OFFSETS[x + y]);
        }
      // pi
      const uint64_t a[25] = { A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], A[8], A[9], A[10], A[11], A[12],
                               A[13], A[14], A[15], A[16], A[17], A[18], A[19], A[20], A[21], A[22], A[23], A[24] };
      for (size_t y = 0; y < 5; y++)
        for (size_t x = 0; x < 5; x++)
          {
            const size_t X = (0 * x + 1 * y) % 5;
            const size_t Y = (2 * x + 3 * y) % 5;
            A[X + 5 * Y] = a[x + 5 * y];
          }
      // chi
      for (size_t y = 0; y < 25; y += 5)
        {
          uint64_t *const plane = &A[y];
          for (size_t x = 0; x < 5; x++)
            C[x] = plane[x] ^ (~plane[(x + 1) % 5] & plane[(x + 2) % 5]);
          for (size_t x = 0; x < 5; x++)
            plane[x] = C[x];
        }
      // iota
      A[0 + 5 * 0] ^= KECCAK_ROUND_CONSTANTS[round_index]; // round_index needs %255 for n_rounds>=255
    }
}

} // scl::Keccak

#endif // __KECCAK_HH__

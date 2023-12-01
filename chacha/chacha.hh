// Licensed CC0 Public Domain

// ChaCha implementations for ALU, SSE, AVX2, based on Public Domain code from:
// http://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c and CryptoPP

[[maybe_unused]] static inline uint32_t bswap32    (uint32_t v) noexcept { return __builtin_bswap32 (v); }
#if __BYTE_ORDER == __LITTLE_ENDIAN // ! __BIG_ENDIAN
[[maybe_unused]] static inline uint32_t aslittle32 (uint32_t v) noexcept { return v; }
[[maybe_unused]] static inline uint64_t aslittle64 (uint64_t v) noexcept { return v; }
#else
[[maybe_unused]] static inline uint32_t aslittle32 (uint32_t v) noexcept { return bswap32 (v); }
[[maybe_unused]] static inline uint64_t aslittle64 (uint64_t v) noexcept { return __builtin_bswap64 (v); }
#endif

/// Original ChaCha IV with 64 bit nonce and 64 bit counter.
static void
chacha_key_setup (std::array<uint32_t, 16> &state, const unsigned keybits, const std::array<uint8_t, 32> &key, uint64_t nonce, uint64_t counter = 0) noexcept
{
  assert (keybits == 128 || keybits == 256);

  const char sigma[] = "expand 32-byte k";
  const char tau[]   = "expand 16-byte k";
  const char *pad = keybits == 128 ? tau : sigma;

  // https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant - Initial state of ChaCha
  const unsigned h = keybits == 128 ? 0 : 16;
  memcpy (&state[0], pad, 16);      // "expand ??-byte k"
  memcpy (&state[4], &key[0], 16);  // 128 bit key
  memcpy (&state[8], &key[h], 16);  // 256 bit key
  counter = aslittle64 (counter);
  memcpy (&state[12], &counter, 8); // counter low, high
  nonce = aslittle64 (nonce);
  memcpy (&state[14], &nonce, 8);   // 64 bit nonce
}

/// Nonce setup for RFC7539
static void
chacha_rfc7539_setup (std::array<uint32_t, 16> &state, const std::array<uint8_t, 32> &key,
                      const std::array<uint8_t, 12> &nonce, uint32_t counter = 0) noexcept
{
  const char sigma[] = "expand 32-byte k";
  uint32_t u32;
  memcpy (&state[0], sigma, 16);      // "expand 32-byte k"
  memcpy (&state[4], &key[0], 32);    // 256 bit key
  u32 = aslittle32 (counter);
  memcpy (&state[12], &u32, 4);       // counter 32 bit
  memcpy (&state[13], &nonce[0], 12); // 96 bit nonce
}

// == ALU ==
// Based on https://github.com/weidai11/cryptopp/blob/master/chacha.cpp
namespace Alu {
static inline uint32_t
load32 (const uint8_t *s) noexcept
{
  uint32_t v;
  memcpy (&v, s, sizeof (v));
  v = aslittle32 (v);
  return v;
}

static inline void
store32 (uint8_t *d, uint32_t v) noexcept
{
  v = aslittle32 (v);
  memcpy (d, &v, sizeof (v));
}

static inline uint32_t
rol32 (uint32_t w, unsigned left) noexcept
{
  const unsigned right = sizeof (w) * 8 - left;
  return left == 0 ? w : (w << left) | (w >> right);
}

static inline void
qround32 (uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) noexcept
{
  a += b; d = rol32 (d ^ a, 16);
  c += d; b = rol32 (b ^ c, 12);
  a += b; d = rol32 (d ^ a, 8);
  c += d; b = rol32 (b ^ c, 7);
}
} // Alu

static void
chacha_alu (std::array<uint32_t, 16> &state, const uint8_t *input, uint8_t *output, unsigned int rounds)
{
  using namespace Alu;
  uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  x0 = state[0];    x1 = state[1];    x2 = state[2];    x3 = state[3];
  x4 = state[4];    x5 = state[5];    x6 = state[6];    x7 = state[7];
  x8 = state[8];    x9 = state[9];    x10 = state[10];  x11 = state[11];
  x12 = state[12];  x13 = state[13];  x14 = state[14];  x15 = state[15];

  for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
      qround32 (x0, x4,  x8, x12);
      qround32 (x1, x5,  x9, x13);
      qround32 (x2, x6, x10, x14);
      qround32 (x3, x7, x11, x15);

      qround32 (x0, x5, x10, x15);
      qround32 (x1, x6, x11, x12);
      qround32 (x2, x7,  x8, x13);
      qround32 (x3, x4,  x9, x14);
    }

  if (input) {
    store32 (&output[0],  (x0  + state[0])  ^ load32 (&input[0]));
    store32 (&output[4],  (x1  + state[1])  ^ load32 (&input[4]));
    store32 (&output[8],  (x2  + state[2])  ^ load32 (&input[8]));
    store32 (&output[12], (x3  + state[3])  ^ load32 (&input[12]));
    store32 (&output[16], (x4  + state[4])  ^ load32 (&input[16]));
    store32 (&output[20], (x5  + state[5])  ^ load32 (&input[20]));
    store32 (&output[24], (x6  + state[6])  ^ load32 (&input[24]));
    store32 (&output[28], (x7  + state[7])  ^ load32 (&input[28]));
    store32 (&output[32], (x8  + state[8])  ^ load32 (&input[32]));
    store32 (&output[36], (x9  + state[9])  ^ load32 (&input[36]));
    store32 (&output[40], (x10 + state[10]) ^ load32 (&input[40]));
    store32 (&output[44], (x11 + state[11]) ^ load32 (&input[44]));
    store32 (&output[48], (x12 + state[12]) ^ load32 (&input[48]));
    store32 (&output[52], (x13 + state[13]) ^ load32 (&input[52]));
    store32 (&output[56], (x14 + state[14]) ^ load32 (&input[56]));
    store32 (&output[60], (x15 + state[15]) ^ load32 (&input[60]));
  } else {
    store32 (&output[0],  (x0  + state[0]));
    store32 (&output[4],  (x1  + state[1]));
    store32 (&output[8],  (x2  + state[2]));
    store32 (&output[12], (x3  + state[3]));
    store32 (&output[16], (x4  + state[4]));
    store32 (&output[20], (x5  + state[5]));
    store32 (&output[24], (x6  + state[6]));
    store32 (&output[28], (x7  + state[7]));
    store32 (&output[32], (x8  + state[8]));
    store32 (&output[36], (x9  + state[9]));
    store32 (&output[40], (x10 + state[10]));
    store32 (&output[44], (x11 + state[11]));
    store32 (&output[48], (x12 + state[12]));
    store32 (&output[52], (x13 + state[13]));
    store32 (&output[56], (x14 + state[14]));
    store32 (&output[60], (x15 + state[15]));
  }

  if (++state[12] == 0)
    state[13] += 1; // add with carry
}

// == SSE ==
// chacha_simd.cpp - written and placed in the public domain by
//                   Jack Lloyd and Jeffrey Walton
//
#if defined(__SSE2__)
// Based on https://github.com/weidai11/cryptopp/blob/master/chacha_simd.cpp
#include <xmmintrin.h>
#include <emmintrin.h>
#if defined(__SSSE3__)
#include <tmmintrin.h>
#endif // __SSSE3__

namespace Sse2 {
template<unsigned int R>
inline __m128i RotateLeft(const __m128i val)
{
#ifdef __XOP__
  return _mm_roti_epi32(val, R);
#else
  return _mm_or_si128(_mm_slli_epi32(val, R), _mm_srli_epi32(val, 32-R));
#endif
}

template<>
inline __m128i RotateLeft<8>(const __m128i val)
{
#if defined(__XOP__)
  return _mm_roti_epi32(val, 8);
#elif defined(__SSSE3__)
  const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
  return _mm_shuffle_epi8(val, mask);
#else
  return _mm_or_si128(_mm_slli_epi32(val, 8), _mm_srli_epi32(val, 32-8));
#endif
}

template<>
inline __m128i RotateLeft<16>(const __m128i val)
{
#if defined(__XOP__)
  return _mm_roti_epi32(val, 16);
#elif defined(__SSSE3__)
  const __m128i mask = _mm_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
  return _mm_shuffle_epi8(val, mask);
#else
  return _mm_or_si128(_mm_slli_epi32(val, 16), _mm_srli_epi32(val, 32-16));
#endif
}
} // Sse2

static void
chacha_sse (std::array<uint32_t, 16> &state, const uint8_t *input, uint8_t *output, unsigned int rounds)
{
  using namespace Sse2;
  const __m128i state0 = _mm_load_si128(reinterpret_cast<const __m128i*>(&state[0*4]));
  const __m128i state1 = _mm_load_si128(reinterpret_cast<const __m128i*>(&state[1*4]));
  const __m128i state2 = _mm_load_si128(reinterpret_cast<const __m128i*>(&state[2*4]));
  const __m128i state3 = _mm_load_si128(reinterpret_cast<const __m128i*>(&state[3*4]));

  __m128i r0_0 = state0;
  __m128i r0_1 = state1;
  __m128i r0_2 = state2;
  __m128i r0_3 = state3;

  __m128i r1_0 = state0;
  __m128i r1_1 = state1;
  __m128i r1_2 = state2;
  __m128i r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));

  __m128i r2_0 = state0;
  __m128i r2_1 = state1;
  __m128i r2_2 = state2;
  __m128i r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));

  __m128i r3_0 = state0;
  __m128i r3_1 = state1;
  __m128i r3_2 = state2;
  __m128i r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));

  for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
      r0_0 = _mm_add_epi32(r0_0, r0_1);
      r1_0 = _mm_add_epi32(r1_0, r1_1);
      r2_0 = _mm_add_epi32(r2_0, r2_1);
      r3_0 = _mm_add_epi32(r3_0, r3_1);

      r0_3 = _mm_xor_si128(r0_3, r0_0);
      r1_3 = _mm_xor_si128(r1_3, r1_0);
      r2_3 = _mm_xor_si128(r2_3, r2_0);
      r3_3 = _mm_xor_si128(r3_3, r3_0);

      r0_3 = RotateLeft<16>(r0_3);
      r1_3 = RotateLeft<16>(r1_3);
      r2_3 = RotateLeft<16>(r2_3);
      r3_3 = RotateLeft<16>(r3_3);

      r0_2 = _mm_add_epi32(r0_2, r0_3);
      r1_2 = _mm_add_epi32(r1_2, r1_3);
      r2_2 = _mm_add_epi32(r2_2, r2_3);
      r3_2 = _mm_add_epi32(r3_2, r3_3);

      r0_1 = _mm_xor_si128(r0_1, r0_2);
      r1_1 = _mm_xor_si128(r1_1, r1_2);
      r2_1 = _mm_xor_si128(r2_1, r2_2);
      r3_1 = _mm_xor_si128(r3_1, r3_2);

      r0_1 = RotateLeft<12>(r0_1);
      r1_1 = RotateLeft<12>(r1_1);
      r2_1 = RotateLeft<12>(r2_1);
      r3_1 = RotateLeft<12>(r3_1);

      r0_0 = _mm_add_epi32(r0_0, r0_1);
      r1_0 = _mm_add_epi32(r1_0, r1_1);
      r2_0 = _mm_add_epi32(r2_0, r2_1);
      r3_0 = _mm_add_epi32(r3_0, r3_1);

      r0_3 = _mm_xor_si128(r0_3, r0_0);
      r1_3 = _mm_xor_si128(r1_3, r1_0);
      r2_3 = _mm_xor_si128(r2_3, r2_0);
      r3_3 = _mm_xor_si128(r3_3, r3_0);

      r0_3 = RotateLeft<8>(r0_3);
      r1_3 = RotateLeft<8>(r1_3);
      r2_3 = RotateLeft<8>(r2_3);
      r3_3 = RotateLeft<8>(r3_3);

      r0_2 = _mm_add_epi32(r0_2, r0_3);
      r1_2 = _mm_add_epi32(r1_2, r1_3);
      r2_2 = _mm_add_epi32(r2_2, r2_3);
      r3_2 = _mm_add_epi32(r3_2, r3_3);

      r0_1 = _mm_xor_si128(r0_1, r0_2);
      r1_1 = _mm_xor_si128(r1_1, r1_2);
      r2_1 = _mm_xor_si128(r2_1, r2_2);
      r3_1 = _mm_xor_si128(r3_1, r3_2);

      r0_1 = RotateLeft<7>(r0_1);
      r1_1 = RotateLeft<7>(r1_1);
      r2_1 = RotateLeft<7>(r2_1);
      r3_1 = RotateLeft<7>(r3_1);

      r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
      r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
      r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

      r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(0, 3, 2, 1));
      r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
      r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(2, 1, 0, 3));

      r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(0, 3, 2, 1));
      r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
      r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(2, 1, 0, 3));

      r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(0, 3, 2, 1));
      r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
      r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(2, 1, 0, 3));

      r0_0 = _mm_add_epi32(r0_0, r0_1);
      r1_0 = _mm_add_epi32(r1_0, r1_1);
      r2_0 = _mm_add_epi32(r2_0, r2_1);
      r3_0 = _mm_add_epi32(r3_0, r3_1);

      r0_3 = _mm_xor_si128(r0_3, r0_0);
      r1_3 = _mm_xor_si128(r1_3, r1_0);
      r2_3 = _mm_xor_si128(r2_3, r2_0);
      r3_3 = _mm_xor_si128(r3_3, r3_0);

      r0_3 = RotateLeft<16>(r0_3);
      r1_3 = RotateLeft<16>(r1_3);
      r2_3 = RotateLeft<16>(r2_3);
      r3_3 = RotateLeft<16>(r3_3);

      r0_2 = _mm_add_epi32(r0_2, r0_3);
      r1_2 = _mm_add_epi32(r1_2, r1_3);
      r2_2 = _mm_add_epi32(r2_2, r2_3);
      r3_2 = _mm_add_epi32(r3_2, r3_3);

      r0_1 = _mm_xor_si128(r0_1, r0_2);
      r1_1 = _mm_xor_si128(r1_1, r1_2);
      r2_1 = _mm_xor_si128(r2_1, r2_2);
      r3_1 = _mm_xor_si128(r3_1, r3_2);

      r0_1 = RotateLeft<12>(r0_1);
      r1_1 = RotateLeft<12>(r1_1);
      r2_1 = RotateLeft<12>(r2_1);
      r3_1 = RotateLeft<12>(r3_1);

      r0_0 = _mm_add_epi32(r0_0, r0_1);
      r1_0 = _mm_add_epi32(r1_0, r1_1);
      r2_0 = _mm_add_epi32(r2_0, r2_1);
      r3_0 = _mm_add_epi32(r3_0, r3_1);

      r0_3 = _mm_xor_si128(r0_3, r0_0);
      r1_3 = _mm_xor_si128(r1_3, r1_0);
      r2_3 = _mm_xor_si128(r2_3, r2_0);
      r3_3 = _mm_xor_si128(r3_3, r3_0);

      r0_3 = RotateLeft<8>(r0_3);
      r1_3 = RotateLeft<8>(r1_3);
      r2_3 = RotateLeft<8>(r2_3);
      r3_3 = RotateLeft<8>(r3_3);

      r0_2 = _mm_add_epi32(r0_2, r0_3);
      r1_2 = _mm_add_epi32(r1_2, r1_3);
      r2_2 = _mm_add_epi32(r2_2, r2_3);
      r3_2 = _mm_add_epi32(r3_2, r3_3);

      r0_1 = _mm_xor_si128(r0_1, r0_2);
      r1_1 = _mm_xor_si128(r1_1, r1_2);
      r2_1 = _mm_xor_si128(r2_1, r2_2);
      r3_1 = _mm_xor_si128(r3_1, r3_2);

      r0_1 = RotateLeft<7>(r0_1);
      r1_1 = RotateLeft<7>(r1_1);
      r2_1 = RotateLeft<7>(r2_1);
      r3_1 = RotateLeft<7>(r3_1);

      r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
      r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
      r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));

      r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(2, 1, 0, 3));
      r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
      r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(0, 3, 2, 1));

      r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(2, 1, 0, 3));
      r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
      r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(0, 3, 2, 1));

      r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(2, 1, 0, 3));
      r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
      r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(0, 3, 2, 1));
    }

  r0_0 = _mm_add_epi32(r0_0, state0);
  r0_1 = _mm_add_epi32(r0_1, state1);
  r0_2 = _mm_add_epi32(r0_2, state2);
  r0_3 = _mm_add_epi32(r0_3, state3);

  r1_0 = _mm_add_epi32(r1_0, state0);
  r1_1 = _mm_add_epi32(r1_1, state1);
  r1_2 = _mm_add_epi32(r1_2, state2);
  r1_3 = _mm_add_epi32(r1_3, state3);
  r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

  r2_0 = _mm_add_epi32(r2_0, state0);
  r2_1 = _mm_add_epi32(r2_1, state1);
  r2_2 = _mm_add_epi32(r2_2, state2);
  r2_3 = _mm_add_epi32(r2_3, state3);
  r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

  r3_0 = _mm_add_epi32(r3_0, state0);
  r3_1 = _mm_add_epi32(r3_1, state1);
  r3_2 = _mm_add_epi32(r3_2, state2);
  r3_3 = _mm_add_epi32(r3_3, state3);
  r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

  if (input)
    {
      r0_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+0*16)), r0_0);
      r0_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+1*16)), r0_1);
      r0_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+2*16)), r0_2);
      r0_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+3*16)), r0_3);
    }

  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+0*16), r0_0);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+1*16), r0_1);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+2*16), r0_2);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+3*16), r0_3);

  if (input)
    {
      r1_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+4*16)), r1_0);
      r1_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+5*16)), r1_1);
      r1_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+6*16)), r1_2);
      r1_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+7*16)), r1_3);
    }

  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+4*16), r1_0);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+5*16), r1_1);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+6*16), r1_2);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+7*16), r1_3);

  if (input)
    {
      r2_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+ 8*16)), r2_0);
      r2_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+ 9*16)), r2_1);
      r2_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+10*16)), r2_2);
      r2_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+11*16)), r2_3);
    }

  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+ 8*16), r2_0);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+ 9*16), r2_1);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+10*16), r2_2);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+11*16), r2_3);

  if (input)
    {
      r3_0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+12*16)), r3_0);
      r3_1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+13*16)), r3_1);
      r3_2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+14*16)), r3_2);
      r3_3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(input+15*16)), r3_3);
    }

  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+12*16), r3_0);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+13*16), r3_1);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+14*16), r3_2);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(output+15*16), r3_3);

  state[12] += 4;
  if (state[12] == 0)
    state[13] += 1; // add with carry
}
static constexpr unsigned sse_blocks = 4;
#else // !__SSE2__
static void chacha_sse (std::array<uint32_t, 16>&, const uint8_t*, uint8_t*, unsigned int) { assert (!"reached"); }
static constexpr unsigned sse_blocks = 0;
#endif // !__SSE2__

// == AVX2 ==
// chacha_avx.cpp - written and placed in the public domain by
//                  Jack Lloyd and Jeffrey Walton
//
#if defined(__AVX2__)
// Based on https://github.com/weidai11/cryptopp/blob/master/chacha_avx.cpp
#include <xmmintrin.h>
#include <emmintrin.h>
#include <immintrin.h>

namespace Avx2 {
template<unsigned int R>
inline __m256i RotateLeft(const __m256i val)
{
  return _mm256_or_si256(_mm256_slli_epi32(val, R), _mm256_srli_epi32(val, 32-R));
}

template<>
inline __m256i RotateLeft<8>(const __m256i val)
{
  const __m256i mask = _mm256_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3,
                                       14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
  return _mm256_shuffle_epi8(val, mask);
}

template<>
inline __m256i RotateLeft<16>(const __m256i val)
{
  const __m256i mask = _mm256_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2,
                                       13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
  return _mm256_shuffle_epi8(val, mask);
}
} // Avx2

static void
chacha_avx2(std::array<uint32_t, 16> &state, const uint8_t *input, uint8_t *output, unsigned int rounds)
{
  using namespace Avx2;
  const __m256i state0 = _mm256_broadcastsi128_si256(
                                                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0*4])));
  const __m256i state1 = _mm256_broadcastsi128_si256(
                                                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[1*4])));
  const __m256i state2 = _mm256_broadcastsi128_si256(
                                                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[2*4])));
  const __m256i state3 = _mm256_broadcastsi128_si256(
                                                     _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[3*4])));

  const uint32_t C = 0xFFFFFFFFu - state[12];
  const __m256i CTR0 = _mm256_set_epi32(0, 0,     0, 0, 0, 0, C < 4, 4);
  const __m256i CTR1 = _mm256_set_epi32(0, 0, C < 1, 1, 0, 0, C < 5, 5);
  const __m256i CTR2 = _mm256_set_epi32(0, 0, C < 2, 2, 0, 0, C < 6, 6);
  const __m256i CTR3 = _mm256_set_epi32(0, 0, C < 3, 3, 0, 0, C < 7, 7);

  __m256i X0_0 = state0;
  __m256i X0_1 = state1;
  __m256i X0_2 = state2;
  __m256i X0_3 = _mm256_add_epi32(state3, CTR0);

  __m256i X1_0 = state0;
  __m256i X1_1 = state1;
  __m256i X1_2 = state2;
  __m256i X1_3 = _mm256_add_epi32(state3, CTR1);

  __m256i X2_0 = state0;
  __m256i X2_1 = state1;
  __m256i X2_2 = state2;
  __m256i X2_3 = _mm256_add_epi32(state3, CTR2);

  __m256i X3_0 = state0;
  __m256i X3_1 = state1;
  __m256i X3_2 = state2;
  __m256i X3_3 = _mm256_add_epi32(state3, CTR3);

  for (int i = static_cast<int>(rounds); i > 0; i -= 2)
    {
      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = RotateLeft<16>(X0_3);
      X1_3 = RotateLeft<16>(X1_3);
      X2_3 = RotateLeft<16>(X2_3);
      X3_3 = RotateLeft<16>(X3_3);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = RotateLeft<12>(X0_1);
      X1_1 = RotateLeft<12>(X1_1);
      X2_1 = RotateLeft<12>(X2_1);
      X3_1 = RotateLeft<12>(X3_1);

      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = RotateLeft<8>(X0_3);
      X1_3 = RotateLeft<8>(X1_3);
      X2_3 = RotateLeft<8>(X2_3);
      X3_3 = RotateLeft<8>(X3_3);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = RotateLeft<7>(X0_1);
      X1_1 = RotateLeft<7>(X1_1);
      X2_1 = RotateLeft<7>(X2_1);
      X3_1 = RotateLeft<7>(X3_1);

      X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(0, 3, 2, 1));
      X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
      X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(2, 1, 0, 3));

      X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(0, 3, 2, 1));
      X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
      X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(2, 1, 0, 3));

      X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(0, 3, 2, 1));
      X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
      X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(2, 1, 0, 3));

      X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(0, 3, 2, 1));
      X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
      X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(2, 1, 0, 3));

      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = RotateLeft<16>(X0_3);
      X1_3 = RotateLeft<16>(X1_3);
      X2_3 = RotateLeft<16>(X2_3);
      X3_3 = RotateLeft<16>(X3_3);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = RotateLeft<12>(X0_1);
      X1_1 = RotateLeft<12>(X1_1);
      X2_1 = RotateLeft<12>(X2_1);
      X3_1 = RotateLeft<12>(X3_1);

      X0_0 = _mm256_add_epi32(X0_0, X0_1);
      X1_0 = _mm256_add_epi32(X1_0, X1_1);
      X2_0 = _mm256_add_epi32(X2_0, X2_1);
      X3_0 = _mm256_add_epi32(X3_0, X3_1);

      X0_3 = _mm256_xor_si256(X0_3, X0_0);
      X1_3 = _mm256_xor_si256(X1_3, X1_0);
      X2_3 = _mm256_xor_si256(X2_3, X2_0);
      X3_3 = _mm256_xor_si256(X3_3, X3_0);

      X0_3 = RotateLeft<8>(X0_3);
      X1_3 = RotateLeft<8>(X1_3);
      X2_3 = RotateLeft<8>(X2_3);
      X3_3 = RotateLeft<8>(X3_3);

      X0_2 = _mm256_add_epi32(X0_2, X0_3);
      X1_2 = _mm256_add_epi32(X1_2, X1_3);
      X2_2 = _mm256_add_epi32(X2_2, X2_3);
      X3_2 = _mm256_add_epi32(X3_2, X3_3);

      X0_1 = _mm256_xor_si256(X0_1, X0_2);
      X1_1 = _mm256_xor_si256(X1_1, X1_2);
      X2_1 = _mm256_xor_si256(X2_1, X2_2);
      X3_1 = _mm256_xor_si256(X3_1, X3_2);

      X0_1 = RotateLeft<7>(X0_1);
      X1_1 = RotateLeft<7>(X1_1);
      X2_1 = RotateLeft<7>(X2_1);
      X3_1 = RotateLeft<7>(X3_1);

      X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(2, 1, 0, 3));
      X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
      X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(0, 3, 2, 1));

      X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(2, 1, 0, 3));
      X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
      X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(0, 3, 2, 1));

      X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(2, 1, 0, 3));
      X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
      X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(0, 3, 2, 1));

      X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(2, 1, 0, 3));
      X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
      X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(0, 3, 2, 1));
    }

  X0_0 = _mm256_add_epi32(X0_0, state0);
  X0_1 = _mm256_add_epi32(X0_1, state1);
  X0_2 = _mm256_add_epi32(X0_2, state2);
  X0_3 = _mm256_add_epi32(X0_3, state3);
  X0_3 = _mm256_add_epi32(X0_3, CTR0);

  X1_0 = _mm256_add_epi32(X1_0, state0);
  X1_1 = _mm256_add_epi32(X1_1, state1);
  X1_2 = _mm256_add_epi32(X1_2, state2);
  X1_3 = _mm256_add_epi32(X1_3, state3);
  X1_3 = _mm256_add_epi32(X1_3, CTR1);

  X2_0 = _mm256_add_epi32(X2_0, state0);
  X2_1 = _mm256_add_epi32(X2_1, state1);
  X2_2 = _mm256_add_epi32(X2_2, state2);
  X2_3 = _mm256_add_epi32(X2_3, state3);
  X2_3 = _mm256_add_epi32(X2_3, CTR2);

  X3_0 = _mm256_add_epi32(X3_0, state0);
  X3_1 = _mm256_add_epi32(X3_1, state1);
  X3_2 = _mm256_add_epi32(X3_2, state2);
  X3_3 = _mm256_add_epi32(X3_3, state3);
  X3_3 = _mm256_add_epi32(X3_3, CTR3);

  if (input)
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+0*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+0*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+1*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+1*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+2*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+2*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+3*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+3*32)))));
    }
  else
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+0*32),
                          _mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+1*32),
                          _mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+2*32),
                          _mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+3*32),
                          _mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)));
    }

  if (input)
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+4*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+4*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+5*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+5*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+6*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+6*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+7*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+7*32)))));
    }
  else
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+4*32),
                          _mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+5*32),
                          _mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+6*32),
                          _mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+7*32),
                          _mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)));
    }

  if (input)
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 8*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+8*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 9*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+9*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+10*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+10*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+11*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+11*32)))));
    }
  else
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 8*32),
                          _mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+ 9*32),
                          _mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+10*32),
                          _mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+11*32),
                          _mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)));
    }

  if (input)
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+12*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+12*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+13*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+13*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+14*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+14*32)))));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+15*32),
                          _mm256_xor_si256(_mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)),
                                           _mm256_loadu_si256(const_cast<const __m256i*>(reinterpret_cast<const __m256i*>(input+15*32)))));
    }
  else
    {
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+12*32),
                          _mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+13*32),
                          _mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+14*32),
                          _mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)));
      _mm256_storeu_si256(reinterpret_cast<__m256i*>(output+15*32),
                          _mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)));
    }

  // https://software.intel.com/en-us/articles/avoiding-avx-sse-transition-penalties
  _mm256_zeroupper();

  state[12] += 8;
  if (state[12] == 0)
    state[13] += 1; // add with carry
}
static constexpr unsigned avx_blocks = 8;
#else // !__AVX2__
static void chacha_avx2 (std::array<uint32_t, 16>&, const uint8_t*, uint8_t*, unsigned int) { assert (!"reached"); }
static constexpr unsigned avx_blocks = 0;
#endif // !__AVX2__

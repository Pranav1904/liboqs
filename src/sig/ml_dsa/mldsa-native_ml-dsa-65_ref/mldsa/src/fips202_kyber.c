/* Based on the public domain implementation in crypto_hash/keccakc512/simple/ from
 * http://bench.cr.yp.to/supercop.html by Ronny Van Keer and the public domain "TweetFips202"
 * implementation from https://twitter.com/tweetfips202 by Gilles Van Assche, Daniel J. Bernstein,
 * and Peter Schwabe */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "fips202_kyber.h"

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

/*************************************************
* Name:        load64
*
* Description: Load 8 bytes into uint64_t in little-endian order
*
* Arguments:   - const uint8_t *x: pointer to input byte array
*
* Returns the loaded 64-bit unsigned integer
**************************************************/
static uint64_t load64(const uint8_t x[8]) {
  uint64_t r;
  memcpy(&r, x, 8);
  return r;
}

/*************************************************
* Name:        store64
*
* Description: Store a 64-bit integer to array of 8 bytes in little-endian order
*
* Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
*              - uint64_t u: input 64-bit unsigned integer
**************************************************/
static void store64(uint8_t x[8], uint64_t u) {
  memcpy(x, &u, 8);
}

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};

/* wolfSSL-style Keccak-f[1600] with double buffer (s and n) to reduce
 * register pressure on 32-bit RISC-V; same round constants and logic. */

#define ROTL64_KECCAK(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

/* Rho-pi indices (lane permutation) */
#define KI_0   6
#define KI_1  12
#define KI_2  18
#define KI_3  24
#define KI_4   3
#define KI_5   9
#define KI_6  10
#define KI_7  16
#define KI_8  22
#define KI_9   1
#define KI_10  7
#define KI_11 13
#define KI_12 19
#define KI_13 20
#define KI_14  4
#define KI_15  5
#define KI_16 11
#define KI_17 17
#define KI_18 23
#define KI_19  2
#define KI_20  8
#define KI_21 14
#define KI_22 15
#define KI_23 21

/* Rho rotation amounts (bits) */
#define KR_0  44
#define KR_1  43
#define KR_2  21
#define KR_3  14
#define KR_4  28
#define KR_5  20
#define KR_6   3
#define KR_7  45
#define KR_8  61
#define KR_9   1
#define KR_10  6
#define KR_11 25
#define KR_12  8
#define KR_13 18
#define KR_14 27
#define KR_15 36
#define KR_16 10
#define KR_17 15
#define KR_18 56
#define KR_19 62
#define KR_20 55
#define KR_21 39
#define KR_22 41
#define KR_23  2

#define S_KECCAK(s1, i) ROTL64_KECCAK((s1)[KI_##i], KR_##i)

/* Theta: mix columns (in-place). */
#define COL_MIX_KECCAK(s, b, t) do { \
    (b)[0] = (s)[0] ^ (s)[5] ^ (s)[10] ^ (s)[15] ^ (s)[20]; \
    (b)[1] = (s)[1] ^ (s)[6] ^ (s)[11] ^ (s)[16] ^ (s)[21]; \
    (b)[2] = (s)[2] ^ (s)[7] ^ (s)[12] ^ (s)[17] ^ (s)[22]; \
    (b)[3] = (s)[3] ^ (s)[8] ^ (s)[13] ^ (s)[18] ^ (s)[23]; \
    (b)[4] = (s)[4] ^ (s)[9] ^ (s)[14] ^ (s)[19] ^ (s)[24]; \
    (t) = (b)[4] ^ ROTL64_KECCAK((b)[1], 1); \
    (s)[ 0] ^= (t); (s)[ 5] ^= (t); (s)[10] ^= (t); (s)[15] ^= (t); (s)[20] ^= (t); \
    (t) = (b)[0] ^ ROTL64_KECCAK((b)[2], 1); \
    (s)[ 1] ^= (t); (s)[ 6] ^= (t); (s)[11] ^= (t); (s)[16] ^= (t); (s)[21] ^= (t); \
    (t) = (b)[1] ^ ROTL64_KECCAK((b)[3], 1); \
    (s)[ 2] ^= (t); (s)[ 7] ^= (t); (s)[12] ^= (t); (s)[17] ^= (t); (s)[22] ^= (t); \
    (t) = (b)[2] ^ ROTL64_KECCAK((b)[4], 1); \
    (s)[ 3] ^= (t); (s)[ 8] ^= (t); (s)[13] ^= (t); (s)[18] ^= (t); (s)[23] ^= (t); \
    (t) = (b)[3] ^ ROTL64_KECCAK((b)[0], 1); \
    (s)[ 4] ^= (t); (s)[ 9] ^= (t); (s)[14] ^= (t); (s)[19] ^= (t); (s)[24] ^= (t); \
} while (0)

/* Rho-pi-chi: read s1, write s2. Chi without ANDN: a^(~b&c) = a^(c&(b^c)). */
#define ROW_MIX_KECCAK(s2, s1, b, t12, t34) do { \
    (b)[0] = (s1)[0]; \
    (b)[1] = S_KECCAK((s1), 0); \
    (b)[2] = S_KECCAK((s1), 1); \
    (b)[3] = S_KECCAK((s1), 2); \
    (b)[4] = S_KECCAK((s1), 3); \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[0] = (b)[0] ^ ((b)[2] & (t12)); \
    (s2)[1] = (t12) ^ ((b)[2] | (b)[3]); \
    (s2)[2] = (b)[2] ^ ((b)[4] & (t34)); \
    (s2)[3] = (t34) ^ ((b)[4] | (b)[0]); \
    (s2)[4] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1])); \
    (b)[0] = S_KECCAK((s1), 4); \
    (b)[1] = S_KECCAK((s1), 5); \
    (b)[2] = S_KECCAK((s1), 6); \
    (b)[3] = S_KECCAK((s1), 7); \
    (b)[4] = S_KECCAK((s1), 8); \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[5] = (b)[0] ^ ((b)[2] & (t12)); \
    (s2)[6] = (t12) ^ ((b)[2] | (b)[3]); \
    (s2)[7] = (b)[2] ^ ((b)[4] & (t34)); \
    (s2)[8] = (t34) ^ ((b)[4] | (b)[0]); \
    (s2)[9] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1])); \
    (b)[0] = S_KECCAK((s1), 9); \
    (b)[1] = S_KECCAK((s1), 10); \
    (b)[2] = S_KECCAK((s1), 11); \
    (b)[3] = S_KECCAK((s1), 12); \
    (b)[4] = S_KECCAK((s1), 13); \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[10] = (b)[0] ^ ((b)[2] & (t12)); \
    (s2)[11] = (t12) ^ ((b)[2] | (b)[3]); \
    (s2)[12] = (b)[2] ^ ((b)[4] & (t34)); \
    (s2)[13] = (t34) ^ ((b)[4] | (b)[0]); \
    (s2)[14] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1])); \
    (b)[0] = S_KECCAK((s1), 14); \
    (b)[1] = S_KECCAK((s1), 15); \
    (b)[2] = S_KECCAK((s1), 16); \
    (b)[3] = S_KECCAK((s1), 17); \
    (b)[4] = S_KECCAK((s1), 18); \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[15] = (b)[0] ^ ((b)[2] & (t12)); \
    (s2)[16] = (t12) ^ ((b)[2] | (b)[3]); \
    (s2)[17] = (b)[2] ^ ((b)[4] & (t34)); \
    (s2)[18] = (t34) ^ ((b)[4] | (b)[0]); \
    (s2)[19] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1])); \
    (b)[0] = S_KECCAK((s1), 19); \
    (b)[1] = S_KECCAK((s1), 20); \
    (b)[2] = S_KECCAK((s1), 21); \
    (b)[3] = S_KECCAK((s1), 22); \
    (b)[4] = S_KECCAK((s1), 23); \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[20] = (b)[0] ^ ((b)[2] & (t12)); \
    (s2)[21] = (t12) ^ ((b)[2] | (b)[3]); \
    (s2)[22] = (b)[2] ^ ((b)[4] & (t34)); \
    (s2)[23] = (t34) ^ ((b)[4] | (b)[0]); \
    (s2)[24] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1])); \
} while (0)

/* Optional Keccak block counter for verify matrix_expand (define MLD_KECCAK_COUNT_VERIFY).
 * Count = one per KeccakF1600_StatePermute() call (squeezeblocks does 1 per block; absorb can add more).
 * Serial path: 40 polys * 5 blocks initial = 200, plus 0..40 from rejection loop. Expected >= 200.
 * WolfSSL uses 5 blocks; if you see 150, the serial path was using 3 blocks (40*3 + 30 rejection). */
#if defined(MLD_KECCAK_COUNT_VERIFY)
static uint64_t s_keccak_permute_count = 0;
static uint64_t s_squeeze_blocks_requested = 0; /* total nblocks passed to shake128_squeezeblocks */
#endif

/*************************************************
* Name:        KeccakF1600_StatePermute
*
* Description: The Keccak F1600 Permutation (wolfSSL-style double buffer
*              for better register usage on 32-bit RISC-V).
*              Inlined on ESP32/RISC-V to cut call overhead in hot paths.
*
* Arguments:   - uint64_t *state: pointer to input/output Keccak state
**************************************************/
static inline void KeccakF1600_StatePermute(uint64_t state[25])
{
  uint64_t n[25];
  uint64_t b[5];
  uint64_t t0, t12, t34;
  unsigned int i;
#if defined(MLD_KECCAK_COUNT_VERIFY)
  s_keccak_permute_count++;
#endif

  for (i = 0; i < 24; i += 2) {
    COL_MIX_KECCAK(state, b, t0);
    ROW_MIX_KECCAK(n, state, b, t12, t34);
    n[0] ^= KeccakF_RoundConstants[i];

    COL_MIX_KECCAK(n, b, t0);
    ROW_MIX_KECCAK(state, n, b, t12, t34);
    state[0] ^= KeccakF_RoundConstants[i + 1];
  }
}

/*************************************************
* Name:        keccak_init
*
* Description: Initializes the Keccak state.
*
* Arguments:   - uint64_t *s: pointer to Keccak state
**************************************************/
static void keccak_init(uint64_t s[25])
{
  memset(s, 0, 25 * sizeof(uint64_t));
}

#if defined(MLD_KECCAK_COUNT_VERIFY)
void mld_keccak_count_reset(void)
{
  s_keccak_permute_count = 0;
  s_squeeze_blocks_requested = 0;
}

uint64_t mld_keccak_count_get(void)
{
  return s_keccak_permute_count;
}

uint64_t mld_keccak_squeeze_blocks_requested_get(void)
{
  return s_squeeze_blocks_requested;
}
#endif

/*************************************************
* Name:        keccak_absorb
*
* Description: Absorb step of Keccak; incremental.
*
* Arguments:   - uint64_t *s: pointer to Keccak state
*              - unsigned int pos: position in current block to be absorbed
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
*
* Returns new position pos in current block
**************************************************/
static unsigned int keccak_absorb(uint64_t s[25],
                                  unsigned int pos,
                                  unsigned int r,
                                  const uint8_t *in,
                                  size_t inlen)
{
  unsigned int i;

  while (pos + inlen >= r) {
    if (pos == 0) {
      /* Full block: lane-oriented absorb (like wolfSSL xorbuf) */
      for (i = 0; i < r / 8; i++)
        s[i] ^= load64(in + 8 * i);
      in += r;
      inlen -= r;
      KeccakF1600_StatePermute(s);
    } else {
      for (i = pos; i < r; i++)
        s[i / 8] ^= (uint64_t)*in++ << 8 * (i % 8);
      inlen -= (r - pos);
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
  }

  for (i = pos; (size_t)(i - pos) < inlen; i++)
    s[i / 8] ^= (uint64_t)*in++ << 8 * (i % 8);

  return i;
}

/*************************************************
* Name:        keccak_finalize
*
* Description: Finalize absorb step.
*
* Arguments:   - uint64_t *s: pointer to Keccak state
*              - unsigned int pos: position in current block to be absorbed
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - uint8_t p: domain separation byte
**************************************************/
static void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p)
{
  s[pos/8] ^= (uint64_t)p << 8*(pos%8);
  s[r/8-1] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeeze
*
* Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental.
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: number of bytes to be squeezed (written to out)
*              - uint64_t *s: pointer to input/output Keccak state
*              - unsigned int pos: number of bytes in current block already squeezed
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*
* Returns new position pos in current block
**************************************************/
static unsigned int keccak_squeeze(uint8_t *out,
                                   size_t outlen,
                                   uint64_t s[25],
                                   unsigned int pos,
                                   unsigned int r)
{
  unsigned int i;

  /* Fast path: output full blocks with single memcpy (like wolfSSL XMEMCPY(out, s, rate)) */
  while (outlen >= r && pos == 0) {
    KeccakF1600_StatePermute(s);
    memcpy(out, s, r);
    out += r;
    outlen -= r;
  }

  /* Remainder: full blocks with memcpy when pos==0, else byte-by-byte */
  while (outlen) {
    if (pos == r) {
      KeccakF1600_StatePermute(s);
      pos = 0;
    }
    if (pos == 0 && outlen >= r) {
      memcpy(out, s, r);
      out += r;
      outlen -= r;
      pos = r; /* next iteration will permute */
      continue;
    }
    for (i = pos; i < r && (size_t)(i - pos) < outlen; i++)
      *out++ = (uint8_t)(s[i / 8] >> 8 * (i % 8));
    outlen -= i - pos;
    pos = i;
  }

  return pos;
}


/*************************************************
* Name:        keccak_absorb_once
*
* Description: Absorb step of Keccak;
*              non-incremental, starts by zeroeing the state.
*
* Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
*              - uint8_t p: domain-separation byte for different Keccak-derived functions
**************************************************/
static void keccak_absorb_once(uint64_t s[25],
                               unsigned int r,
                               const uint8_t *in,
                               size_t inlen,
                               uint8_t p)
{
  unsigned int i;

  memset(s, 0, 25 * sizeof(uint64_t));

  while (inlen >= r) {
    for (i = 0; i < r / 8; i++)
      s[i] ^= load64(in + 8 * i);
    in += r;
    inlen -= r;
    KeccakF1600_StatePermute(s);
  }

  /* Tail: lane-oriented for complete 8-byte chunks, then byte for remainder */
  for (i = 0; i + 8 <= inlen; i += 8)
    s[i / 8] ^= load64(in + i);
  for (; i < inlen; i++)
    s[i / 8] ^= (uint64_t)in[i] << 8 * (i % 8);

  s[i / 8] ^= (uint64_t)p << 8 * (i % 8);
  s[(r - 1) / 8] ^= 1ULL << 63;
}

/*************************************************
* Name:        keccak_squeezeblocks
*
* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
*              Modifies the state. Can be called multiple times to keep
*              squeezing, i.e., is incremental. Assumes zero bytes of current
*              block have already been squeezed.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to out)
*              - uint64_t *s: pointer to input/output Keccak state
*              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
**************************************************/
static void keccak_squeezeblocks(uint8_t *out,
                                 size_t nblocks,
                                 uint64_t s[25],
                                 unsigned int r)
{
  while (nblocks) {
    KeccakF1600_StatePermute(s);
    memcpy(out, s, r);
    out += r;
    nblocks -= 1;
  }
}

/*************************************************
* Name:        shake128_init
*
* Description: Initilizes Keccak state for use as SHAKE128 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
void shake128_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
* Name:        shake128_absorb
*
* Description: Absorb step of the SHAKE128 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}

/*************************************************
* Name:        shake128_finalize
*
* Description: Finalize absorb step of the SHAKE128 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake128_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
  state->pos = SHAKE128_RATE;
}

/*************************************************
* Name:        shake128_squeeze
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t outlen : number of bytes to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
}

/*************************************************
* Name:        shake128_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
  state->pos = SHAKE128_RATE;
}

/*************************************************
* Name:        shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
*              SHAKE128_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes new block has not yet been
*              started (state->pos = SHAKE128_RATE).
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
#if defined(MLD_KECCAK_COUNT_VERIFY)
  s_squeeze_blocks_requested += nblocks;
#endif
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
}

/*************************************************
* Name:        shake256_init
*
* Description: Initilizes Keccak state for use as SHAKE256 XOF
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
**************************************************/
void shake256_init(keccak_state *state)
{
  keccak_init(state->s);
  state->pos = 0;
}

/*************************************************
* Name:        shake256_absorb
*
* Description: Absorb step of the SHAKE256 XOF; incremental.
*
* Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, in, inlen);
}

/*************************************************
* Name:        shake256_finalize
*
* Description: Finalize absorb step of the SHAKE256 XOF.
*
* Arguments:   - keccak_state *state: pointer to Keccak state
**************************************************/
void shake256_finalize(keccak_state *state)
{
  keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
  state->pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeeze
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
*              bytes. Can be called multiple times to keep squeezing.
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t outlen : number of bytes to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE256_RATE);
}

/*************************************************
* Name:        shake256_absorb_once
*
* Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
*
* Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
*              - const uint8_t *in: pointer to input to be absorbed into s
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
  keccak_absorb_once(state->s, SHAKE256_RATE, in, inlen, 0x1F);
  state->pos = SHAKE256_RATE;
}

/*************************************************
* Name:        shake256_squeezeblocks
*
* Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
*              SHAKE256_RATE bytes each. Can be called multiple times
*              to keep squeezing. Assumes next block has not yet been
*              started (state->pos = SHAKE256_RATE).
*
* Arguments:   - uint8_t *out: pointer to output blocks
*              - size_t nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s: pointer to input/output Keccak state
**************************************************/
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
  keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
}

/*************************************************
* Name:        shake128
*
* Description: SHAKE128 XOF with non-incremental API
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake128_absorb_once(&state, in, inlen);
  nblocks = outlen/SHAKE128_RATE;
  shake128_squeezeblocks(out, nblocks, &state);
  outlen -= nblocks*SHAKE128_RATE;
  out += nblocks*SHAKE128_RATE;
  shake128_squeeze(out, outlen, &state);
}

/*************************************************
* Name:        shake256
*
* Description: SHAKE256 XOF with non-incremental API
*
* Arguments:   - uint8_t *out: pointer to output
*              - size_t outlen: requested output length in bytes
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake256_absorb_once(&state, in, inlen);
  nblocks = outlen/SHAKE256_RATE;
  shake256_squeezeblocks(out, nblocks, &state);
  outlen -= nblocks*SHAKE256_RATE;
  out += nblocks*SHAKE256_RATE;
  shake256_squeeze(out, outlen, &state);
}

/*************************************************
* Name:        sha3_256
*
* Description: SHA3-256 with non-incremental API
*
* Arguments:   - uint8_t *h: pointer to output (32 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<4;i++)
    store64(h+8*i,s[i]);
}

/*************************************************
* Name:        sha3_512
*
* Description: SHA3-512 with non-incremental API
*
* Arguments:   - uint8_t *h: pointer to output (64 bytes)
*              - const uint8_t *in: pointer to input
*              - size_t inlen: length of input in bytes
**************************************************/
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
  unsigned int i;
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);
  for(i=0;i<8;i++)
    store64(h+8*i,s[i]);
}

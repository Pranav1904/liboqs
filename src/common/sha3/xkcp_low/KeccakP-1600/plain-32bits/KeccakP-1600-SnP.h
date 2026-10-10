/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël
Peeters and Gilles Van Assche.

Implementation by Pranav Sonawane, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team
website: https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

32-bit optimized Keccak-p[1600] implementation using bit-interleaving.
Designed for embedded 32-bit targets (e.g. ESP32, ARM Cortex-M) where
64-bit lane operations are expensive.

State representation: each 64-bit Keccak lane is split into two 32-bit
words (even-indexed and odd-indexed bits), reducing 64-bit register
pressure to 32-bit operations throughout the permutation.

SPDX-License-Identifier: MIT
*/

#ifndef _KeccakP_1600_plain32_SnP_h_
#define _KeccakP_1600_plain32_SnP_h_

#include <stddef.h>
#include <stdint.h>

/* State: 25 lanes × 2 halves (even + odd bits) = 50 × uint32_t = 200 bytes.
 * Bit-interleaved: lane i → A[2*i] (even bits) + A[2*i+1] (odd bits). */
typedef struct {
  uint32_t A[50];
} KeccakP1600_plain32_state;

/* State is 200 bytes (25 × 64-bit lanes), stored as 50 × uint32_t
 * in bit-interleaved form. Alignment of 4 bytes is sufficient for 32-bit. */
#define KeccakP1600_implementation_plain32                                     \
  "32-bit optimized bit-interleaved implementation"
#define KeccakP1600_stateSizeInBytes_plain32 200
#define KeccakP1600_stateAlignment_plain32 4
#define KeccakF1600_FastLoop_supported_plain32

/* Unsuffixed aliases required by PlSnP-Fallback.inc (times4 serial wrapper).
 * JOIN(KeccakP1600, stateSizeInBytes, ) expands to KeccakP1600_stateSizeInBytes. */
#define KeccakP1600_implementation    KeccakP1600_implementation_plain32
#define KeccakP1600_stateSizeInBytes  KeccakP1600_stateSizeInBytes_plain32
#define KeccakP1600_stateAlignment    KeccakP1600_stateAlignment_plain32
#define KeccakF1600_FastLoop_supported KeccakF1600_FastLoop_supported_plain32

/* All symbols hardcoded with _plain32 suffix — no dist-build ADD_SYMBOL_SUFFIX
 * needed. */
#define KeccakP1600_StaticInitialize KeccakP1600_StaticInitialize_plain32
#define KeccakP1600_Initialize KeccakP1600_Initialize_plain32
#define KeccakP1600_AddByte KeccakP1600_AddByte_plain32
#define KeccakP1600_AddBytes KeccakP1600_AddBytes_plain32
#define KeccakP1600_OverwriteBytes KeccakP1600_OverwriteBytes_plain32
#define KeccakP1600_OverwriteWithZeroes KeccakP1600_OverwriteWithZeroes_plain32
#define KeccakP1600_Permute_Nrounds KeccakP1600_Permute_Nrounds_plain32
#define KeccakP1600_Permute_12rounds KeccakP1600_Permute_12rounds_plain32
#define KeccakP1600_Permute_24rounds KeccakP1600_Permute_24rounds_plain32
#define KeccakP1600_ExtractBytes KeccakP1600_ExtractBytes_plain32
#define KeccakP1600_ExtractAndAddBytes KeccakP1600_ExtractAndAddBytes_plain32
#define KeccakF1600_FastLoop_Absorb KeccakF1600_FastLoop_Absorb_plain32

void KeccakP1600_StaticInitialize_plain32(void);
void KeccakP1600_Initialize_plain32(void *state);
void KeccakP1600_AddByte_plain32(void *state, unsigned char data,
                                 unsigned int offset);
void KeccakP1600_AddBytes_plain32(void *state, const unsigned char *data,
                                  unsigned int offset, unsigned int length);
void KeccakP1600_OverwriteBytes_plain32(void *state, const unsigned char *data,
                                         unsigned int offset,
                                         unsigned int length);
void KeccakP1600_OverwriteWithZeroes_plain32(void *state,
                                             unsigned int byteCount);
void KeccakP1600_Permute_Nrounds_plain32(void *state, unsigned int nrounds);
void KeccakP1600_Permute_12rounds_plain32(void *state);
void KeccakP1600_Permute_24rounds_plain32(void *state);
void KeccakP1600_ExtractBytes_plain32(const void *state, unsigned char *data,
                                      unsigned int offset, unsigned int length);
void KeccakP1600_ExtractAndAddBytes_plain32(const void *state,
                                            const unsigned char *input,
                                            unsigned char *output,
                                            unsigned int offset,
                                            unsigned int length);
size_t KeccakF1600_FastLoop_Absorb_plain32(void *state, unsigned int laneCount,
                                           const unsigned char *data,
                                           size_t dataByteLen);

#endif /* _KeccakP_1600_plain32_SnP_h_ */

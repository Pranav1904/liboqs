/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_SYMMETRIC_H
#define MLD_SYMMETRIC_H

#include <stdint.h>
#include "cbmc.h"
#include "common.h"

#define LIBOQS_SHA_IMPLEMENTATION 1
#define MLD_USE_FIPS202_KYBER 1

#if LIBOQS_SHA_IMPLEMENTATION

#if defined(MLD_USE_FIPS202_KYBER)
/*
 * Use local fips202_kyber (SHAKE from Kyber ref). Only single-stream APIs
 * (mld_shake128_*, mld_shake256_*, mld_xof128_*, mld_xof256_*) are defined
 * here; mld_xof128_x4_* and mld_xof256_x4_* are not defined in this branch
 * (they exist only in the #else branch with MLD_FIPS202X4_HEADER_FILE).
 * Therefore matrix_expand must use the serial path: MLD_CONFIG_SERIAL_FIPS202_ONLY
 * is forced below so that all 40 matrix polys are expanded via mld_poly_uniform
 * -> mld_xof128_* -> fips202_kyber.c (no liboqs 4x code used).
 */
#ifndef MLD_CONFIG_SERIAL_FIPS202_ONLY
#define MLD_CONFIG_SERIAL_FIPS202_ONLY 1
#endif
#include "fips202_kyber.h"

/* 5 blocks per poly -> 40*5 = 200 Keccak permutes (match WolfSSL). Override any build -D so count is 200 not 150. */
#undef MLD_POLY_UNIFORM_NBLOCKS
#define MLD_POLY_UNIFORM_NBLOCKS 5

#define MLD_STREAM128_BLOCKBYTES SHAKE128_RATE
#define MLD_STREAM256_BLOCKBYTES SHAKE256_RATE

/* Map ML-DSA context types to fips202_kyber keccak_state */
#define mld_shake256ctx keccak_state
#define mld_shake128ctx keccak_state

/* SHAKE256 */
#define mld_shake256_init(CTX) shake256_init(CTX)
#define mld_shake256_absorb(CTX, IN, INBYTES) shake256_absorb((CTX), (IN), (INBYTES))
#define mld_shake256_finalize(CTX) shake256_finalize(CTX)
#define mld_shake256_squeeze(OUT, OUTLEN, STATE) shake256_squeeze((OUT), (OUTLEN), (STATE))
#define mld_shake256_release(CTX) ((void)(CTX))
#define mld_shake256(OUT, OUTLEN, IN, INLEN) shake256((OUT), (OUTLEN), (IN), (INLEN))

/* SHAKE128 */
#define mld_shake128_init(CTX) shake128_init(CTX)
#define mld_shake128_absorb(CTX, IN, INBYTES) shake128_absorb((CTX), (IN), (INBYTES))
#define mld_shake128_finalize(CTX) shake128_finalize(CTX)
#define mld_shake128_squeeze(OUT, OUTLEN, STATE) shake128_squeeze((OUT), (OUTLEN), (STATE))
#define mld_shake128_release(CTX) ((void)(CTX))

#define mld_xof256_ctx mld_shake256ctx
#define mld_xof256_init(CTX) mld_shake256_init(CTX)

#define mld_xof256_absorb_once(CTX, IN, INBYTES) \
  do                                             \
  {                                              \
    mld_shake256_absorb(CTX, IN, INBYTES);       \
    mld_shake256_finalize(CTX);                  \
  } while (0)

#define mld_xof256_release(CTX) mld_shake256_release(CTX)
#define mld_xof256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  mld_shake256_squeeze(OUT, (OUTBLOCKS) * SHAKE256_RATE, STATE)

#define mld_xof128_ctx mld_shake128ctx
#define mld_xof128_init(CTX) mld_shake128_init(CTX)

#define mld_xof128_absorb_once(CTX, IN, INBYTES) \
  do                                             \
  {                                              \
    mld_shake128_absorb(CTX, IN, INBYTES);       \
    mld_shake128_finalize(CTX);                  \
  } while (0)

#define mld_xof128_release(CTX) mld_shake128_release(CTX)
/* Use squeezeblocks so each call does exactly OUTBLOCKS Keccak permutes (200 for 40 polys * 5). */
#define mld_xof128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  shake128_squeezeblocks(OUT, (OUTBLOCKS), (STATE))

#else /* !MLD_USE_FIPS202_KYBER */
/* Use build-configured FIPS202 backend (e.g. liboqs fips202.h). */
#include MLD_FIPS202_HEADER_FILE
#if !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
#include MLD_FIPS202X4_HEADER_FILE
#endif

#define MLD_STREAM128_BLOCKBYTES SHAKE128_RATE
#define MLD_STREAM256_BLOCKBYTES SHAKE256_RATE

#define mld_xof256_ctx mld_shake256ctx
#define mld_xof256_init(CTX) mld_shake256_init(CTX)

#define mld_xof256_absorb_once(CTX, IN, INBYTES) \
  do                                             \
  {                                              \
    mld_shake256_absorb(CTX, IN, INBYTES);       \
    mld_shake256_finalize(CTX);                  \
  } while (0)


#define mld_xof256_release(CTX) mld_shake256_release(CTX)
#define mld_xof256_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  mld_shake256_squeeze(OUT, (OUTBLOCKS) * SHAKE256_RATE, STATE)

#define mld_xof128_ctx mld_shake128ctx
#define mld_xof128_init(CTX) mld_shake128_init(CTX)

#define mld_xof128_absorb_once(CTX, IN, INBYTES) \
  do                                             \
  {                                              \
    mld_shake128_absorb(CTX, IN, INBYTES);       \
    mld_shake128_finalize(CTX);                  \
  } while (0)

#define mld_xof128_release(CTX) mld_shake128_release(CTX)
#define mld_xof128_squeezeblocks(OUT, OUTBLOCKS, STATE) \
  mld_shake128_squeeze(OUT, (OUTBLOCKS) * SHAKE128_RATE, STATE)

#define mld_xof256_x4_ctx mld_shake256x4ctx
#define mld_xof256_x4_init(CTX) mld_shake256x4_init((CTX))
#define mld_xof256_x4_absorb(CTX, IN, INBYTES)                          \
  mld_shake256x4_absorb_once((CTX), (IN)[0], (IN)[1], (IN)[2], (IN)[3], \
                             (INBYTES))
#define mld_xof256_x4_squeezeblocks(BUF, NBLOCKS, CTX)                 \
  mld_shake256x4_squeezeblocks((BUF)[0], (BUF)[1], (BUF)[2], (BUF)[3], \
                               (NBLOCKS), (CTX))
#define mld_xof256_x4_release(CTX) mld_shake256x4_release((CTX))

#define mld_xof128_x4_ctx mld_shake128x4ctx
#define mld_xof128_x4_init(CTX) mld_shake128x4_init((CTX))
#define mld_xof128_x4_absorb(CTX, IN, INBYTES)                          \
  mld_shake128x4_absorb_once((CTX), (IN)[0], (IN)[1], (IN)[2], (IN)[3], \
                             (INBYTES))
#define mld_xof128_x4_squeezeblocks(BUF, NBLOCKS, CTX)                 \
  mld_shake128x4_squeezeblocks((BUF)[0], (BUF)[1], (BUF)[2], (BUF)[3], \
                               (NBLOCKS), (CTX))
#define mld_xof128_x4_release(CTX) mld_shake128x4_release((CTX))

#endif /* MLD_USE_FIPS202_KYBER */
#endif

#endif /* !MLD_SYMMETRIC_H */

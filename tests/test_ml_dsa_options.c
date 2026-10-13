/*
 * test_ml_dsa_options.c
 *
 * Exercises the ML-DSA key generation, signing and verification build
 * options through the generic OQS_SIG API. The program adapts to the
 * operations that were enabled at compile time, which are reported by the
 * OQS_ENABLE_SIG_ML_DSA_* macros in <oqs/oqsconfig.h>.
 *
 *   test_ml_dsa_options gen <pk> <sk> <sig>
 *       Make a key pair and sign a fixed message, then write the public key,
 *       secret key and signature to the given files. Needs every operation.
 *
 *   test_ml_dsa_options run <pk> <sk> <sig>
 *       Check that the enabled operations work and the disabled ones return
 *       OQS_ERROR. The files hold a key pair and signature from a build that
 *       has every operation, so a verify-only build can still be checked.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_ML_DSA_KEYPAIR)
#define HAS_KEYPAIR 1
#else
#define HAS_KEYPAIR 0
#endif

#if defined(OQS_ENABLE_SIG_ML_DSA_SIGN)
#define HAS_SIGN 1
#else
#define HAS_SIGN 0
#endif

#if defined(OQS_ENABLE_SIG_ML_DSA_VERIFY)
#define HAS_VERIFY 1
#else
#define HAS_VERIFY 0
#endif

static const uint8_t MESSAGE[] = "liboqs ML-DSA build option test";

// Read or write a whole file. Returns 1 on success and 0 on failure.
static int rw_file(const char *path, uint8_t *buf, size_t len, int write) {
	FILE *f = fopen(path, write ? "wb" : "rb");
	if (f == NULL) {
		return 0;
	}
	size_t n = write ? fwrite(buf, 1, len, f) : fread(buf, 1, len, f);
	fclose(f);
	return n == len;
}

// Report a mismatch between the expected and the actual status of an operation.
static int expect(const char *what, int enabled, OQS_STATUS status) {
	if ((status == OQS_SUCCESS) != enabled) {
		fprintf(stderr, "%s: expected %s, got %s\n", what,
		        enabled ? "OQS_SUCCESS" : "OQS_ERROR",
		        status == OQS_SUCCESS ? "OQS_SUCCESS" : "OQS_ERROR");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv) {
	int fail = 0;
	OQS_init();

	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
	if (sig == NULL) {
		fprintf(stderr, "OQS_SIG_new failed\n");
		OQS_destroy();
		return 2;
	}

	uint8_t *pk = OQS_MEM_malloc(sig->length_public_key);
	uint8_t *sk = OQS_MEM_malloc(sig->length_secret_key);
	uint8_t *signature = OQS_MEM_malloc(sig->length_signature);
	uint8_t *new_pk = OQS_MEM_malloc(sig->length_public_key);
	uint8_t *new_sk = OQS_MEM_malloc(sig->length_secret_key);
	uint8_t *new_signature = OQS_MEM_malloc(sig->length_signature);
	size_t sig_len = 0;

	if (pk == NULL || sk == NULL || signature == NULL ||
	        new_pk == NULL || new_sk == NULL || new_signature == NULL) {
		fprintf(stderr, "OQS_MEM_malloc failed\n");
		fail = 2;
		goto cleanup;
	}

	if (argc == 5 && strcmp(argv[1], "gen") == 0) {
#if HAS_KEYPAIR && HAS_SIGN
		fail |= OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS;
		fail |= OQS_SIG_sign(sig, signature, &sig_len, MESSAGE, sizeof(MESSAGE), sk) != OQS_SUCCESS;
		fail |= sig_len != sig->length_signature;
		fail |= !rw_file(argv[2], pk, sig->length_public_key, 1);
		fail |= !rw_file(argv[3], sk, sig->length_secret_key, 1);
		fail |= !rw_file(argv[4], signature, sig->length_signature, 1);
#else
		fprintf(stderr, "gen needs the keypair and sign operations\n");
		fail = 1;
#endif
	} else if (argc == 5 && strcmp(argv[1], "run") == 0) {
		// A disabled operation leaves its function pointer NULL.
		if ((sig->keypair != NULL) != HAS_KEYPAIR ||
		        (sig->sign != NULL) != HAS_SIGN || (sig->sign_with_ctx_str != NULL) != HAS_SIGN ||
		        (sig->verify != NULL) != HAS_VERIFY || (sig->verify_with_ctx_str != NULL) != HAS_VERIFY) {
			fprintf(stderr, "function pointers do not match the enabled operations\n");
			fail = 1;
		}

		// The key pair and the signature come from a build that has every operation.
		fail |= !rw_file(argv[2], pk, sig->length_public_key, 0);
		fail |= !rw_file(argv[3], sk, sig->length_secret_key, 0);
		fail |= !rw_file(argv[4], signature, sig->length_signature, 0);

		fail |= expect("OQS_SIG_keypair", HAS_KEYPAIR, OQS_SIG_keypair(sig, new_pk, new_sk));
		fail |= expect("OQS_SIG_sign", HAS_SIGN,
		               OQS_SIG_sign(sig, new_signature, &sig_len, MESSAGE, sizeof(MESSAGE), sk));
		fail |= expect("OQS_SIG_verify", HAS_VERIFY,
		               OQS_SIG_verify(sig, MESSAGE, sizeof(MESSAGE), signature, sig->length_signature, pk));
		if (HAS_SIGN && HAS_VERIFY) {
			fail |= expect("OQS_SIG_verify (new signature)", 1,
			               OQS_SIG_verify(sig, MESSAGE, sizeof(MESSAGE), new_signature, sig_len, pk));
		}
		if (HAS_VERIFY) {
			// A changed signature must still be rejected.
			signature[0] = (uint8_t)(signature[0] ^ 1);
			fail |= expect("OQS_SIG_verify (bad signature)", 0,
			               OQS_SIG_verify(sig, MESSAGE, sizeof(MESSAGE), signature, sig->length_signature, pk));
		}
	} else {
		fprintf(stderr, "usage: %s gen <pk> <sk> <sig> | run <pk> <sk> <sig>\n", argv[0]);
		fail = 1;
	}

cleanup:
	OQS_MEM_insecure_free(pk);
	OQS_MEM_secure_free(sk, sig->length_secret_key);
	OQS_MEM_insecure_free(signature);
	OQS_MEM_insecure_free(new_pk);
	OQS_MEM_secure_free(new_sk, sig->length_secret_key);
	OQS_MEM_insecure_free(new_signature);
	OQS_SIG_free(sig);
	OQS_destroy();
	return fail;
}

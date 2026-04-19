#include "openssl_vdf.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

struct vdfrsa_ctx {
  BIGNUM* modulus;
  BN_CTX* bn_ctx;
  BN_MONT_CTX* mont_ctx;
};

struct vdfrsa_prove_session {
  const vdfrsa_ctx* ctx;
  BIGNUM* x;
  BIGNUM* q;
};

static _Thread_local char vdfrsa_error[256];

static void vdfrsa_set_error(const char* message) {
  if (message == NULL) {
    message = "unknown error";
  }

  snprintf(vdfrsa_error, sizeof(vdfrsa_error), "%s", message);
}

static void vdfrsa_set_openssl_error(const char* prefix) {
  unsigned long err = ERR_get_error();
  if (err == 0) {
    vdfrsa_set_error(prefix);
    return;
  }

  char detail[160];
  ERR_error_string_n(err, detail, sizeof(detail));
  snprintf(vdfrsa_error, sizeof(vdfrsa_error), "%s: %s", prefix, detail);
}

static int vdfrsa_bn_from_bytes(const uint8_t* bytes,
                                size_t len,
                                BIGNUM** out,
                                const char* field_name) {
  if (bytes == NULL || out == NULL) {
    vdfrsa_set_error("invalid null pointer");
    return -1;
  }

  *out = BN_bin2bn(bytes, (int)len, NULL);
  if (*out == NULL) {
    vdfrsa_set_openssl_error(field_name);
    return -1;
  }
  return 0;
}

static int vdfrsa_take_bytes(BIGNUM* value, uint8_t** out, size_t* out_len) {
  if (value == NULL || out == NULL || out_len == NULL) {
    vdfrsa_set_error("invalid output pointer");
    return -1;
  }

  const int len = BN_num_bytes(value);
  const size_t safe_len = len > 0 ? (size_t)len : (size_t)1;
  uint8_t* buffer = (uint8_t*)malloc(safe_len);
  if (buffer == NULL) {
    vdfrsa_set_error("malloc failed");
    return -1;
  }

  if (len > 0) {
    BN_bn2bin(value, buffer);
  } else {
    buffer[0] = 0;
  }

  *out = buffer;
  *out_len = safe_len;
  return 0;
}

static void vdfrsa_write_u64_be(uint64_t value, uint8_t out[8]) {
  for (int i = 7; i >= 0; --i) {
    out[i] = (uint8_t)(value & 0xffu);
    value >>= 8;
  }
}

static void vdfrsa_write_u32_be(uint32_t value, uint8_t out[4]) {
  for (int i = 3; i >= 0; --i) {
    out[i] = (uint8_t)(value & 0xffu);
    value >>= 8;
  }
}

static int vdfrsa_expand_hash_to_int(int k,
                                     const char* domain,
                                     int64_t difficulty,
                                     const uint8_t* payload,
                                     size_t payload_len,
                                     const uint8_t* extra,
                                     size_t extra_len,
                                     BIGNUM** out) {
  if (k <= 0 || domain == NULL || payload == NULL || out == NULL ||
      difficulty < 0) {
    vdfrsa_set_error("invalid expand_hash_to_int arguments");
    return -1;
  }

  size_t byte_len = ((size_t)(2 * k) + 7u) >> 3u;
  if (byte_len < SHA256_DIGEST_LENGTH) {
    byte_len = SHA256_DIGEST_LENGTH;
  }

  uint8_t* buffer = (uint8_t*)malloc(byte_len);
  if (buffer == NULL) {
    vdfrsa_set_error("malloc failed");
    return -1;
  }

  uint8_t diff_bytes[8];
  vdfrsa_write_u64_be((uint64_t)difficulty, diff_bytes);

  size_t offset = 0;
  uint32_t counter = 0;
  while (offset < byte_len) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t counter_bytes[4];
    SHA256_CTX sha_ctx;
    vdfrsa_write_u32_be(counter, counter_bytes);

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, domain, strlen(domain));
    SHA256_Update(&sha_ctx, diff_bytes, sizeof(diff_bytes));
    SHA256_Update(&sha_ctx, payload, payload_len);
    if (extra != NULL && extra_len > 0) {
      SHA256_Update(&sha_ctx, extra, extra_len);
    }
    SHA256_Update(&sha_ctx, counter_bytes, sizeof(counter_bytes));
    SHA256_Final(digest, &sha_ctx);

    const size_t remaining = byte_len - offset;
    const size_t take =
        remaining < SHA256_DIGEST_LENGTH ? remaining : SHA256_DIGEST_LENGTH;
    memcpy(buffer + offset, digest, take);
    offset += take;
    counter++;
  }

  *out = BN_bin2bn(buffer, (int)byte_len, NULL);
  free(buffer);
  if (*out == NULL) {
    vdfrsa_set_openssl_error("BN_bin2bn");
    return -1;
  }
  return 0;
}

static int vdfrsa_input_from_payload(const BIGNUM* modulus,
                                     BN_CTX* bn_ctx,
                                     int k,
                                     const uint8_t* payload,
                                     size_t payload_len,
                                     BIGNUM** out) {
  BIGNUM* value = NULL;
  int rc = -1;

  if (vdfrsa_expand_hash_to_int(k, "rsavdf:x:v1", 0, payload, payload_len, NULL,
                                0, &value) != 0) {
    goto cleanup;
  }

  if (BN_mod(value, value, modulus, bn_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_mod");
    goto cleanup;
  }
  if (BN_is_zero(value)) {
    if (BN_one(value) != 1) {
      vdfrsa_set_openssl_error("BN_one");
      goto cleanup;
    }
  }

  *out = value;
  value = NULL;
  rc = 0;

cleanup:
  if (value != NULL) {
    BN_free(value);
  }
  return rc;
}

static int vdfrsa_next_prime(const BIGNUM* n, BN_CTX* bn_ctx, BIGNUM** out) {
  BIGNUM* candidate = NULL;
  BIGNUM* two = NULL;
  int rc = -1;

  candidate = BN_dup(n);
  two = BN_new();
  if (candidate == NULL || two == NULL) {
    vdfrsa_set_openssl_error("BN_dup/BN_new");
    goto cleanup;
  }
  if (BN_set_word(two, 2) != 1) {
    vdfrsa_set_openssl_error("BN_set_word");
    goto cleanup;
  }

  if (BN_cmp(candidate, two) < 0) {
    if (BN_set_word(candidate, 2) != 1) {
      vdfrsa_set_openssl_error("BN_set_word");
      goto cleanup;
    }
  } else if (!BN_is_word(candidate, 2) && !BN_is_odd(candidate)) {
    if (BN_add(candidate, candidate, BN_value_one()) != 1) {
      vdfrsa_set_openssl_error("BN_add");
      goto cleanup;
    }
  }

  while (1) {
    const int is_prime = BN_check_prime(candidate, bn_ctx, NULL);
    if (is_prime == 1) {
      *out = candidate;
      candidate = NULL;
      rc = 0;
      goto cleanup;
    }
    if (ERR_peek_error() != 0) {
      vdfrsa_set_openssl_error("BN_check_prime");
      goto cleanup;
    }
    if (BN_add(candidate, candidate, two) != 1) {
      vdfrsa_set_openssl_error("BN_add");
      goto cleanup;
    }
  }

cleanup:
  if (candidate != NULL) {
    BN_free(candidate);
  }
  if (two != NULL) {
    BN_free(two);
  }
  return rc;
}

static int vdfrsa_prime_from_statement(int k,
                                       int64_t difficulty,
                                       const uint8_t* payload,
                                       size_t payload_len,
                                       const uint8_t* output,
                                       size_t output_len,
                                       BN_CTX* bn_ctx,
                                       BIGNUM** out) {
  BIGNUM* seed = NULL;
  int rc = -1;

  if (vdfrsa_expand_hash_to_int(k, "rsavdf:l:v1", difficulty, payload,
                                payload_len, output, output_len, &seed) != 0) {
    goto cleanup;
  }

  rc = vdfrsa_next_prime(seed, bn_ctx, out);

cleanup:
  if (seed != NULL) {
    BN_free(seed);
  }
  return rc;
}

static int64_t vdfrsa_estimate_exp_work_from_bitlen(int bit_len) {
  if (bit_len <= 1) {
    return 1;
  }

  const int64_t squarings = (int64_t)bit_len - 1;
  const int64_t expected_multiplies = ((int64_t)bit_len + 1) / 2;
  return squarings + expected_multiplies;
}

static int vdfrsa_pow2_mod(const BIGNUM* base,
                           int64_t squarings,
                           const BIGNUM* modulus,
                           BN_MONT_CTX* mont_ctx,
                           BN_CTX* bn_ctx,
                           BIGNUM** out) {
  BIGNUM* reduced = NULL;
  BIGNUM* mont_value = NULL;
  BIGNUM* value = NULL;
  int rc = -1;

  if (squarings < 0) {
    vdfrsa_set_error("difficulty must be non-negative");
    return -1;
  }

  reduced = BN_new();
  mont_value = BN_new();
  value = BN_new();
  if (reduced == NULL || mont_value == NULL || value == NULL) {
    vdfrsa_set_openssl_error("BN_new");
    goto cleanup;
  }

  if (BN_nnmod(reduced, base, modulus, bn_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_nnmod");
    goto cleanup;
  }
  if (squarings == 0) {
    if (BN_copy(value, reduced) == NULL) {
      vdfrsa_set_openssl_error("BN_copy");
      goto cleanup;
    }
  } else {
    if (BN_to_montgomery(mont_value, reduced, mont_ctx, bn_ctx) != 1) {
      vdfrsa_set_openssl_error("BN_to_montgomery");
      goto cleanup;
    }
    for (int64_t i = 0; i < squarings; ++i) {
      if (BN_mod_mul_montgomery(mont_value, mont_value, mont_value, mont_ctx,
                                bn_ctx) != 1) {
        vdfrsa_set_openssl_error("BN_mod_mul_montgomery");
        goto cleanup;
      }
    }
    if (BN_from_montgomery(value, mont_value, mont_ctx, bn_ctx) != 1) {
      vdfrsa_set_openssl_error("BN_from_montgomery");
      goto cleanup;
    }
  }

  *out = value;
  value = NULL;
  rc = 0;

cleanup:
  if (reduced != NULL) {
    BN_free(reduced);
  }
  if (mont_value != NULL) {
    BN_free(mont_value);
  }
  if (value != NULL) {
    BN_free(value);
  }
  return rc;
}

vdfrsa_ctx* vdfrsa_ctx_new(const uint8_t* modulus, size_t modulus_len) {
  vdfrsa_ctx* ctx = NULL;

  ctx = (vdfrsa_ctx*)calloc(1, sizeof(vdfrsa_ctx));
  if (ctx == NULL) {
    vdfrsa_set_error("calloc failed");
    return NULL;
  }

  if (vdfrsa_bn_from_bytes(modulus, modulus_len, &ctx->modulus, "modulus") !=
      0) {
    vdfrsa_ctx_free(ctx);
    return NULL;
  }

  ctx->bn_ctx = BN_CTX_new();
  ctx->mont_ctx = BN_MONT_CTX_new();
  if (ctx->bn_ctx == NULL || ctx->mont_ctx == NULL) {
    vdfrsa_set_openssl_error("BN_CTX_new/BN_MONT_CTX_new");
    vdfrsa_ctx_free(ctx);
    return NULL;
  }
  if (BN_MONT_CTX_set(ctx->mont_ctx, ctx->modulus, ctx->bn_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_MONT_CTX_set");
    vdfrsa_ctx_free(ctx);
    return NULL;
  }

  return ctx;
}

void vdfrsa_ctx_free(vdfrsa_ctx* ctx) {
  if (ctx == NULL) {
    return;
  }

  if (ctx->modulus != NULL) {
    BN_free(ctx->modulus);
  }
  if (ctx->bn_ctx != NULL) {
    BN_CTX_free(ctx->bn_ctx);
  }
  if (ctx->mont_ctx != NULL) {
    BN_MONT_CTX_free(ctx->mont_ctx);
  }
  free(ctx);
}

int vdfrsa_ctx_mod_pow(const vdfrsa_ctx* ctx,
                       const uint8_t* base,
                       size_t base_len,
                       const uint8_t* exponent,
                       size_t exponent_len,
                       uint8_t** out,
                       size_t* out_len) {
  BIGNUM* base_bn = NULL;
  BIGNUM* exp_bn = NULL;
  BIGNUM* result = NULL;
  int rc = -1;

  if (ctx == NULL || ctx->modulus == NULL || ctx->bn_ctx == NULL ||
      ctx->mont_ctx == NULL) {
    vdfrsa_set_error("invalid modulus context");
    return -1;
  }

  if (vdfrsa_bn_from_bytes(base, base_len, &base_bn, "base") != 0) {
    goto cleanup;
  }
  if (vdfrsa_bn_from_bytes(exponent, exponent_len, &exp_bn, "exponent") != 0) {
    goto cleanup;
  }

  result = BN_new();
  if (result == NULL) {
    vdfrsa_set_openssl_error("BN_new");
    goto cleanup;
  }

  if (BN_mod_exp_mont(result, base_bn, exp_bn, ctx->modulus, ctx->bn_ctx,
                      ctx->mont_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_mod_exp_mont");
    goto cleanup;
  }

  rc = vdfrsa_take_bytes(result, out, out_len);

cleanup:
  if (base_bn != NULL) {
    BN_free(base_bn);
  }
  if (exp_bn != NULL) {
    BN_free(exp_bn);
  }
  if (result != NULL) {
    BN_free(result);
  }
  return rc;
}

int vdfrsa_ctx_prove(const vdfrsa_ctx* ctx,
                     int k,
                     const uint8_t* payload,
                     size_t payload_len,
                     int64_t difficulty,
                     uint8_t** out_y,
                     size_t* out_y_len,
                     uint8_t** out_pi,
                     size_t* out_pi_len) {
  BN_CTX* bn_ctx = NULL;
  BIGNUM* x = NULL;
  BIGNUM* y = NULL;
  BIGNUM* l = NULL;
  BIGNUM* exp = NULL;
  BIGNUM* q = NULL;
  BIGNUM* pi = NULL;
  int rc = -1;

  if (ctx == NULL || ctx->modulus == NULL || ctx->mont_ctx == NULL ||
      payload == NULL || out_y == NULL || out_y_len == NULL ||
      out_pi == NULL || out_pi_len == NULL) {
    vdfrsa_set_error("invalid prove arguments");
    return -1;
  }
  if (difficulty < 0) {
    vdfrsa_set_error("difficulty must be non-negative");
    return -1;
  }
  if (difficulty > INT_MAX) {
    vdfrsa_set_error("difficulty too large for native fast path");
    return -1;
  }

  *out_y = NULL;
  *out_y_len = 0;
  *out_pi = NULL;
  *out_pi_len = 0;

  bn_ctx = BN_CTX_new();
  if (bn_ctx == NULL) {
    vdfrsa_set_openssl_error("BN_CTX_new");
    goto cleanup;
  }

  if (vdfrsa_input_from_payload(ctx->modulus, bn_ctx, k, payload, payload_len,
                                &x) != 0) {
    goto cleanup;
  }
  if (vdfrsa_pow2_mod(x, difficulty, ctx->modulus, ctx->mont_ctx, bn_ctx,
                      &y) != 0) {
    goto cleanup;
  }
  if (vdfrsa_take_bytes(y, out_y, out_y_len) != 0) {
    goto cleanup;
  }

  if (vdfrsa_prime_from_statement(k, difficulty, payload, payload_len, *out_y,
                                  *out_y_len, bn_ctx, &l) != 0) {
    goto cleanup;
  }

  exp = BN_new();
  q = BN_new();
  pi = BN_new();
  if (exp == NULL || q == NULL || pi == NULL) {
    vdfrsa_set_openssl_error("BN_new");
    goto cleanup;
  }

  if (BN_set_word(exp, 0) != 1 || BN_set_bit(exp, (int)difficulty) != 1) {
    vdfrsa_set_openssl_error("BN_set_word/BN_set_bit");
    goto cleanup;
  }
  if (BN_div(q, NULL, exp, l, bn_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_div");
    goto cleanup;
  }
  if (BN_mod_exp_mont(pi, x, q, ctx->modulus, bn_ctx, ctx->mont_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_mod_exp_mont");
    goto cleanup;
  }
  if (vdfrsa_take_bytes(pi, out_pi, out_pi_len) != 0) {
    goto cleanup;
  }

  rc = 0;

cleanup:
  if (rc != 0) {
    if (*out_y != NULL) {
      free(*out_y);
      *out_y = NULL;
      *out_y_len = 0;
    }
    if (*out_pi != NULL) {
      free(*out_pi);
      *out_pi = NULL;
      *out_pi_len = 0;
    }
  }
  if (x != NULL) {
    BN_free(x);
  }
  if (y != NULL) {
    BN_free(y);
  }
  if (l != NULL) {
    BN_free(l);
  }
  if (exp != NULL) {
    BN_free(exp);
  }
  if (q != NULL) {
    BN_free(q);
  }
  if (pi != NULL) {
    BN_free(pi);
  }
  if (bn_ctx != NULL) {
    BN_CTX_free(bn_ctx);
  }
  return rc;
}

int vdfrsa_ctx_prove_stage1(const vdfrsa_ctx* ctx,
                            int k,
                            const uint8_t* payload,
                            size_t payload_len,
                            int64_t difficulty,
                            vdfrsa_prove_session** out_session,
                            uint8_t** out_y,
                            size_t* out_y_len,
                            int64_t* out_second_work) {
  BN_CTX* bn_ctx = NULL;
  BIGNUM* x = NULL;
  BIGNUM* y = NULL;
  BIGNUM* l = NULL;
  BIGNUM* exp = NULL;
  BIGNUM* q = NULL;
  vdfrsa_prove_session* session = NULL;
  int rc = -1;

  if (ctx == NULL || ctx->modulus == NULL || ctx->mont_ctx == NULL ||
      payload == NULL || out_session == NULL || out_y == NULL ||
      out_y_len == NULL || out_second_work == NULL) {
    vdfrsa_set_error("invalid stage1 arguments");
    return -1;
  }
  if (difficulty < 0) {
    vdfrsa_set_error("difficulty must be non-negative");
    return -1;
  }
  if (difficulty > INT_MAX) {
    vdfrsa_set_error("difficulty too large for native fast path");
    return -1;
  }

  *out_session = NULL;
  *out_y = NULL;
  *out_y_len = 0;
  *out_second_work = 1;

  bn_ctx = BN_CTX_new();
  if (bn_ctx == NULL) {
    vdfrsa_set_openssl_error("BN_CTX_new");
    goto cleanup;
  }

  if (vdfrsa_input_from_payload(ctx->modulus, bn_ctx, k, payload, payload_len,
                                &x) != 0) {
    goto cleanup;
  }
  if (vdfrsa_pow2_mod(x, difficulty, ctx->modulus, ctx->mont_ctx, bn_ctx,
                      &y) != 0) {
    goto cleanup;
  }
  if (vdfrsa_take_bytes(y, out_y, out_y_len) != 0) {
    goto cleanup;
  }
  if (vdfrsa_prime_from_statement(k, difficulty, payload, payload_len, *out_y,
                                  *out_y_len, bn_ctx, &l) != 0) {
    goto cleanup;
  }

  exp = BN_new();
  q = BN_new();
  if (exp == NULL || q == NULL) {
    vdfrsa_set_openssl_error("BN_new");
    goto cleanup;
  }
  if (BN_set_word(exp, 0) != 1 || BN_set_bit(exp, (int)difficulty) != 1) {
    vdfrsa_set_openssl_error("BN_set_word/BN_set_bit");
    goto cleanup;
  }
  if (BN_div(q, NULL, exp, l, bn_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_div");
    goto cleanup;
  }

  session = (vdfrsa_prove_session*)calloc(1, sizeof(vdfrsa_prove_session));
  if (session == NULL) {
    vdfrsa_set_error("calloc failed");
    goto cleanup;
  }
  session->ctx = ctx;
  session->x = x;
  session->q = q;
  x = NULL;
  q = NULL;

  *out_second_work = vdfrsa_estimate_exp_work_from_bitlen(BN_num_bits(session->q));
  *out_session = session;
  session = NULL;
  rc = 0;

cleanup:
  if (rc != 0 && *out_y != NULL) {
    free(*out_y);
    *out_y = NULL;
    *out_y_len = 0;
  }
  if (session != NULL) {
    vdfrsa_prove_session_free(session);
  }
  if (x != NULL) {
    BN_free(x);
  }
  if (y != NULL) {
    BN_free(y);
  }
  if (l != NULL) {
    BN_free(l);
  }
  if (exp != NULL) {
    BN_free(exp);
  }
  if (q != NULL) {
    BN_free(q);
  }
  if (bn_ctx != NULL) {
    BN_CTX_free(bn_ctx);
  }
  return rc;
}

int vdfrsa_prove_session_finish(vdfrsa_prove_session* session,
                                uint8_t** out_pi,
                                size_t* out_pi_len) {
  BIGNUM* pi = NULL;
  int rc = -1;

  if (session == NULL || session->ctx == NULL || session->ctx->modulus == NULL ||
      session->ctx->mont_ctx == NULL || session->x == NULL || session->q == NULL ||
      out_pi == NULL || out_pi_len == NULL) {
    vdfrsa_set_error("invalid prove session");
    return -1;
  }

  *out_pi = NULL;
  *out_pi_len = 0;

  pi = BN_new();
  if (pi == NULL) {
    vdfrsa_set_openssl_error("BN_new");
    goto cleanup;
  }
  if (BN_mod_exp_mont(pi, session->x, session->q, session->ctx->modulus,
                      session->ctx->bn_ctx, session->ctx->mont_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_mod_exp_mont");
    goto cleanup;
  }
  if (vdfrsa_take_bytes(pi, out_pi, out_pi_len) != 0) {
    goto cleanup;
  }

  rc = 0;

cleanup:
  if (pi != NULL) {
    BN_free(pi);
  }
  return rc;
}

void vdfrsa_prove_session_free(vdfrsa_prove_session* session) {
  if (session == NULL) {
    return;
  }
  if (session->x != NULL) {
    BN_free(session->x);
  }
  if (session->q != NULL) {
    BN_free(session->q);
  }
  free(session);
}

int vdfrsa_quotient(const uint8_t* dividend,
                    size_t dividend_len,
                    const uint8_t* divisor,
                    size_t divisor_len,
                    uint8_t** out,
                    size_t* out_len) {
  BIGNUM* dividend_bn = NULL;
  BIGNUM* divisor_bn = NULL;
  BIGNUM* quotient = NULL;
  BN_CTX* bn_ctx = NULL;
  int rc = -1;

  if (vdfrsa_bn_from_bytes(dividend, dividend_len, &dividend_bn, "dividend") !=
      0) {
    goto cleanup;
  }
  if (vdfrsa_bn_from_bytes(divisor, divisor_len, &divisor_bn, "divisor") != 0) {
    goto cleanup;
  }

  if (BN_is_zero(divisor_bn)) {
    vdfrsa_set_error("division by zero");
    goto cleanup;
  }

  quotient = BN_new();
  bn_ctx = BN_CTX_new();
  if (quotient == NULL || bn_ctx == NULL) {
    vdfrsa_set_openssl_error("BN_new/BN_CTX_new");
    goto cleanup;
  }

  if (BN_div(quotient, NULL, dividend_bn, divisor_bn, bn_ctx) != 1) {
    vdfrsa_set_openssl_error("BN_div");
    goto cleanup;
  }

  rc = vdfrsa_take_bytes(quotient, out, out_len);

cleanup:
  if (dividend_bn != NULL) {
    BN_free(dividend_bn);
  }
  if (divisor_bn != NULL) {
    BN_free(divisor_bn);
  }
  if (quotient != NULL) {
    BN_free(quotient);
  }
  if (bn_ctx != NULL) {
    BN_CTX_free(bn_ctx);
  }
  return rc;
}

void vdfrsa_buffer_free(uint8_t* buffer) {
  free(buffer);
}

const char* vdfrsa_last_error(void) {
  if (vdfrsa_error[0] == '\0') {
    return "native backend call failed";
  }
  return vdfrsa_error;
}

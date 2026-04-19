#ifndef VDFRSA_OPENSSL_VDF_H_
#define VDFRSA_OPENSSL_VDF_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vdfrsa_ctx vdfrsa_ctx;
typedef struct vdfrsa_prove_session vdfrsa_prove_session;

vdfrsa_ctx* vdfrsa_ctx_new(const uint8_t* modulus, size_t modulus_len);
void vdfrsa_ctx_free(vdfrsa_ctx* ctx);

int vdfrsa_ctx_mod_pow(
    const vdfrsa_ctx* ctx,
    const uint8_t* base,
    size_t base_len,
    const uint8_t* exponent,
    size_t exponent_len,
    uint8_t** out,
    size_t* out_len);

int vdfrsa_ctx_prove(
    const vdfrsa_ctx* ctx,
    int k,
    const uint8_t* payload,
    size_t payload_len,
    int64_t difficulty,
    uint8_t** out_y,
    size_t* out_y_len,
    uint8_t** out_pi,
    size_t* out_pi_len);

int vdfrsa_ctx_prove_stage1(
    const vdfrsa_ctx* ctx,
    int k,
    const uint8_t* payload,
    size_t payload_len,
    int64_t difficulty,
    vdfrsa_prove_session** out_session,
    uint8_t** out_y,
    size_t* out_y_len,
    int64_t* out_second_work);

int vdfrsa_prove_session_finish(
    vdfrsa_prove_session* session,
    uint8_t** out_pi,
    size_t* out_pi_len);

void vdfrsa_prove_session_free(vdfrsa_prove_session* session);

int vdfrsa_quotient(
    const uint8_t* dividend,
    size_t dividend_len,
    const uint8_t* divisor,
    size_t divisor_len,
    uint8_t** out,
    size_t* out_len);

void vdfrsa_buffer_free(uint8_t* buffer);
const char* vdfrsa_last_error(void);

#ifdef __cplusplus
}
#endif

#endif

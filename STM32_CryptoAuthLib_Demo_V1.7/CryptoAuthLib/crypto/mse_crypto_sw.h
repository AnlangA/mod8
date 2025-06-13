/**
 * \file
 * \brief Common defines for CryptoAuthLib software crypto wrappers.
 *
 * \copyright (c) 2020-2025 ModSemi Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use ModSemi software
 * and any derivatives exclusively with ModSemi products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany ModSemi software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MODMEMI "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MODMEMI BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MODMEMI HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MODMEMI'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MODMEMI FOR
 * THIS SOFTWARE.
 */

#ifndef MSE_CRYPTO_SW_H
#define MSE_CRYPTO_SW_H

#include <stdint.h>
#include <stdlib.h>

#include "mse_config.h"
#include "mse_status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MSE_SHA1_DIGEST_SIZE       (20)
#define MSE_SHA2_256_DIGEST_SIZE   (32)
#define MSE_SHA2_256_BLOCK_SIZE    (64)

#ifndef MSE_ENABLE_SHA1_IMPL
#define MSE_ENABLE_SHA1_IMPL       1
#endif

#ifndef MSE_ENABLE_SHA256_IMPL
#define MSE_ENABLE_SHA256_IMPL     1
#endif

#ifndef MSE_ENABLE_RAND_IMPL
#define MSE_ENABLE_RAND_IMPL       1
#endif

typedef struct
{
    uint32_t pad[32]; //!< Filler value to make sure the actual implementation has enough room to store its context. uint32_t is used to remove some alignment warnings.
} mcac_sha1_ctx;

typedef struct
{
    uint32_t pad[48]; //!< Filler value to make sure the actual implementation has enough room to store its context. uint32_t is used to remove some alignment warnings.
} mcac_sha2_256_ctx;

typedef struct
{
    mcac_sha2_256_ctx sha256_ctx;
    uint8_t            ipad[MSE_SHA2_256_BLOCK_SIZE];
    uint8_t            opad[MSE_SHA2_256_BLOCK_SIZE];
} mcac_hmac_sha256_ctx;

typedef struct
{
    void *ptr;
} mca_evp_ctx;
typedef mca_evp_ctx mcac_pk_ctx;

MSE_STATUS mcac_pbkdf2_sha256(const uint32_t iter, const uint8_t* password, const size_t password_len, const uint8_t* salt, const size_t salt_len, uint8_t* result, size_t result_len);
MSE_STATUS mcac_pk_init(mcac_pk_ctx *ctx, uint8_t *buf, size_t buflen, uint8_t key_type, bool pubkey);
// MSE_STATUS mcac_pk_init_pem(mcac_pk_ctx *ctx, uint8_t *buf, size_t buflen, bool pubkey);
MSE_STATUS mcac_pk_free(mcac_pk_ctx *ctx);

MSE_STATUS mcac_pk_verify(mcac_pk_ctx *ctx, uint8_t *digest, size_t dig_len, uint8_t *signature, size_t sig_len);


#ifdef __cplusplus
}
#endif

#endif /* MSE_CRYPTO_SW_H */

/**
 * \file
 * \brief  Wrapper API for software SHA 256 routines
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

#ifndef MSE_CRYPTO_SW_SHA2_H
#define MSE_CRYPTO_SW_SHA2_H

#include "mse_crypto_sw.h"
#include <stddef.h>
#include <stdint.h>

/** \defgroup mcac_ Software crypto methods (mcac_)
 *
 * \brief
 * These methods provide a software implementation of various crypto
 * algorithms
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

int mcac_sw_sha2_256_init(mcac_sha2_256_ctx *ctx);
int mcac_sw_sha2_256_update(mcac_sha2_256_ctx *ctx, const uint8_t *data, size_t data_size);
int mcac_sw_sha2_256_finish(mcac_sha2_256_ctx *ctx, uint8_t digest[MSE_SHA2_256_DIGEST_SIZE]);
int mcac_sw_sha2_256(const uint8_t *data, size_t data_size, uint8_t digest[MSE_SHA2_256_DIGEST_SIZE]);

MSE_STATUS mcac_sha256_hmac_init(mcac_hmac_sha256_ctx *ctx, const uint8_t *key, const uint8_t key_len);
MSE_STATUS mcac_sha256_hmac_update(mcac_hmac_sha256_ctx *ctx, const uint8_t *data, size_t data_size);
MSE_STATUS mcac_sha256_hmac_finish(mcac_hmac_sha256_ctx *ctx, uint8_t *digest, size_t *digest_len);
MSE_STATUS mcac_sha256_hmac_counter(mcac_hmac_sha256_ctx *ctx, uint8_t *label, size_t label_len, uint8_t *data,
                                    size_t data_len, uint8_t *digest, size_t diglen);
MSE_STATUS mcac_sw_sha256_hmac(const uint8_t *data, size_t data_size, const uint8_t *key, const uint8_t key_size,
                               uint8_t digest[MSE_SHA2_256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

/** @} */
#endif

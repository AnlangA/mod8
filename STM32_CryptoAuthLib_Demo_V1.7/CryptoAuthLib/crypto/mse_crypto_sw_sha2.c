/**
 * \file
 * \brief Wrapper API for software SHA 256 routines
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

#include "cryptoauthlib.h"
#include "mse_crypto_sw_sha2.h"
#include "hashes/sha2_routines.h"

#if MSE_ENABLE_SHA256_IMPL
/** \brief initializes the SHA256 software
 * \param[in] ctx  ptr to context data structure
 * \return MSE_SUCCESS on success, otherwise an error code.
 */

int mcac_sw_sha2_256_init(mcac_sha2_256_ctx *ctx)
{
    if (sizeof(sw_sha256_ctx) > sizeof(mcac_sha2_256_ctx))
    {
        return MSE_ASSERT_FAILURE; // mcac_sha1_ctx isn't large enough for this implementation
    }
    sw_sha256_init((sw_sha256_ctx *)ctx);

    return MSE_SUCCESS;
}

/** \brief updates the running hash with the next block of data, called iteratively for the entire
    stream of data to be hashed using the SHA256 software
    \param[in] ctx        ptr to SHA context data structure
    \param[in] data       ptr to next block of data to hash
    \param[in] data_size  size amount of data to hash in the given block, in bytes
    \return MSE_SUCCESS
 */

int mcac_sw_sha2_256_update(mcac_sha2_256_ctx *ctx, const uint8_t *data, size_t data_size)
{
    sw_sha256_update((sw_sha256_ctx *)ctx, data, (uint32_t)data_size);

    return MSE_SUCCESS;
}

/** \brief completes the final SHA256 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 256
 * \return MSE_SUCCESS
 */

int mcac_sw_sha2_256_finish(mcac_sha2_256_ctx *ctx, uint8_t digest[MSE_SHA2_256_DIGEST_SIZE])
{
    sw_sha256_final((sw_sha256_ctx *)ctx, digest);

    return MSE_SUCCESS;
}

/** \brief Initialize context for performing HMAC (sha256) in software.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_sha256_hmac_init(mcac_hmac_sha256_ctx *ctx, /**< [in] pointer to a sha256-hmac context */
                                 const uint8_t *key,        /**< [in] key value to use */
                                 const uint8_t key_len      /**< [in] length of the key */
)
{
    MSE_STATUS status = MSE_BAD_PARAM;
    size_t klen = key_len;

    if (ctx && key && key_len)
    {
        if (klen <= MSE_SHA2_256_BLOCK_SIZE)
        {
            memcpy(ctx->ipad, key, klen);
            status = MSE_SUCCESS;
        }
        else
        {
            (void)mcac_sw_sha2_256_init(&ctx->sha256_ctx);
            (void)mcac_sw_sha2_256_update(&ctx->sha256_ctx, key, klen);
            status = (MSE_STATUS)mcac_sw_sha2_256_finish(&ctx->sha256_ctx, ctx->ipad);
            klen = MSE_SHA2_256_DIGEST_SIZE;
        }

        if (MSE_SUCCESS == status)
        {
            int i;
            if (klen < MSE_SHA2_256_BLOCK_SIZE)
            {
                memset(&ctx->ipad[klen], 0, MSE_SHA2_256_BLOCK_SIZE - klen);
            }

            for (i = 0; i < MSE_SHA2_256_BLOCK_SIZE; i++)
            {
                ctx->opad[i] = ctx->ipad[i] ^ 0x5C;
                ctx->ipad[i] ^= 0x36;
            }

            (void)mcac_sw_sha2_256_init(&ctx->sha256_ctx);
            status = (MSE_STATUS)mcac_sw_sha2_256_update(&ctx->sha256_ctx, ctx->ipad, MSE_SHA2_256_BLOCK_SIZE);
        }
    }

    return status;
}

/** \brief Update HMAC context with input data
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_sha256_hmac_update(mcac_hmac_sha256_ctx *ctx, /**< [in] pointer to a sha256-hmac context */
                                   const uint8_t *data,       /**< [in] input data */
                                   size_t data_size           /**< [in] length of input data */
)
{
    return (MSE_STATUS)mcac_sw_sha2_256_update(&ctx->sha256_ctx, data, data_size);
}

/** \brief Finish HMAC calculation and clear the HMAC context
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_sha256_hmac_finish(mcac_hmac_sha256_ctx *ctx, /**< [in] pointer to a sha256-hmac context */
                                   uint8_t *digest,           /**< [out] hmac value */
                                   size_t *digest_len         /**< [inout] length of hmac */
)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (ctx)
    {
        uint8_t temp_dig[MSE_SHA2_256_DIGEST_SIZE];

        status = (MSE_STATUS)mcac_sw_sha2_256_finish(&ctx->sha256_ctx, temp_dig);

        if (MSE_SUCCESS == status)
        {
            (void)mcac_sw_sha2_256_init(&ctx->sha256_ctx);
            (void)mcac_sw_sha2_256_update(&ctx->sha256_ctx, ctx->opad, MSE_SHA2_256_BLOCK_SIZE);
            (void)mcac_sw_sha2_256_update(&ctx->sha256_ctx, temp_dig, MSE_SHA2_256_DIGEST_SIZE);
            status = (MSE_STATUS)mcac_sw_sha2_256_finish(&ctx->sha256_ctx, digest);
        }
    }
    return status;
}

#endif /* MSE_ENABLE_SHA256_IMPL */

/** \brief single call convenience function which computes Hash of given data using SHA256 software
 * \param[in]  data       pointer to stream of data to hash
 * \param[in]  data_size  size of data stream to hash
 * \param[out] digest     result
 * \return MSE_SUCCESS on success, otherwise an error code.
 */

int mcac_sw_sha2_256(const uint8_t *data, size_t data_size, uint8_t digest[MSE_SHA2_256_DIGEST_SIZE])
{
    int ret;
    mcac_sha2_256_ctx ctx;

    ret = mcac_sw_sha2_256_init(&ctx);
    if (ret != MSE_SUCCESS)
    {
        return ret;
    }

    ret = mcac_sw_sha2_256_update(&ctx, data, data_size);
    if (ret != MSE_SUCCESS)
    {
        return ret;
    }

    ret = mcac_sw_sha2_256_finish(&ctx, digest);
    if (ret != MSE_SUCCESS)
    {
        return ret;
    }

    return MSE_SUCCESS;
}

/** \brief Implements SHA256 HMAC-Counter per  NIST SP 800-108 used for KDF like operations */
// MSE_STATUS mcac_sha256_hmac_counter(mcac_hmac_sha256_ctx *ctx, uint8_t *label, size_t label_len, uint8_t *data,
//                                     size_t data_len, uint8_t *digest, size_t diglen)
// {
//     MSE_STATUS ret = MSE_GEN_FAIL;

//     if (ctx)
//     {
//         uint32_t tmp = 1;

//         (void)mcac_sha256_hmac_update(ctx, (uint8_t *)&tmp, 1);
//         (void)mcac_sha256_hmac_update(ctx, label, label_len);

//         tmp = 0;
//         (void)mcac_sha256_hmac_update(ctx, (uint8_t *)&tmp, 1);
//         (void)mcac_sha256_hmac_update(ctx, data, data_len);

//         tmp = MSE_UINT16_HOST_TO_BE(diglen);
//         (void)mcac_sha256_hmac_update(ctx, (uint8_t *)&tmp, 2);

//         ret = mcac_sha256_hmac_finish(ctx, digest, &diglen);
//     }
//     return ret;
// }

/** \brief single call convenience function which computes Hash of given data using SHA256 software
 * \param[in]  data       pointer to stream of data to hash
 * \param[in]  data_size  size of data stream to hash
 * \param[in]  key        key value to use
 * \param[in]  key_size   size of the key
 * \param[out] digest     result
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_sw_sha256_hmac(const uint8_t *data, size_t data_size, const uint8_t *key, const uint8_t key_size,
                               uint8_t digest[MSE_SHA2_256_DIGEST_SIZE])
{
    MSE_STATUS ret = MSE_GEN_FAIL;
    mcac_hmac_sha256_ctx ctx;
    size_t digest_len;

    ret = mcac_sha256_hmac_init(&ctx, key, key_size);
    if (ret != MSE_SUCCESS)
    {
        return ret;
    }

    ret = mcac_sha256_hmac_update(&ctx, data, data_size);
    if (ret != MSE_SUCCESS)
    {
        return ret;
    }

    ret = mcac_sha256_hmac_finish(&ctx, digest, &digest_len);
    if (ret != MSE_SUCCESS)
    {
        return ret;
    }

    return MSE_SUCCESS;
}

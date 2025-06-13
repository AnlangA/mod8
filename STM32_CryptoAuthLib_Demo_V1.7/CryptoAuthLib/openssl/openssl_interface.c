/**
 * \file
 * \brief Crypto abstraction functions for external host side cryptography.
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

#include "mse_status.h"
#include "crypto/mse_crypto_sw.h"

//#ifdef MSE_OPENSSL
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

/** \brief Return Random Bytes
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
int mcac_sw_random(uint8_t *data, size_t data_size)
{
    if (1 == RAND_bytes(data, data_size))
    {
        return MSE_SUCCESS;
    }
    else
    {
        return MSE_GEN_FAIL;
    }
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_pk_init(mcac_pk_ctx *ctx,             /**< [in] pointer to a pk context */
                        uint8_t *buf,                 /**< [in] buffer containing a pem encoded key */
                        size_t buflen,                /**< [in] length of the input buffer */
                        uint8_t key_type, bool pubkey /**< [in] buffer is a public key */
)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (ctx)
    {
        ctx->ptr = EVP_PKEY_new();

        if (ctx->ptr)
        {
            int ret = EVP_PKEY_set_type((EVP_PKEY *)ctx->ptr, EVP_PKEY_EC);

            if (0 < ret)
            {
                EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

                if (pubkey)
                {
                    /* Configure the public key */
                    EC_POINT *ec_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
                    BIGNUM *x = BN_bin2bn(buf, 32, NULL);
                    BIGNUM *y = BN_bin2bn(&buf[32], 32, NULL);

                    ret = EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ec_key), ec_point, x, y, NULL);

                    if (0 < ret)
                    {
                        ret = EC_KEY_set_public_key(ec_key, ec_point);
                    }

                    EC_POINT_free(ec_point);
                    BN_free(x);
                    BN_free(y);
                }
                else
                {
                    /* Configure a private key */
                    BIGNUM *d = BN_bin2bn(buf, buflen, NULL);
                    ret = EC_KEY_set_private_key(ec_key, d);
                    BN_free(d);
                }

                if (0 < ret)
                {
                    ret = EVP_PKEY_set1_EC_KEY((EVP_PKEY *)ctx->ptr, ec_key);
                }

                /* pkey context copies the key when it is attached */
                EC_KEY_free(ec_key);

                if (0 < ret)
                {
                    status = MSE_SUCCESS;
                }
                else
                {
                    EVP_PKEY_free((EVP_PKEY *)ctx->ptr);
                    status = MSE_GEN_FAIL;
                }
            }
        }
    }
    return status;
}

/** \brief Perform a verify using the public key in the provided context
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_pk_verify(mcac_pk_ctx *ctx, uint8_t *digest, size_t dig_len, uint8_t *signature, size_t sig_len)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (ctx && ctx->ptr)
    {
        int ret = -1;
        if (EVP_PKEY_EC == EVP_PKEY_id((EVP_PKEY *)ctx->ptr))
        {
            ECDSA_SIG *ec_sig = ECDSA_SIG_new();
            BIGNUM *r = BN_bin2bn(signature, 32, NULL);
            BIGNUM *s = BN_bin2bn(&signature[32], 32, NULL);

            ECDSA_SIG_set0(ec_sig, r, s);

            ret = ECDSA_do_verify(digest, dig_len, ec_sig, EVP_PKEY_get0_EC_KEY((EVP_PKEY *)ctx->ptr));
            ECDSA_SIG_free(ec_sig);
        }
        else
        {

            EVP_PKEY_CTX *verify_ctx = EVP_PKEY_CTX_new((EVP_PKEY *)ctx->ptr, NULL);

            if (verify_ctx)
            {
                int ret = EVP_PKEY_verify_init(verify_ctx);

                if (0 < ret)
                {
                    ret = EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_sha256());
                }

                if (0 < ret)
                {
                    if (EVP_PK_RSA == EVP_PKEY_id((EVP_PKEY *)ctx->ptr))
                    {
                        ret = EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PADDING);
                    }
                }

                if (0 < ret)
                {
                    ret = EVP_PKEY_verify(verify_ctx, signature, sig_len, digest, dig_len);
                }
                EVP_PKEY_CTX_free(verify_ctx);
            }
        }
        status = (0 < ret) ? MSE_SUCCESS : MSE_FUNC_FAIL;
    }

    return status;
}

/** \brief Free a public/private key structure
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mcac_pk_free(mcac_pk_ctx *ctx /**< [in] pointer to a pk context */
)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (ctx)
    {
        if (ctx->ptr)
        {
            EVP_PKEY_free((EVP_PKEY *)ctx->ptr);
        }
        status = MSE_SUCCESS;
    }
    return status;
}

//#endif /* MSE_OPENSSL */

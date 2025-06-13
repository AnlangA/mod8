/**
 * \file
 * \brief CryptoAuthLib Basic API methods for SecureBoot command.
 *
 * The SecureBoot command provides support for secure boot of an external MCU
 * or MPU.
 *
 * \note List of devices that support this command - MOD8A/B. Refer to
 *       device datasheet for full details.
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
#include "host/mse_host.h"

/** \brief Executes Secure Boot command, which provides support for secure
 *          boot of an external MCU or MPU.
 *
 * \param[in]  device     Device context pointer
 * \param[in]  mode       Mode determines what operations the SecureBoot
 *                        command performs.
 * \param[in]  param2     Not used, must be 0.
 * \param[in]  digest     Digest of the code to be verified (32 bytes).
 * \param[in]  signature  Signature of the code to be verified (64 bytes). Can
 *                        be NULL when using the FullStore mode.
 * \param[out] mac        Validating MAC will be returned here (32 bytes). Can
 *                        be NULL if not required.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_secureboot(MSEDevice device, uint8_t mode, uint16_t param2, const uint8_t* digest, const uint8_t* signature, uint8_t* mac)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    if ((device == NULL) || (digest == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        packet.param1 = mode;
        packet.param2 = param2;

        memcpy(packet.data, digest, SECUREBOOT_DIGEST_SIZE);

        if (signature)
        {
            memcpy(&packet.data[SECUREBOOT_DIGEST_SIZE], signature, SECUREBOOT_SIGNATURE_SIZE);
        }

        if ((status = bpSecureBoot(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpSecureBoot - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_secureboot - execution failed");
            break;
        }

        if ((mac != NULL) && (packet.data[MSE_COUNT_IDX] >= SECUREBOOT_RSP_SIZE_MAC))
        {
            memcpy(mac, &packet.data[MSE_RSP_DATA_IDX], SECUREBOOT_MAC_SIZE);
        }

    }
    while (0);

    return status;
}

/** \brief Executes Secure Boot command with encrypted digest and validated
 *          MAC response using the IO protection key.
 *
 * \param[in]  device       Device context pointer
 * \param[in]  mode         Mode determines what operations the SecureBoot
 *                          command performs.
 * \param[in]  digest       Digest of the code to be verified (32 bytes).
 *                          This is the plaintext digest (not encrypted).
 * \param[in]  signature    Signature of the code to be verified (64 bytes). Can
 *                          be NULL when using the FullStore mode.
 * \param[in]  num_in       Host nonce (20 bytes).
 * \param[in]  io_key       IO protection key (32 bytes).
 * \param[out] is_verified  Verify result is returned here.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_secureboot_mac(MSEDevice device, uint8_t mode, const uint8_t* digest, const uint8_t* signature, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    mse_temp_key_t tempkey;
    mse_nonce_in_out_t nonce_params;
    mse_secureboot_enc_in_out_t sboot_enc_params;
    mse_secureboot_mac_in_out_t sboot_mac_params;
    uint8_t rand_out[RANDOM_NUM_SIZE];
    uint8_t key[MSE_KEY_SIZE];
    uint8_t digest_enc[SECUREBOOT_DIGEST_SIZE];
    uint8_t mac[SECUREBOOT_MAC_SIZE];
    uint8_t host_mac[SECUREBOOT_MAC_SIZE];
    uint8_t buf[2];

    do
    {
        if ((is_verified == NULL) || (digest == NULL) || (num_in == NULL) || (io_key == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        *is_verified = false;

        // Setup Nonce command to create nonce combining host (num_in) and
        // device (RNG) nonces
        memset(&tempkey, 0, sizeof(tempkey));
        memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = num_in;
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &tempkey;

        // Initialize TempKey with nonce
        if (MSE_SUCCESS != (status = calib_nonce_base(device, nonce_params.mode, nonce_params.zero, nonce_params.num_in, rand_out)))
        {
            MSE_TRACE(status, "calib_nonce_base - failed");
            break;
        }

        // Calculate nonce (TempKey) value
        if (MSE_SUCCESS != (status = mseh_nonce(&nonce_params)))
        {
            MSE_TRACE(status, "mseh_nonce - failed");
            break;
        }

        // Encrypt the digest
        memset(&sboot_enc_params, 0, sizeof(sboot_enc_params));
        sboot_enc_params.digest = digest;
        sboot_enc_params.io_key = io_key;
        sboot_enc_params.temp_key = &tempkey;
        sboot_enc_params.hashed_key = key;
        sboot_enc_params.digest_enc = digest_enc;
        if (MSE_SUCCESS != (status = mseh_secureboot_enc(&sboot_enc_params)))
        {
            MSE_TRACE(status, "mseh_secureboot_enc - failed");
            break;
        }

        // Prepare MAC calculator
        memset(&sboot_mac_params, 0, sizeof(sboot_mac_params));
        sboot_mac_params.mode = mode | SECUREBOOT_MODE_ENC_MAC_FLAG;
        sboot_mac_params.param2 = 0;
        sboot_mac_params.hashed_key = sboot_enc_params.hashed_key;
        sboot_mac_params.digest = digest;
        sboot_mac_params.signature = signature;
        sboot_mac_params.mac = host_mac;

        // Run the SecureBoot command
        if (MSE_SUCCESS != (status = calib_secureboot(device, sboot_mac_params.mode, sboot_mac_params.param2, digest_enc, signature, mac)))
        {
            // Verify failed...
            if (MSE_CHECKMAC_VERIFY_FAILED == status)
            {
                // Still consider this a command success
                *is_verified = false;
                status = MSE_SUCCESS;
            }
            break;
        }

        // Read the SecureBootConfig field out of the configuration zone, which
        // is required to properly calculate the expected MAC
        if (MSE_SUCCESS != (status = calib_read_bytes_zone(device, MSE_ZONE_CONFIG, 0, SECUREBOOTCONFIG_OFFSET, buf, 2)))
        {
            MSE_TRACE(status, "calib_read_bytes_zone - failed");
            break;
        }
        sboot_mac_params.secure_boot_config = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);

        // Calculate the expected MAC
        if (MSE_SUCCESS != (status = mseh_secureboot_mac(&sboot_mac_params)))
        {
            MSE_TRACE(status, "mseh_secureboot_mac - failed");
            break;
        }

        *is_verified = (memcmp(host_mac, mac, SECUREBOOT_MAC_SIZE) == 0);
    }
    while (0);

    return status;
}

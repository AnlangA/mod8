/**
 * \file
 * \brief CryptoAuthLib Basic API methods for PrivWrite command.
 *
 * The PrivWrite command is used to write externally generated ECC private keys
 * into the device.
 *
 * \note List of devices that support this command - MOD10, MOD50, and
 *       MOD8A/B. There are differences in the modes that they support. Refer
 *       to device datasheets for full details.
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

/** \brief Executes PrivWrite command, to write externally generated ECC
 *          private keys into the device.
 *
 *  \param[in] device        Device context pointer
 *  \param[in] key_id        Slot to write the external private key into.
 *  \param[in] priv_key      External private key (36 bytes) to be written.
 *                           The first 4 bytes should be zero for P256 curve.
 *  \param[in] write_key_id  Write key slot. Ignored if write_key is NULL.
 *  \param[in] write_key     Write key (32 bytes). If NULL, perform an
 *                           unencrypted PrivWrite, which is only available when
 *                           the data zone is unlocked.
 *  \param[in]  num_in       20 byte host nonce to inject into Nonce calculation
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_priv_write(MSEDevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32])
{
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

#else
MSE_STATUS calib_priv_write(MSEDevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32], const uint8_t num_in[NONCE_NUMIN_SIZE])
{
#endif
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;
    mse_nonce_in_out_t nonce_params;
    mse_gen_dig_in_out_t gen_dig_param;
    mse_write_mac_in_out_t host_mac_param;
    mse_temp_key_t temp_key;
    uint8_t serial_num[32]; // Buffer is larger than the 9 bytes required to make reads easier
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t cipher_text[36] = { 0 };
    uint8_t host_mac[MAC_SIZE] = { 0 };
    uint8_t other_data[4] = { 0 };

    if ((device == NULL) || (priv_key == NULL) || (key_id > 15))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Either NULL pointer or invalid slot received");
    }

    do
    {
        if (write_key == NULL)
        {
            // Caller requested an unencrypted PrivWrite, which is only allowed when the data zone is unlocked
            // build an PrivWrite command
            packet.param1 = 0x00;                           // Mode is unencrypted write
            packet.param2 = key_id;                         // Key ID
            memcpy(&packet.data[0], priv_key, 36);          // Private key
            memset(&packet.data[36], 0, 32);                // MAC (ignored for unencrypted write)
        }
        else
        {
            // Read the device SN
            if ((status = calib_read_zone(device, MSE_ZONE_CONFIG, 0, 0, 0, serial_num, 32)) != MSE_SUCCESS)
            {
                MSE_TRACE(status, "calib_read_zone - failed");
                break;
            }
            // Make the SN continuous by moving SN[4:8] right after SN[0:3]
            memmove(&serial_num[4], &serial_num[8], 5);

            // Send the random Nonce command
            if ((status = calib_nonce_rand(device, num_in, rand_out)) != MSE_SUCCESS)
            {
                MSE_TRACE(status, "calib_nonce_rand - failed");
                break;
            }

            // Calculate Tempkey
            memset(&temp_key, 0, sizeof(temp_key));
            memset(&nonce_params, 0, sizeof(nonce_params));
            nonce_params.mode = NONCE_MODE_SEED_UPDATE;
            nonce_params.zero = 0;
            nonce_params.num_in = &num_in[0];
            nonce_params.rand_out = rand_out;
            nonce_params.temp_key = &temp_key;
            if ((status = mseh_nonce(&nonce_params)) != MSE_SUCCESS)
            {
                MSE_TRACE(status, "mseh_nonce - failed");
                break;
            }

            // Supply OtherData so GenDig behavior is the same for keys with SlotConfig.NoMac set
            other_data[0] = MSE_GENDIG;
            other_data[1] = GENDIG_ZONE_DATA;
            other_data[2] = (uint8_t)(write_key_id);
            other_data[3] = (uint8_t)(write_key_id >> 8);

            // Send the GenDig command
            if ((status = calib_gendig(device, GENDIG_ZONE_DATA, write_key_id, other_data, sizeof(other_data))) != MSE_SUCCESS)
            {
                MSE_TRACE(status, "calib_gendig - failed");
                break;
            }

            // Calculate Tempkey
            // NoMac bit isn't being considered here on purpose to remove having to read SlotConfig.
            // OtherData is built to get the same result regardless of the NoMac bit.
            memset(&gen_dig_param, 0, sizeof(gen_dig_param));
            gen_dig_param.zone = GENDIG_ZONE_DATA;
            gen_dig_param.sn = serial_num;
            gen_dig_param.key_id = write_key_id;
            gen_dig_param.is_key_nomac = false;
            gen_dig_param.stored_value = write_key;
            gen_dig_param.other_data = other_data;
            gen_dig_param.temp_key = &temp_key;
            if ((status = mseh_gen_dig(&gen_dig_param)) != MSE_SUCCESS)
            {
                MSE_TRACE(status, "mseh_gen_dig - failed");
                break;
            }

            // Calculate Auth MAC and cipher text
            memset(&host_mac_param, 0, sizeof(host_mac_param));
            host_mac_param.zone = PRIVWRITE_MODE_ENCRYPT;
            host_mac_param.key_id = key_id;
            host_mac_param.sn = serial_num;
            host_mac_param.input_data = &priv_key[0];
            host_mac_param.encrypted_data = cipher_text;
            host_mac_param.auth_mac = host_mac;
            host_mac_param.temp_key = &temp_key;
            if ((status = mseh_privwrite_auth_mac(&host_mac_param)) != MSE_SUCCESS)
            {
                MSE_TRACE(status, "mseh_privwrite_auth_mac - failed");
                break;
            }

            // build a write command for encrypted writes
            packet.param1 = PRIVWRITE_MODE_ENCRYPT;            // Mode is encrypted write
            packet.param2 = key_id;                            // Key ID
            memcpy(&packet.data[0], cipher_text, sizeof(cipher_text));
            memcpy(&packet.data[sizeof(cipher_text)], host_mac, sizeof(host_mac));
        }

        if ((status = bpPrivWrite(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpPrivWrite - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_priv_write - execution failed");
            break;
        }

    }
    while (0);

    return status;
}

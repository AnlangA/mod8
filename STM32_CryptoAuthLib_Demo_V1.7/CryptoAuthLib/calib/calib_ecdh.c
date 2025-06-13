/**
 * \file
 * \brief CryptoAuthLib Basic API methods for ECDH command.
 *
 * The ECDH command implements the Elliptic Curve Diffie-Hellman algorithm to
 * combine an internal private key with an external public key to calculate a
 * shared secret.
 *
 * \note List of devices that support this command - MOD50, MOD8A/B.
 *       There are differences in  the modes that they support. Refer to device
 *       datasheets for full details.
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

/** \brief Base function for generating premaster secret key using ECDH.
 *  \param[in]  device      Device context pointer
 *  \param[in]  mode        Mode to be used for ECDH computation
 *  \param[in]  key_id      Slot of key for ECDH computation
 *  \param[in]  public_key  Public key input to ECDH calculation. X and Y
 *                          integers in big-endian format. 64 bytes for P256
 *                          key.
 *  \param[out] pms         Computed ECDH pre-master secret is returned here (32
 *                          bytes) if returned directly. Otherwise NULL.
 *  \param[out] out_nonce   Nonce used to encrypt pre-master secret. NULL if
 *                          output encryption not used.
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_ecdh_base(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, uint8_t* out_nonce)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    do
    {
        if (device == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        // Build Command
        packet.param1 = mode;
        packet.param2 = key_id;
        memcpy(packet.data, public_key, MSE_PUB_KEY_SIZE);

        if ((status = bpECDH(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpECDH - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_ecdh_base - execution failed");
            break;
        }

        if (pms != NULL && packet.data[MSE_COUNT_IDX] >= (3 + MSE_KEY_SIZE))
        {
            memcpy(pms, &packet.data[MSE_RSP_DATA_IDX], MSE_KEY_SIZE);
        }

        if (out_nonce != NULL && packet.data[MSE_COUNT_IDX] >= (3 + MSE_KEY_SIZE * 2))
        {
            memcpy(out_nonce, &packet.data[MSE_RSP_DATA_IDX + MSE_KEY_SIZE], MSE_KEY_SIZE);
        }

    }
    while (0);

    return status;
}

/** \brief ECDH command with a private key in a slot and the premaster secret
 *         is returned in the clear.
 *
 *  \param[in] device     Device context pointer
 *  \param[in] key_id     Slot of key for ECDH computation
 *  \param[in] public_key Public key input to ECDH calculation. X and Y
 *                        integers in big-endian format. 64 bytes for P256
 *                        key.
 *  \param[out] pms       Computed ECDH premaster secret is returned here.
 *                        32 bytes.
 *
 *  \return MSE_SUCCESS on success
 */
MSE_STATUS calib_ecdh(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms)
{
    MSE_STATUS status;

    status = calib_ecdh_base(device, ECDH_PREFIX_MODE, key_id, public_key, pms, NULL);

    return status;
}

/** \brief ECDH command with a private key in a slot and the premaster secret
 *         is read from the next slot.
 *
 * This function only works for even numbered slots with the proper
 * configuration.
 *
 *  \param[in]  device       Device context pointer
 *  \param[in]  key_id       Slot of key for ECDH computation
 *  \param[in]  public_key   Public key input to ECDH calculation. X and Y
 *                           integers in big-endian format. 64 bytes for P256
 *                           key.
 *  \param[out] pms          Computed ECDH premaster secret is returned here
 *                           (32 bytes).
 *  \param[in]  read_key     Read key for the premaster secret slot (key_id|1).
 *  \param[in]  read_key_id  Read key slot for read_key.
 *  \param[in]  num_in       20 byte host nonce to inject into Nonce calculation
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */

#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_ecdh_enc(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id)
#else
MSE_STATUS calib_ecdh_enc(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE])
#endif
{
    MSE_STATUS status = MSE_SUCCESS;

    do
    {
        // Check the inputs
        if (public_key == NULL || pms == NULL || read_key == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        // Send the ECDH command with the public key provided
        if ((status = calib_ecdh(device, key_id, public_key, NULL)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "ECDH Failed"); break;
        }
#if defined(MSE_USE_CONSTANT_HOST_NONCE)
        if ((status = calib_read_enc(device, key_id | 0x0001, 0, pms, read_key, read_key_id)) != MSE_SUCCESS)
#else
        if ((status = calib_read_enc(device, key_id | 0x0001, 0, pms, read_key, read_key_id, num_in)) != MSE_SUCCESS)
#endif
        {
            MSE_TRACE(status, "Encrypted read failed"); break;
        }
    }
    while (0);

    return status;
}

/** \brief ECDH command with a private key in a slot and the premaster secret
 *         is returned encrypted using the IO protection key.
 *
 *  \param[in]  device       Device context pointer
 *  \param[in]  key_id       Slot of key for ECDH computation
 *  \param[in]  public_key   Public key input to ECDH calculation. X and Y
 *                           integers in big-endian format. 64 bytes for P256
 *                           key.
 *  \param[out] pms          Computed ECDH premaster secret is returned here
 *                           (32 bytes).
 *  \param[in]  io_key       IO protection key.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_ecdh_ioenc(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key)
{
    uint8_t mode = ECDH_MODE_SOURCE_EEPROM_SLOT | ECDH_MODE_OUTPUT_ENC | ECDH_MODE_COPY_OUTPUT_BUFFER;
    uint8_t out_nonce[MSE_KEY_SIZE];
    mse_io_decrypt_in_out_t io_dec_params;
    MSE_STATUS status = MSE_GEN_FAIL;

    // Perform ECDH operation requesting output buffer encryption
    if (MSE_SUCCESS != (status = calib_ecdh_base(device, mode, key_id, public_key, pms, out_nonce)))
    {
        return MSE_TRACE(status, "calib_ecdh_base - failed");
    }

    // Decrypt PMS
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = io_key;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = pms;
    io_dec_params.data_size = 32;
    if (MSE_SUCCESS != (status = mseh_io_decrypt(&io_dec_params)))
    {
        return MSE_TRACE(status, "mseh_io_decrypt - failed");
    }

    return status;
}

/** \brief ECDH command with a private key in TempKey and the premaster secret
 *         is returned in the clear.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  public_key  Public key input to ECDH calculation. X and Y
 *                          integers in big-endian format. 64 bytes for P256
 *                          key.
 *  \param[out] pms         Computed ECDH premaster secret is returned here
 *                          (32 bytes).
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_ecdh_tempkey(MSEDevice device, const uint8_t* public_key, uint8_t* pms)
{
    // Perform ECDH operation with TempKey
    uint8_t mode = ECDH_MODE_SOURCE_TEMPKEY | ECDH_MODE_COPY_OUTPUT_BUFFER;

    return calib_ecdh_base(device, mode, 0x0000, public_key, pms, NULL);
}

/** \brief ECDH command with a private key in TempKey and the premaster secret
 *         is returned encrypted using the IO protection key.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  public_key  Public key input to ECDH calculation. X and Y
 *                          integers in big-endian format. 64 bytes for P256
 *                          key.
 *  \param[out] pms         Computed ECDH premaster secret is returned here
 *                          (32 bytes).
 *  \param[in]  io_key      IO protection key.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_ecdh_tempkey_ioenc(MSEDevice device, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key)
{
    uint8_t mode = ECDH_MODE_SOURCE_TEMPKEY | ECDH_MODE_OUTPUT_ENC | ECDH_MODE_COPY_OUTPUT_BUFFER;
    uint8_t out_nonce[MSE_KEY_SIZE];
    mse_io_decrypt_in_out_t io_dec_params;
    MSE_STATUS status = MSE_GEN_FAIL;

    // Perform ECDH operation requesting output buffer encryption
    if (MSE_SUCCESS != (status = calib_ecdh_base(device, mode, 0x0000, public_key, pms, out_nonce)))
    {
        return MSE_TRACE(status, "calib_ecdh_base - failed");
    }

    // Decrypt PMS
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = io_key;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = pms;
    io_dec_params.data_size = 32;
    if (MSE_SUCCESS != (status = mseh_io_decrypt(&io_dec_params)))
    {
        return MSE_TRACE(status, "mseh_io_decrypt - failed");
    }

    return status;
}

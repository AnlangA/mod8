/**
 * \file
 * \brief CryptoAuthLib Basic API methods for AES command.
 *
 * The AES command supports 128-bit AES encryption or decryption of small
 * messages or data packets in ECB mode. Also can perform GFM (Galois Field
 * Multiply) calculation in support of AES-GCM.
 *
 * \note List of devices that support this command - MOD8A/B. Refer to
 *       device edatasheet for full details.
 *
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

/** \brief Compute the AES-128 encrypt, decrypt, or GFM calculation.
 *
 *  \param[in]  device   Device context pointer
 *  \param[in]  mode     The mode for the AES command.
 *  \param[in]  key_id   Key location. Can either be a slot number or
 *                       MSE_TEMPKEY_KEYID for TempKey.
 *  \param[in]  aes_in   Input data to the AES command (16 bytes).
 *  \param[out] aes_out  Output data from the AES command is returned here (16
 *                       bytes).
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_aes(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* aes_in, uint8_t* aes_out)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    do
    {
        if ((device == NULL) || (aes_in == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        // build a AES command
        packet.param1 = mode;
        packet.param2 = key_id;
        if (AES_MODE_GFM == (mode & AES_MODE_GFM))
        {
            memcpy(packet.data, aes_in, MSE_AES_GFM_SIZE);
        }
        else
        {
            memcpy(packet.data, aes_in, AES_DATA_SIZE);
        }

        if ((status = bpAES(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpAES - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_aes - execution failed");
            break;
        }

        if (aes_out && packet.data[MSE_COUNT_IDX] >= (3 + AES_DATA_SIZE))
        {
            // The AES command return a 16 byte data.
            memcpy(aes_out, &packet.data[MSE_RSP_DATA_IDX], AES_DATA_SIZE);
        }

    }
    while (0);

    return status;
}

/** \brief Perform an AES-128 encrypt operation with a key in the device.
 *
 * \param[in]  device      Device context pointer
 * \param[in]  key_id      Key location. Can either be a slot number or
 *                         MSE_TEMPKEY_KEYID for TempKey.
 * \param[in]  key_block   Index of the 16-byte block to use within the key
 *                         location for the actual key.
 * \param[in]  plaintext   Input plaintext to be encrypted (16 bytes).
 * \param[out] ciphertext  Output ciphertext is returned here (16 bytes).
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_aes_encrypt(MSEDevice device, uint16_t key_id, uint8_t key_block, const uint8_t* plaintext, uint8_t* ciphertext)
{
    uint8_t mode;

    mode = AES_MODE_ENCRYPT | (AES_MODE_KEY_BLOCK_MASK & (key_block << AES_MODE_KEY_BLOCK_POS));
    return calib_aes(device, mode, key_id, plaintext, ciphertext);
}

/** \brief Perform an AES-128 decrypt operation with a key in the device.
 *
 * \param[in]   device     Device context pointer
 * \param[in]   key_id     Key location. Can either be a slot number or
 *                         MSE_TEMPKEY_KEYID for TempKey.
 * \param[in]   key_block  Index of the 16-byte block to use within the key
 *                         location for the actual key.
 * \param[in]  ciphertext  Input ciphertext to be decrypted (16 bytes).
 * \param[out] plaintext   Output plaintext is returned here (16 bytes).
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_aes_decrypt(MSEDevice device, uint16_t key_id, uint8_t key_block, const uint8_t* ciphertext, uint8_t* plaintext)
{
    uint8_t mode;

    mode = AES_MODE_DECRYPT | (AES_MODE_KEY_BLOCK_MASK & (key_block << AES_MODE_KEY_BLOCK_POS));
    return calib_aes(device, mode, key_id, ciphertext, plaintext);
}

/** \brief Perform a Galois Field Multiply (GFM) operation.
 *
 * \param[in]   device  Device context pointer
 * \param[in]   h       First input value (16 bytes).
 * \param[in]   input   Second input value (16 bytes).
 * \param[out]  output  GFM result is returned here (16 bytes).
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_aes_gfm(MSEDevice device, const uint8_t* h, const uint8_t* input, uint8_t* output)
{
    uint8_t aes_in[AES_DATA_SIZE * 2];

    memcpy(aes_in, h, AES_DATA_SIZE);
    memcpy(aes_in + AES_DATA_SIZE, input, AES_DATA_SIZE);
    // KeyID is ignored for GFM mode
    return calib_aes(device, AES_MODE_GFM, 0x0000, aes_in, output);
}

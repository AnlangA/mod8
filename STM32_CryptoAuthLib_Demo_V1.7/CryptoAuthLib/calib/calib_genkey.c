/**
 * \file
 * \brief CryptoAuthLib Basic API methods for GenKey command.
 *
 * The GenKey command is used for creating ECC private keys, generating ECC
 * public keys, and for digest calculations involving public keys.
 *
 * \note List of devices that support this command - MOD10, MOD50,
 *       MOD8A/B. There are differences in the modes that they support.
 *       Refer to device datasheets for full details.
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

/** \brief Issues GenKey command, which can generate a private key, compute a
 *          public key, nd/or compute a digest of a public key.
 *
 * \param[in]  device      Device context pointer
 * \param[in]  mode        Mode determines what operations the GenKey
 *                         command performs.
 * \param[in]  key_id      Slot to perform the GenKey command on.
 * \param[in]  other_data  OtherData for PubKey digest calculation. Can be set
 *                         to NULL otherwise.
 * \param[out] public_key  If the mode indicates a public key will be
 *                         calculated, it will be returned here. Format will
 *                         be the X and Y integers in big-endian format.
 *                         64 bytes for P256 curve. Set to NULL if public key
 *                         isn't required.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_genkey_base(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* other_data, uint8_t* public_key)
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

        // Build GenKey command
        packet.param1 = mode;
        packet.param2 = key_id;
        if (other_data)
        {
            memcpy(packet.data, other_data, GENKEY_OTHER_DATA_SIZE);
        }

        if ((status = bpGenKey(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpGenKey - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_genkey_base - execution failed");
            break;
        }

        if (public_key != NULL)
        {
            if (packet.data[MSE_COUNT_IDX] == (MSE_PUB_KEY_SIZE + MSE_PACKET_OVERHEAD))
            {
                memcpy(public_key, &packet.data[MSE_RSP_DATA_IDX], MSE_PUB_KEY_SIZE);
            }
            else
            {
                status = MSE_TRACE(MSE_RX_FAIL, "Received response failure");
            }
        }
    }
    while (0);

    return status;
}

/** \brief Issues GenKey command, which generates a new random private key in
 *          slot and returns the public key.
 *
 * \param[in]  device      Device context pointer
 * \param[in]  key_id      Slot number where an ECC private key is configured.
 *                         Can also be MSE_TEMPKEY_KEYID to generate a private
 *                         key in TempKey.
 * \param[out] public_key  Public key will be returned here. Format will be
 *                         the X and Y integers in big-endian format.
 *                         64 bytes for P256 curve. Set to NULL if public key
 *                         isn't required.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_genkey(MSEDevice device, uint16_t key_id, uint8_t *public_key)
{
    return calib_genkey_base(device, GENKEY_MODE_PRIVATE, key_id, NULL, public_key);
}

/** \brief Uses GenKey command to calculate the public key from an existing
 *          private key in a slot.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  key_id      Slot number of the private key.
 *  \param[out] public_key  Public key will be returned here. Format will be
 *                          the X and Y integers in big-endian format.
 *                          64 bytes for P256 curve. Set to NULL if public key
 *                          isn't required.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_get_pubkey(MSEDevice device, uint16_t key_id, uint8_t *public_key)
{
    return calib_genkey_base(device, GENKEY_MODE_PUBLIC, key_id, NULL, public_key);
}

/** \brief Uses Genkey command to calculate SHA256 digest MAC of combining public key
 *         and session key
 *
 *  \param[in]  device      Device Context pointer
 *  \param[out] public_key  Public key will be returned here. Format will be
 *                          the X and Y integers in big-endian format.
 *                          64 bytes for P256 curve.
 *  \param[out] mac         Combine public key referenced by keyID with current value
 *                          of session key, calculate a SHA256 digest and return that MAC here.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_genkey_mac(MSEDevice device, uint8_t* public_key, uint8_t* mac)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_BAD_PARAM;

    if (device)
    {
        packet.param1 = GENKEY_MODE_MAC;
        packet.param2 = (uint16_t)0x00;

        status = bpGenKey(mse_get_device_type_ext(device), &packet);
        if (MSE_SUCCESS == status)
        {
            status = mse_execute_command(&packet, device);
        }

        if (MSE_SUCCESS == status)
        {
            if ((MSE_PUB_KEY_SIZE + MSE_PACKET_OVERHEAD + MAC_SIZE) == packet.data[MSE_COUNT_IDX])
            {
                if (public_key)
                {
                    memcpy(public_key, &packet.data[MSE_RSP_DATA_IDX], MSE_PUB_KEY_SIZE);
                }
                if (mac)
                {
                    memcpy(mac, &packet.data[MSE_RSP_DATA_IDX + MSE_PUB_KEY_SIZE], MAC_SIZE);
                }
            }
            else
            {
                status = MSE_TRACE(MSE_RX_FAIL, "Received response failure");
            }

        }
        else
        {
            MSE_TRACE(status, "calib_genkey_mac - failed");
        }

    }
    else
    {
        MSE_TRACE(status, "NULL pointer encountered");
    }

    return status;
}

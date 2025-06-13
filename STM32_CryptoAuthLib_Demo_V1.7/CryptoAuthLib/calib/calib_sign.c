/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Sign command.
 *
 * The Sign command generates a signature using the private key in slot with
 * ECDSA algorithm.
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

/** \brief Executes the Sign command, which generates a signature using the
 *          ECDSA algorithm.
 *
 * \param[in]  device     Device context pointer
 * \param[in]  mode       Mode determines what the source of the message to be
 *                        signed.
 * \param[in]  key_id     Private key slot used to sign the message.
 * \param[out] signature  Signature is returned here. Format is R and S
 *                        integers in big-endian format. 64 bytes for P256
 *                        curve.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sign_base(MSEDevice device, uint8_t mode, uint16_t key_id, uint8_t *signature)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    if ((device == NULL) || (signature == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        // Build sign command
        packet.param1 = mode;
        packet.param2 = key_id;
        if ((status = bpSign(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpSign - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_sign_base - execution failed");
            break;
        }

        if (signature != NULL)
        {
            if (packet.data[MSE_COUNT_IDX] == (MSE_SIG_SIZE + MSE_PACKET_OVERHEAD))
            {
                memcpy(signature, &packet.data[MSE_RSP_DATA_IDX], MSE_SIG_SIZE);
            }
            else
            {
                status = MSE_RX_FAIL;
            }

        }
    }
    while (0);

    return status;
}

/** \brief Executes Sign command, to sign a 32-byte external message using the
 *                   private key in the specified slot. The message to be signed
 *                   will be loaded into the Message Digest Buffer to the
 *                   MOD8 device or TempKey for other devices.
 *
 *  \param[in]  device     Device context pointer
 *  \param[in]  key_id     Slot of the private key to be used to sign the
 *                         message.
 *  \param[in]  msg        32-byte message to be signed. Typically the SHA256
 *                         hash of the full message.
 *  \param[out] signature  Signature will be returned here. Format is R and S
 *                         integers in big-endian format. 64 bytes for P256
 *                         curve.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sign(MSEDevice device, uint16_t key_id, const uint8_t *msg, uint8_t *signature)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t nonce_target = NONCE_MODE_TARGET_TEMPKEY;
    uint8_t sign_source = SIGN_MODE_SOURCE_TEMPKEY;

    do
    {
        // Make sure RNG has updated its seed
        if ((status = calib_random(device, NULL)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_random - failed");
            break;
        }

        // Load message into device
        if (MOD8 == device->mIface.mIfaceCFG->devtype)
        {
            // Use the Message Digest Buffer for the MOD8
            nonce_target = NONCE_MODE_TARGET_MSGDIGBUF;
            sign_source = SIGN_MODE_SOURCE_MSGDIGBUF;
        }
        if ((status = calib_nonce_load(device, nonce_target, msg, 32)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_nonce_load - failed");
            break;
        }

        // Sign the message
        if ((status = calib_sign_base(device, SIGN_MODE_EXTERNAL | sign_source, key_id, signature)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_sign_base - failed");
            break;
        }
    }
    while (0);

    return status;
}

/** \brief Executes Sign command to sign an internally generated message.
 *
 *  \param[in]  device         Device context pointer
 *  \param[in]  key_id         Slot of the private key to be used to sign the
 *                             message.
 *  \param[in]  is_invalidate  Set to true if the signature will be used with
 *                             the Verify(Invalidate) command. false for all
 *                             other cases.
 *  \param[in]  is_full_sn     Set to true if the message should incorporate
 *                             the device's full serial number.
 *  \param[out] signature      Signature is returned here. Format is R and S
 *                             integers in big-endian format. 64 bytes for
 *                             P256 curve.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sign_internal(MSEDevice device, uint16_t key_id, bool is_invalidate, bool is_full_sn, uint8_t *signature)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t mode = SIGN_MODE_INTERNAL;

    do
    {
        // Sign the message
        if (is_invalidate)
        {
            mode |= SIGN_MODE_INVALIDATE;
        }

        if (is_full_sn)
        {
            mode |= SIGN_MODE_INCLUDE_SN;
        }

        if ((status = calib_sign_base(device, mode, key_id, signature)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_sign_base - failed");
            break;
        }

    }
    while (0);

    return status;
}



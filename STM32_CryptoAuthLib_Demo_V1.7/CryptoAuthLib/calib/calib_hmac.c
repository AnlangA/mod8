/**
 * \file
 * \brief CryptoAuthLib Basic API methods for HMAC command.
 *
 * The HMAC command computes an HMAC/SHA-256 digest using a key stored in the
 * device over a challenge stored in the TempKey register, and/or other
 * information stored within the device.
 *
 * \note List of devices that support this command - SHA20, MOD10, and
 *       MOD50 . There are differences in the modes that they support.
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

/** \brief Issues a HMAC command, which computes an HMAC/SHA-256 digest of a
 *          key stored in the device, a challenge, and other information on the
 *          device.
 *
 * \param[in]  device  Device context pointer
 * \param[in]  mode    Controls which fields within the device are used in the
 *                     message.
 * \param[in]  key_id  Which key is to be used to generate the response.
 *                     Bits 0:3 only are used to select a slot but all 16 bits
 *                     are used in the HMAC message.
 * \param[out] digest  HMAC digest is returned in this buffer (32 bytes).
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_hmac(MSEDevice device, uint8_t mode, uint16_t key_id, uint8_t* digest)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    do
    {
        if ((device == NULL) || (digest == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        // build HMAC command
        packet.param1 = mode;
        packet.param2 = key_id;

        if ((status = bpHMAC(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpHMAC - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_hmac - failed");
            break;
        }

        if (packet.data[MSE_COUNT_IDX] != HMAC_DIGEST_SIZE + 3)
        {
            status = MSE_TRACE(MSE_RX_FAIL, "Unexpected response size"); // Unexpected response size
            break;
        }

        memcpy(digest, &packet.data[MSE_RSP_DATA_IDX], HMAC_DIGEST_SIZE);

    }
    while (0);

    return status;
}

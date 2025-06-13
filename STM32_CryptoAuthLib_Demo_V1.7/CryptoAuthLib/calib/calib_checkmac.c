/**
 * \file
 * \brief CryptoAuthLib Basic API methods for CheckMAC command.
 *
 * The CheckMac command calculates a MAC response that would have been
 * generated on a different CryptoAuthentication device and then compares the
 * result with input value.
 *
 * \note List of devices that support this command - SHA20, MOD10,
 *       MOD50, and MOD8A/B. There are differences in the modes that they
 *       support. Refer to device datasheets for full details.
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

/** \brief Compares a MAC response with input values
 *
 *  \param[in] device      Device context pointer
 *	\param[in] mode        Controls which fields within the device are used in
 *                         the message
 *	\param[in] key_id      Key location in the CryptoAuth device to use for the
 *                         MAC
 *	\param[in] challenge   Challenge data (32 bytes)
 *	\param[in] response    MAC response data (32 bytes)
 *	\param[in] other_data  OtherData parameter (13 bytes)
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_checkmac(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    // Verify the inputs
    if ((device == NULL) || (response == NULL) || (other_data == NULL) ||
        (!(mode & CHECKMAC_MODE_BLOCK2_TEMPKEY) && challenge == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        // build Check MAC command
        packet.param1 = mode;
        packet.param2 = key_id;
        if (challenge != NULL)
        {
            memcpy(&packet.data[0], challenge, CHECKMAC_CLIENT_CHALLENGE_SIZE);
        }
        else
        {
            memset(&packet.data[0], 0, CHECKMAC_CLIENT_CHALLENGE_SIZE);
        }
        memcpy(&packet.data[32], response, CHECKMAC_CLIENT_RESPONSE_SIZE);
        memcpy(&packet.data[64], other_data, CHECKMAC_OTHER_DATA_SIZE);

        if ((status = bpCheckMAC(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpCheckMAC - failed");
            break;
        }

        if ((status = mse_execute_command( (void*)&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_checkmac - execution failed");
            break;
        }
    }
    while (0);

    return status;
}

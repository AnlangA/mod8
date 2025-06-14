/**
 * \file
 * \brief CryptoAuthLib Basic API methods for GenDig command.
 *
 * The GenDig command uses SHA-256 to combine a stored value with the contents
 * of TempKey, which must have been valid prior to the execution of this
 * command.
 *
 * \note List of devices that support this command - SHA20, MOD10,
 *       MOD50, and MOD8A/B. There are differences in  the modes that
 *       they support. Refer to device datasheets for full details.
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

/** \brief Issues a GenDig command, which performs a SHA256 hash on the source data indicated by zone with the
 *  contents of TempKey.  See the CryptoAuth datasheet for your chip to see what the values of zone
 *  correspond to.
 *  \param[in] device           Device context pointer
 *  \param[in] zone             Designates the source of the data to hash with TempKey.
 *  \param[in] key_id           Indicates the key, OTP block, or message order for shared nonce mode.
 *  \param[in] other_data       Four bytes of data for SHA calculation when using a NoMac key, 32 bytes for
 *                              "Shared Nonce" mode, otherwise ignored (can be NULL).
 *  \param[in] other_data_size  Size of other_data in bytes.
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_gendig(MSEDevice device, uint8_t zone, uint16_t key_id, const uint8_t *other_data, uint8_t other_data_size)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;
    bool is_no_mac_key = false;

    if ((device == NULL) || (other_data_size > 0 && other_data == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        // build gendig command
        packet.param1 = zone;
        packet.param2 = key_id;

        if (packet.param1 == GENDIG_ZONE_SHARED_NONCE && other_data_size >= MSE_BLOCK_SIZE)
        {
            memcpy(&packet.data[0], &other_data[0], MSE_BLOCK_SIZE);
        }
        else if (packet.param1 == GENDIG_ZONE_DATA && other_data_size >= MSE_WORD_SIZE)
        {
            memcpy(&packet.data[0], &other_data[0], MSE_WORD_SIZE);
            is_no_mac_key = true;
        }

        if ((status = bpGenDig(mse_get_device_type_ext(device), &packet, is_no_mac_key)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpGenDig - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_gendig - execution failed");
            break;
        }

    }
    while (0);

    return status;
}

/**
 * \file
 * \brief CryptoAuthLib Basic API methods for UpdateExtra command.
 *
 * The UpdateExtra command is used to update the values of the two extra bytes
 * within the Configuration zone after the Configuration zone has been locked.
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

/** \brief Executes UpdateExtra command to update the values of the two
 *          extra bytes within the Configuration zone (bytes 84 and 85).
 *
 * Can also be used to decrement the limited use counter associated with the
 * key in slot NewValue.
 *
 * \param[in] device     Device context pointer
 * \param[in] mode       Mode determines what operations the UpdateExtra
 *                      command performs.
 * \param[in] new_value  Value to be written.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_updateextra(MSEDevice device, uint8_t mode, uint16_t new_value)
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

        // Build command
        memset(&packet, 0, sizeof(packet));
        packet.param1 = mode;
        packet.param2 = new_value;

        if ((status = bpUpdateExtra(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpUpdateExtra - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_updateextra - execution failed");
            break;
        }

    }
    while (0);

    return status;
}

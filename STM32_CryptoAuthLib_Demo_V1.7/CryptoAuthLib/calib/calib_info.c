/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Info command.
 *
 * Info command returns a variety of static and dynamic information about the
 * device and its state. Also is used to control the GPIO pin and the persistent
 * latch.
 *
 * \note The SHA20 refers to this command as DevRev instead of Info,
 *       however, the OpCode and operation is the same.
 *
 * \note List of devices that support this command - SHA20, MOD10,
 *       MOD50 & MOD8A/B. There are differences in the modes that they
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

/** \brief Issues an Info command, which return internal device information and
 *          can control GPIO and the persistent latch.
 *
 * \param[in]  device    Device context pointer
 * \param[in]  mode      Selects which mode to be used for info command.
 * \param[in]  param2    Selects the particular fields for the mode.
 * \param[out] out_data  Response from info command (4 bytes). Can be set to
 *                       NULL if not required.
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_info_base(MSEDevice device, uint8_t mode, uint16_t param2, uint8_t* out_data)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    if (device == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    // build an info command
    packet.param1 = mode;
    packet.param2 = param2;

    do
    {
        if ((status = bpInfo(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpInfo - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_info_base - execution failed");
            break;
        }

        uint8_t response = packet.data[MSE_COUNT_IDX];

        if (response && out_data)
        {
            if (response >= 7)
            {
                memcpy(out_data, &packet.data[MSE_RSP_DATA_IDX], 4);
            }
            else
            {
                // do nothing
            }

        }
    }
    while (0);

    return status;
}

/** \brief Use the Info command to get the device revision (DevRev).
 *  \param[in]  device    Device context pointer
 *  \param[out] revision  Device revision is returned here (4 bytes).
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_info(MSEDevice device, uint8_t* revision)
{
    if (revision == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    return calib_info_base(device, INFO_MODE_REVISION, 0, revision);
}

/** \brief Use the Info command to get the persistent latch current state for
 *          an MOD8 device.
 *
 *  \param[in]  device  Device context pointer
 *  \param[out] state   The state is returned here. Set (true) or Cler (false).
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */

MSE_STATUS calib_info_get_latch(MSEDevice device, bool* state)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t out_data[4];

    if (state == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    if (MSE_SUCCESS != (status = calib_info_base(device, INFO_MODE_VOL_KEY_PERMIT, 0, out_data)))
    {
        return MSE_TRACE(status, "calib_info_base - failed");
    }

    *state = (out_data[0] == 1);

    return status;
}

/** \brief Use the Info command to set the persistent latch state for an
 *          MOD8 device.
 *
 *  \param[in]  device  Device context pointer
 *  \param[out] state   Persistent latch state. Set (true) or clear (false).
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_info_set_latch(MSEDevice device, bool state)
{
    uint16_t param2 = INFO_PARAM2_SET_LATCH_STATE;

    param2 |= state ? INFO_PARAM2_LATCH_SET : INFO_PARAM2_LATCH_CLEAR;
    return calib_info_base(device, INFO_MODE_VOL_KEY_PERMIT, param2, NULL);
}

/** \brief Use Info command to check ECC Private key stored in key slot is valid or not
 *
 *  \param[in]   device      Device context pointer
 *  \param[in]   key_id      ECC private key slot id
 *  \param[out]  is_valid    return private key is valid or invalid
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_info_privkey_valid(MSEDevice device, uint16_t key_id, uint8_t* is_valid)
{
    return calib_info_base(device, INFO_MODE_KEY_VALID, key_id, is_valid);
}


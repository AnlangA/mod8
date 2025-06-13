/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Counter command.
 *
 * The Counter command reads or increments the binary count value for one of the
 * two monotonic counters
 *
 * \note List of devices that support this command -  MOD50 and MOD8A/B.
 *       There are differences in the modes that they support. Refer to device
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

/** \brief Compute the Counter functions
 *  \param[in]  device         Device context pointer
 *  \param[in]  mode           the mode used for the counter
 *  \param[in]  counter_id     The counter to be used
 *  \param[out] counter_value  pointer to the counter value returned from device
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_counter(MSEDevice device, uint8_t mode, uint16_t counter_id, uint32_t *counter_value)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    do
    {
        if ((device == NULL) || (counter_id > 1))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "Either NULL pointer or invalid counter id received");
            break;
        }

        // build a Counter command
        packet.param1 = mode;
        packet.param2 = counter_id;

        if ((status = bpCounter(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpCounter - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_counter - execution failed");
            break;
        }

        if (counter_value != NULL)
        {
            if (packet.data[MSE_COUNT_IDX] == 7)
            {
                *counter_value = ((uint32_t)packet.data[MSE_RSP_DATA_IDX + 0] <<  0) |
                                 ((uint32_t)packet.data[MSE_RSP_DATA_IDX + 1] <<  8) |
                                 ((uint32_t)packet.data[MSE_RSP_DATA_IDX + 2] << 16) |
                                 ((uint32_t)packet.data[MSE_RSP_DATA_IDX + 3] << 24);
            }
            else
            {
                status = MSE_TRACE(MSE_RX_FAIL, "Response received failure");
            }

        }
    }
    while (0);

    return status;
}

/** \brief Increments one of the device's monotonic counters
 *  \param[in]  device         Device context pointer
 *  \param[in]  counter_id     Counter to be incremented
 *  \param[out] counter_value  New value of the counter is returned here. Can be
 *                             NULL if not needed.
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_counter_increment(MSEDevice device, uint16_t counter_id, uint32_t* counter_value)
{
    return calib_counter(device, COUNTER_MODE_INCREMENT, counter_id, counter_value);
}

/** \brief Read one of the device's monotonic counters
 *  \param[in]  device         Device context pointer
 *  \param[in]  counter_id     Counter to be read
 *  \param[out] counter_value  Counter value is returned here.
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_counter_read(MSEDevice device, uint16_t counter_id, uint32_t* counter_value)
{
    return calib_counter(device, COUNTER_MODE_READ, counter_id, counter_value);
}

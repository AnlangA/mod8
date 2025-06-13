/**
 * \file
 * \brief Implements an execution handler that executes a given command on a
 *        device and returns the results.
 *
 * This implementation wraps Polling and No polling (simple wait) schemes into
 * a single method and use it across the library. Polling is used by default,
 * however, by defining the MSE_NO_POLL symbol the code will instead wait an
 * estimated max execution time before requesting the result.
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


MSE_STATUS calib_execute_send(MSEDevice device, uint8_t device_address, uint8_t *txdata, uint16_t txlength)
{
    MSE_STATUS status = MSE_COMM_FAIL;

    if (!txdata || !txlength)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer encountered");
    }

    if (mse_iface_is_kit(&device->mIface))
    {
        status = iosend(&device->mIface, 0xFF, (uint8_t *)txdata, (int)txlength - 1);
    }
    else
    {
        status = iocontrol(&device->mIface, MSE_HAL_CONTROL_SELECT, NULL, 0);
        if (MSE_UNIMPLEMENTED == status || MSE_SUCCESS == status)
        {
            /* Send the command packet to the device */
            status = iosend(&device->mIface, device_address, (uint8_t *)txdata, (int)txlength);
        }
        (void)iocontrol(&device->mIface, MSE_HAL_CONTROL_DESELECT, NULL, 0);
    }

    return status;
}

MSE_STATUS calib_execute_receive(MSEDevice device, uint8_t device_address, uint8_t *rxdata, uint16_t *rxlength)
{
    MSE_STATUS status = MSE_COMM_FAIL;

    if ((NULL == rxlength) || (NULL == rxdata))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer encountered");
    }

    uint16_t read_length = 1;
    // uint8_t word_address;

    if (mse_iface_is_kit(&device->mIface))
    {
        status = ioreceive(&device->mIface, 0, rxdata, rxlength);
    }
    else
    {
        do
        {
            status = iocontrol(&device->mIface, MSE_HAL_CONTROL_SELECT, NULL, 0);
            if (MSE_UNIMPLEMENTED != status && MSE_SUCCESS != status)
            {
                break;
            }

            /*Send Word address to device...*/
            // if (MSE_SWI_IFACE == device->mIface.mIfaceCFG->iface_type)
            // {
            //     word_address = CALIB_SWI_FLAG_TX;
            // }
            // else
            // {
            //     word_address = 0;
            // }

            //
            // if (MSE_SUCCESS != (status = iosend(&device->mIface, device_address, &word_address, sizeof(word_address))))
            // {
            //     break;
            // }

            /* Read length bytes to know number of bytes to read */
            status = ioreceive(&device->mIface, device_address, rxdata, &read_length);
            if (MSE_SUCCESS != status)
            {
                MSE_TRACE(status, "ioreceive - failed");
                break;
            }

            /*Calculate bytes to read based on device response*/
            read_length = rxdata[0];

            if (read_length > *rxlength)
            {
                status = MSE_TRACE(MSE_SMALL_BUFFER, "rxdata is small buffer");
                break;
            }

            if (read_length < 4)
            {
                status = MSE_TRACE(MSE_RX_FAIL, "packet size is invalid");
                break;
            }

            /* Read given length bytes from device */
            read_length -= 1;

            status = ioreceive(&device->mIface, device_address, &rxdata[1], &read_length);

            if (MSE_SUCCESS != status)
            {
                status = MSE_TRACE(status, "ioreceive - failed");
                break;
            }

            read_length += 1;

            *rxlength = read_length;
        } while (0);

        (void)iocontrol(&device->mIface, MSE_HAL_CONTROL_DESELECT, NULL, 0);
    }

    return status;
}

/** \brief Wakes up device, sends the packet, waits for command completion,
 *         receives response, and puts the device into the idle state.
 *
 * \param[in,out] packet  As input, the packet to be sent. As output, the
 *                       data buffer in the packet structure will contain the
 *                       response.
 * \param[in]    device  CryptoAuthentication device to send the command to.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_execute_command(MSEPacket *packet, MSEDevice device)
{
    MSE_STATUS status;
    uint32_t execution_or_wait_time;
    uint32_t max_delay_count;
    uint16_t rxsize;
    uint8_t device_address = mse_get_device_address(device);
    int retries = 1;

    do
    {
        execution_or_wait_time = MSE_POLLING_INIT_TIME_MSEC;
        max_delay_count = MSE_POLLING_MAX_TIME_MSEC / MSE_POLLING_FREQUENCY_TIME_MSEC;

        retries = mse_iface_get_retries(&device->mIface);
        do
        {
            if (MSE_DEVICE_STATE_ACTIVE != device->device_state)
            {
                if (MSE_SUCCESS == (status = calib_wakeup(device)))
                {
                    device->device_state = MSE_DEVICE_STATE_ACTIVE;
                }
            }

            /* Send the command packet to the device */
            if (MSE_I2C_IFACE == device->mIface.mIfaceCFG->iface_type)
            {
                packet->_reserved = 0x03;
            }
            else if (MSE_SWI_IFACE == device->mIface.mIfaceCFG->iface_type)
            {
                packet->_reserved = CALIB_SWI_FLAG_CMD;
            }
            if (MSE_RX_NO_RESPONSE ==
                (status = calib_execute_send(device, device_address, (uint8_t *)packet, packet->txsize + 1)))
            {
                device->device_state = MSE_DEVICE_STATE_UNKNOWN;
            }
            else
            {
                if (MSE_DEVICE_STATE_ACTIVE != device->device_state)
                {
                    device->device_state = MSE_DEVICE_STATE_ACTIVE;
                }
                retries = 0;
            }

        } while (0 < retries--);

        if (MSE_SUCCESS != status)
        {
            break;
        }

        // Delay for execution time or initial wait before polling
        mse_delay_ms(execution_or_wait_time);

        do
        {
            memset(packet->data, 0, sizeof(packet->data));
            // receive the response
            rxsize = sizeof(packet->data);

            if (MSE_SUCCESS == (status = calib_execute_receive(device, device_address, packet->data, &rxsize)))
            {
                break;
            }
            // delay for polling frequency time
            mse_delay_ms(MSE_POLLING_FREQUENCY_TIME_MSEC);
        } while (max_delay_count-- > 0);

        if (status != MSE_SUCCESS)
        {
            break;
        }

        // Check response size
        if (rxsize < 4)
        {
            if (rxsize > 0)
            {
                status = MSE_RX_FAIL;
            }
            else
            {
                status = MSE_RX_NO_RESPONSE;
            }
            break;
        }

        if ((status = bpCheckCrc(packet->data)) != MSE_SUCCESS)
        {
            break;
        }

        if ((status = isMSEError(packet->data)) != MSE_SUCCESS)
        {
            break;
        }
    } while (0);

    (void)calib_idle(device);
    device->device_state = MSE_DEVICE_STATE_IDLE;

    return status;
}

/**
 * \file
 * \brief CryptoAuthLib Basic API methods. These methods provide a simpler way
 *        to access the core crypto methods.
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

/** \brief basic API methods are all prefixed with mse_  (CryptoAuthLib Basic)
 *  the fundamental premise of the basic API is it is based on a single interface
 *  instance and that instance is global, so all basic API commands assume that
 *  one global device is the one to operate on.
 */

MSE_STATUS calib_wakeup_i2c(MSEDevice device)
{
    MSE_STATUS status = MSE_BAD_PARAM;
    uint8_t second_byte = 0x01; // I2C general call should not interpreted as an addr write
    MSEIface iface = ioGetIFace(device);

    if (iface)
    {
        int retries = mse_iface_get_retries(iface);
        uint8_t address = mse_get_device_address(device);
        uint32_t temp;
        uint32_t wake;
        uint16_t rxlen;

        do
        {
            if (100000UL < iface->mIfaceCFG->i2c.baud)
            {
                temp = 100000UL;
                status = iocontrol(iface, MSE_HAL_CHANGE_BAUD, &temp, sizeof(temp));
                if (MSE_UNIMPLEMENTED == status)
                {
                    status = iocontrol(iface, MSE_HAL_CONTROL_WAKE, NULL, 0);
                    break;
                }
            }
            else
            {
                status = MSE_SUCCESS;
            }

            (void)iosend(iface, 0x00, &second_byte, 0);

            // mse_delay_us(mse_iface_get_wake_delay(iface)); 在高通信速率时，us可能不准，因此直接调用ms
            mse_delay_ms(2); // delay ms误差不应太大

            rxlen = sizeof(wake);
            if (MSE_SUCCESS == status)
            {
                status = ioreceive(iface, address, (uint8_t *)&wake, &rxlen);
            }

            if ((MSE_SUCCESS == status) && (100000UL < iface->mIfaceCFG->i2c.baud))
            {
                temp = iface->mIfaceCFG->i2c.baud;
                status = iocontrol(iface, MSE_HAL_CHANGE_BAUD, &temp, sizeof(temp));
            }

            if (MSE_SUCCESS == status)
            {
                status = hal_check_wake((uint8_t *)&wake, rxlen);
            }
        } while (0 < retries-- && MSE_SUCCESS != status);
    }
    return status;
}

/** \brief wakeup the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_wakeup(MSEDevice device)
{
    MSE_STATUS status = MSE_BAD_PARAM;
    MSEIface iface = ioGetIFace(device);

    if (iface && iface->mIfaceCFG)
    {
#ifdef MSE_HAL_LEGACY_API
        status = iowake(iface);
#else
        if (mse_iface_is_kit(iface) || mse_iface_is_swi(&device->mIface))
        {
            status = iowake(iface);
        }
        else if (MSE_I2C_IFACE == iface->mIfaceCFG->iface_type)
        {
            status = calib_wakeup_i2c(device);
        }
        else
        {
            status = MSE_SUCCESS;
        }
#endif
    }

    return status;
}

/** \brief idle the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_idle(MSEDevice device)
{
    MSE_STATUS status = MSE_BAD_PARAM;

#ifdef MSE_HAL_LEGACY_API
    status = ioidle(&device->mIface);
#else
    if (mse_iface_is_kit(&device->mIface) || mse_iface_is_swi(&device->mIface))
    {
        status = ioidle(&device->mIface);
    }
    else
    {
        uint8_t command = 0x02;
        status = iosend(&device->mIface, mse_get_device_address(device), &command, 1);
    }
#endif
    return status;
}

/** \brief invoke sleep on the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sleep(MSEDevice device)
{
    MSE_STATUS status = MSE_BAD_PARAM;

#ifdef MSE_HAL_LEGACY_API
    status = iosleep(&device->mIface);
#else
    if (mse_iface_is_kit(&device->mIface) || mse_iface_is_swi(&device->mIface))
    {
        status = iosleep(&device->mIface);
    }
    else
    {
        uint8_t command = 0x01;
        status = iosend(&device->mIface, mse_get_device_address(device), &command, 1);
    }
#endif
    return status;
}

/** \brief common cleanup code which idles the device after any operation
 *  \param[in] device     Device context pointer
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS _calib_exit(MSEDevice device) { return calib_idle(device); }

/** \brief Compute the address given the zone, slot, block, and offset
 *  \param[in] zone   Zone to get address from. Config(0), OTP(1), or
 *                    Data(2) which requires a slot.
 *  \param[in] slot   Slot Id number for data zone and zero for other zones.
 *  \param[in] block  Block number within the data or configuration or OTP zone .
 *  \param[in] offset Offset Number within the block of data or configuration or OTP zone.
 *  \param[out] addr  Pointer to the address of data or configuration or OTP zone.
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t *addr)
{
    MSE_STATUS status = MSE_SUCCESS;
    uint8_t mem_zone = zone & 0x03;

    if (addr == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }
    if ((mem_zone != MSE_ZONE_CONFIG) && (mem_zone != MSE_ZONE_DATA) && (mem_zone != MSE_ZONE_OTP))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Invalid zone received");
    }
    do
    {
        // Initialize the addr to 00
        *addr = 0;
        // Mask the offset
        offset = offset & (uint8_t)0x07;
        if ((mem_zone == MSE_ZONE_CONFIG) || (mem_zone == MSE_ZONE_OTP))
        {
            *addr = ((uint16_t)block) << 3;
            *addr |= offset;
        }
        else // MSE_ZONE_DATA
        {
            *addr = slot << 3;
            *addr |= offset;
            *addr |= ((uint16_t)block) << 8;
        }
    } while (0);

    return status;
}

/** \brief Gets the size of the specified zone in bytes.
 *
 * \param[in]  device  Device context pointer
 * \param[in]  zone    Zone to get size information from. Config(0), OTP(1), or
 *                     Data(2) which requires a slot.
 * \param[in]  slot    If zone is Data(2), the slot to query for size.
 * \param[out] size    Zone size is returned here.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_get_zone_size(MSEDevice device, uint8_t zone, uint16_t slot, size_t *size)
{
    MSE_STATUS status = MSE_SUCCESS;

    if ((device == NULL) || (size == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    if (device->mIface.mIfaceCFG->devtype == SHA20)
    {
        switch (zone)
        {
        case MSE_ZONE_CONFIG:
            *size = 88;
            break;
        case MSE_ZONE_OTP:
            *size = 64;
            break;
        case MSE_ZONE_DATA:
            *size = 32;
            break;
        default:
            status = MSE_TRACE(MSE_BAD_PARAM, "Invalid zone received");
            break;
        }
    }
    else if (device->mIface.mIfaceCFG->devtype == SHA20A)
    {
        switch (zone)
        {
        case MSE_ZONE_CONFIG:
            *size = 88;
            break;
        case MSE_ZONE_OTP:
            *size = 0;
            break;
        case MSE_ZONE_DATA:
            *size = 32;
            break;
        default:
            status = MSE_TRACE(MSE_BAD_PARAM, "Invalid zone received");
            break;
        }
    }
    else
    {
        switch (zone)
        {
        case MSE_ZONE_CONFIG:
            *size = 128;
            break;
        case MSE_ZONE_OTP:
            *size = 64;
            break;
        case MSE_ZONE_DATA:
            if (slot < 8)
            {
                *size = 36;
            }
            else if (slot == 8)
            {
                *size = 416;
            }
            else if (slot < 16)
            {
                *size = 72;
            }
            else
            {
                status = MSE_TRACE(MSE_BAD_PARAM, "Invalid slot received");
            }
            break;
        default:
            status = MSE_TRACE(MSE_BAD_PARAM, "Invalid zone received");
            break;
        }
    }

    return status;
}

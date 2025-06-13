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

#include "mse_basic.h"
#include "mse_version.h"

#if defined(MSE_USE_CONSTANT_HOST_NONCE)
#if defined(_MSC_VER)
#pragma message("Warning : Using a constant host nonce with mse_read_enc, mse_write_enc, etcc., can allow spoofing of a device by replaying previously recorded messages")
#else
#warning "Using a constant host nonce with mse_read_enc, mse_write_enc, etcc., can allow spoofing of a device by replaying previously recorded messages"
#endif
#endif

const char mselib_version[] = MSE_LIBRARY_VERSION_DATE;
MSEDevice _gDevice = NULL;
#ifdef MSE_NO_HEAP
SHARED_LIB_EXPORT struct mse_iface g_mse_iface;
SHARED_LIB_EXPORT struct mse_device g_mse_device;
#endif

/** \brief basic API methods are all prefixed with mse_  (CryptoAuthLib Basic)
 *  the fundamental premise of the basic API is it is based on a single interface
 *  instance and that instance is global, so all basic API commands assume that
 *  one global device is the one to operate on.
 */

/** \brief returns a version string for the CryptoAuthLib release.
 *  The format of the version string returned is "yyyymmdd"
 * \param[out] ver_str ptr to space to receive version string
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mse_version(char *ver_str)
{
    strcpy(ver_str, mselib_version);
    return MSE_SUCCESS;
}


/** \brief Creates and initializes a MSEDevice context
 *  \param[out] device Pointer to the device context pointer
 *  \param[in]  cfg    Logical interface configuration. Some predefined
 *                     configurations can be found in mse_cfgs.h
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mse_init_ext(MSEDevice* device, MSEIfaceCfg *cfg)
{
    MSE_STATUS status = MSE_GEN_FAIL;

    if (device)
    {
        // If a device has already been initialized, release it
        if (*device)
        {
            mse_release_ext(device);
        }

#ifdef MSE_NO_HEAP
        g_mse_device.mIface = g_mse_iface;
        status = initMSEDevice(cfg, &g_mse_device);
        if (status != MSE_SUCCESS)
        {
            return status;
        }
        *device = &g_mse_device;
#else
        *device = newMSEDevice(cfg);
        if (*device == NULL)
        {
            return MSE_GEN_FAIL;
        }
#endif

#ifdef MSE_MOD8_SUPPORT
        if (cfg->devtype == MOD8)
        {
            if ((status = calib_read_bytes_zone(*device, MSE_ZONE_CONFIG, 0, MSE_CHIPMODE_OFFSET, &(*device)->clock_divider, 1)) != MSE_SUCCESS)
            {
                return status;
            }
            (*device)->clock_divider &= MSE_CHIPMODE_CLOCK_DIV_MASK;
        }
#endif


    }

    return MSE_SUCCESS;
}

/** \brief Creates a global MSEDevice object used by Basic API.
 *  \param[in] cfg  Logical interface configuration. Some predefined
 *                  configurations can be found in mse_cfgs.h
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mse_init(MSEIfaceCfg* cfg)
{
    return mse_init_ext(&_gDevice, cfg);
}

/** \brief Initialize the global MSEDevice object to point to one of your
 *         choosing for use with all the mse_ basic API.
 *
 * \deprecated This function is not recommended for use generally. Use of _ext
 * is recommended instead. You can use mse_init_ext to obtain an initialized
 * instance and associated it with the global structure - but this shouldn't be
 * a required process except in extremely unusual circumstances.
 *
 *  \param[in] ca_device  MSEDevice instance to use as the global Basic API
 *                        crypto device instance
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS mse_init_device(MSEDevice ca_device)
{
    if (ca_device == NULL)
    {
        return MSE_BAD_PARAM;
    }

    // if there's already a device created, release it
    if (_gDevice)
    {
        mse_release();
    }

    _gDevice = ca_device;

    return MSE_SUCCESS;
}

/** \brief release (free) the an MSEDevice instance.
 *  \param[in]  device      Pointer to the device context pointer
 *  \return Returns MSE_SUCCESS .
 */
MSE_STATUS mse_release_ext(MSEDevice* device)
{
#ifdef MSE_NO_HEAP
    MSE_STATUS status = releaseMSEDevice(*device);
    if (status != MSE_SUCCESS)
    {
        return status;
    }
    *device = NULL;
#else
    deleteMSEDevice(device);
#endif
    return MSE_SUCCESS;
}

/** \brief release (free) the global MSEDevice instance.
 *  This must be called in order to release or free up the interface.
 *  \return Returns MSE_SUCCESS .
 */
MSE_STATUS mse_release(void)
{
    return mse_release_ext(&_gDevice);
}

/** \brief Get the global device object.
 *  \return instance of global MSEDevice
 */
MSEDevice mse_get_device(void)
{
    return _gDevice;
}

/** \brief Get the selected device type of rthe device context
 *
 *  \param[in]  device      Device context pointer
 *  \return Device type if basic api is initialized or MSE_DEV_UNKNOWN.
 */
MSEDeviceType mse_get_device_type_ext(MSEDevice device)
{
    MSEDeviceType ret = MSE_DEV_UNKNOWN;

    if (device && device->mIface.mIfaceCFG)
    {
        ret = device->mIface.mIfaceCFG->devtype;
    }
    return ret;
}

/** \brief Get the current device type configured for the global MSEDevice
 *  \return Device type if basic api is initialized or MSE_DEV_UNKNOWN.
 */
MSEDeviceType mse_get_device_type(void)
{
    return mse_get_device_type_ext(_gDevice);
}

/** \brief Get the current device address based on the configured device
 * and interface
 * \return the device address if applicable else 0xFF
 */
uint8_t mse_get_device_address(MSEDevice device)
{
    if (device && device->mIface.mIfaceCFG)
    {
        switch (device->mIface.mIfaceCFG->iface_type)
        {
        case MSE_I2C_IFACE:
            return device->mIface.mIfaceCFG->i2c.address;
        default:
            break;
        }
    }
    return 0xFF;
}


/** \brief Check whether the device is cryptoauth device
 *  \return True if device is cryptoauth device or False.
 */
bool mse_is_ca_device(MSEDeviceType dev_type)
{
    return (dev_type < MSE_DEV_UNKNOWN) ? true : false;
}


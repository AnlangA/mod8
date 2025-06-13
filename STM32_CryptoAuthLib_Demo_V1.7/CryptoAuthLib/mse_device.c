/**
 * \file
 * \brief  ModSemi CryptoAuth device object
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

#include <cryptoauthlib.h>

/** \defgroup device MSEDevice (mse_)
 * \brief MSEDevice object - composite of command and interface objects
   @{ */


#ifndef MSE_NO_HEAP
/** \brief constructor for a ModSemi CryptoAuth device
 * \param[in] cfg  Interface configuration object
 * \return Reference to a new MSEDevice on success. NULL on failure.
 */
MSEDevice newMSEDevice(MSEIfaceCfg *cfg)
{
    MSEDevice ca_dev = NULL;
    MSE_STATUS status;

    if (cfg == NULL)
    {
        return NULL;
    }

    ca_dev = (MSEDevice)hal_malloc(sizeof(*ca_dev));
    if (ca_dev == NULL)
    {
        return NULL;
    }

    memset(ca_dev, 0, sizeof(struct mse_device));

    status = initMSEDevice(cfg, ca_dev);
    if (status != MSE_SUCCESS)
    {
        hal_free(ca_dev);
        ca_dev = NULL;
        return NULL;
    }

    return ca_dev;
}

/** \brief destructor for a device NULLs reference after object is freed
 * \param[in] ca_dev  pointer to a reference to a device
 */
void deleteMSEDevice(MSEDevice *ca_dev)
{
    if (ca_dev == NULL)
    {
        return;
    }

    releaseMSEDevice(*ca_dev);

    hal_free(*ca_dev);
    *ca_dev = NULL;
}
#endif

/** \brief Initializer for an ModSemi CryptoAuth device
 * \param[in]    cfg     pointer to an interface configuration object
 * \param[in,out] ca_dev  As input, pre-allocated structure to be initialized.
 *                       mCommands and mIface members should point to existing
 *                       structures to be initialized.
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS initMSEDevice(MSEIfaceCfg *cfg, MSEDevice ca_dev)
{
    MSE_STATUS status;

    if (cfg == NULL || ca_dev == NULL)
    {
        return MSE_BAD_PARAM;
    }

    status = initMSEIface(cfg, &ca_dev->mIface);
    if (status != MSE_SUCCESS)
    {
        return status;
    }

    return MSE_SUCCESS;
}

/** \brief returns a reference to the MSEIface interface object for the device
 * \param[in] dev  reference to a device
 * \return reference to the MSEIface object for the device
 */
MSEIface ioGetIFace(MSEDevice dev)
{
    return &dev->mIface;
}

/** \brief Release any resources associated with the device.
 *  \param[in] ca_dev  Device to release
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS releaseMSEDevice(MSEDevice ca_dev)
{
    if (ca_dev == NULL)
    {
        return MSE_BAD_PARAM;
    }

    return releaseMSEIface(&ca_dev->mIface);
}

/** @} */

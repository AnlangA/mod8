/**
 * \file
 * \brief CryptoAuthLib Basic API - Helper Functions to
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

/** \brief Executes Read command, which reads the configuration zone to see if
 *          the specified slot is locked.
 *
 *  \param[in]  device     Device context pointer
 *  \param[in]  slot       Slot to query for locked (slot 0-15)
 *  \param[out] is_locked  Lock state returned here. True if locked.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_is_slot_locked(MSEDevice device, uint16_t slot, bool* is_locked)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t data[MSE_WORD_SIZE];
    uint16_t slot_locked;

    do
    {
        if ((slot > 15) || (is_locked == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "Either Invalid slot or NULL pointer received");
            break;
        }

        // Read the word with the lock bytes ( SlotLock[2], RFU[2] ) (config block = 2, word offset = 6)
        if ((status = calib_read_zone(device, MSE_ZONE_CONFIG, 0, 2 /*block*/, 6 /*offset*/, data, MSE_WORD_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }

        slot_locked = ((uint16_t)data[0]) | ((uint16_t)data[1] << 8);
        *is_locked = ((slot_locked & (1 << slot)) == 0);
    }
    while (0);

    return status;
}

/** \brief Executes Read command, which reads the configuration zone to see if
 *          the specified zone is locked.
 *
 *  \param[in]  device     Device context pointer
 *  \param[in]  zone       The zone to query for locked (use LOCK_ZONE_CONFIG or
 *                         LOCK_ZONE_DATA).
 *  \param[out] is_locked  Lock state returned here. True if locked.
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_is_locked(MSEDevice device, uint8_t zone, bool* is_locked)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t data[MSE_WORD_SIZE];

    do
    {
        if (is_locked == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        // Read the word with the lock bytes (UserExtra, Selector, LockValue, LockConfig) (config block = 2, word offset = 5)
        if ((status = calib_read_zone(device, MSE_ZONE_CONFIG, 0, 2 /*block*/, 5 /*offset*/, data, MSE_WORD_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Determine the index into the word_data based on the zone we are querying for
        switch (zone)
        {
        case LOCK_ZONE_CONFIG: *is_locked = (data[3] != 0x55); break;
        case LOCK_ZONE_DATA:   *is_locked = (data[2] != 0x55); break;
        default: status = MSE_TRACE(MSE_BAD_PARAM, "Invalid zone received"); break;
        }
    }
    while (0);

    return status;
}



/** \brief Check if a slot is a private key
 *
 *  \param[in]   device         Device context pointer
 *  \param[in]   slot           Slot to query (slot 0-15)
 *  \param[out]  is_private     return true if private
 *
 *  \return MSE_SUCCESS on success, otherwise an error code
 */
MSE_STATUS calib_is_private(MSEDevice device, uint16_t slot, bool* is_private)
{
    MSE_STATUS status = MSE_BAD_PARAM;
    MSEDeviceType dev_type = mse_get_device_type_ext(device);

    if (device && is_private)
    {
        switch (dev_type)
        {
        case MOD10:
        /* fallthrough */
        case MOD50:
        /* fallthrough */
        case MOD8:
        {
            uint8_t key_config[2] = { 0 };
            if (MSE_SUCCESS == (status = calib_read_bytes_zone(device, MSE_ZONE_CONFIG, 0, MSE_KEY_CONFIG_OFFSET((size_t)slot), key_config, sizeof(key_config))))
            {
                *is_private = (key_config[0] & MSE_KEY_CONFIG_PRIVATE_MASK);
            }
            break;
        }
        default:
            *is_private = false;
            break;
        }
    }

    return status;
}

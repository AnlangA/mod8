/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Read command.
 *
 * The Read command reads words either 4-byte words or 32-byte blocks from one
 * of the memory zones of the device. The data may optionally be encrypted
 * before being returned to the system.
 *
 * \note List of devices that support this command - SHA20, MOD10,
 *       MOD50, MOD8A/B. There are differences in the modes that they
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
#include "host/mse_host.h"

/** \brief Executes Read command, which reads either 4 or 32 bytes of data from
 *          a given slot, configuration zone, or the OTP zone.
 *
 *   When reading a slot or OTP, data zone must be locked and the slot
 *   configuration must not be secret for a slot to be successfully read.
 *
 *  \param[in]  device   Device context pointer
 *  \param[in]  zone     Zone to be read from device. Options are
 *                       MSE_ZONE_CONFIG, MSE_ZONE_OTP, or MSE_ZONE_DATA.
 *  \param[in]  slot     Slot number for data zone and ignored for other zones.
 *  \param[in]  block    32 byte block index within the zone.
 *  \param[in]  offset   4 byte work index within the block. Ignored for 32 byte
 *                       reads.
 *  \param[out] data     Read data is returned here.
 *  \param[in]  len      Length of the data to be read. Must be either 4 or 32.
 *
 *  returns MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_read_zone(MSEDevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t *data, uint8_t len)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;
    uint16_t addr;

    do
    {
        // Check the input parameters
        if ((device == NULL) || (data == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        if (len != 4 && len != 32)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "Invalid length received");
            break;
        }

        // The get address function checks the remaining variables
        if ((status = calib_get_addr(zone, slot, block, offset, &addr)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_get_addr - failed");
            break;
        }

        // If there are 32 bytes to read, then OR the bit into the mode
        if (len == MSE_BLOCK_SIZE)
        {
            zone = zone | MSE_ZONE_READWRITE_32;
        }

        // build a read command
        packet.param1 = zone;
        packet.param2 = addr;

        if ((status = bpRead(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpRead - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - execution failed");
            break;
        }

        memcpy(data, &packet.data[1], len);
    }
    while (0);

    return status;
}
/** \brief Executes Read command, which reads the 9 byte serial number of the
 *          device from the config zone.
 *
 *  \param[in]  device         Device context pointer
 *  \param[out] serial_number  9 byte serial number is returned here.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_read_serial_number(MSEDevice device, uint8_t* serial_number)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t read_buf[MSE_BLOCK_SIZE];

    if (!serial_number)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        if ((status = calib_read_zone(device, MSE_ZONE_CONFIG, 0, 0, 0, read_buf, MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }
        memcpy(&serial_number[0], &read_buf[0], 4);
        memcpy(&serial_number[4], &read_buf[8], 5);
    }
    while (0);

    return status;
}


/** \brief Executes Read command on a slot configured for encrypted reads and
 *          decrypts the data to return it as plaintext.
 *
 * Data zone must be locked for this command to succeed. Can only read 32 byte
 * blocks.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  key_id      The slot ID to read from.
 *  \param[in]  block       Index of the 32 byte block within the slot to read.
 *  \param[out] data        Decrypted (plaintext) data from the read is returned
 *                          here (32 bytes).
 *  \param[in]  enc_key     32 byte ReadKey for the slot being read.
 *  \param[in]  enc_key_id  KeyID of the ReadKey being used.
 *  \param[in]  num_in      20 byte host nonce to inject into Nonce calculation
 *
 *  returns MSE_SUCCESS on success, otherwise an error code.
 */
#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_read_enc(MSEDevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id)
{
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

#else
MSE_STATUS calib_read_enc(MSEDevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE])
{
#endif
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t zone = MSE_ZONE_DATA | MSE_ZONE_READWRITE_32;
    mse_nonce_in_out_t nonce_params;
    mse_gen_dig_in_out_t gen_dig_param;
    mse_temp_key_t temp_key;
    uint8_t serial_num[32];
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t other_data[4] = { 0 };
    int i = 0;

    do
    {
        // Verify inputs parameters
        if (data == NULL || enc_key == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        // Read the device SN
        if ((status = calib_read_zone(device, MSE_ZONE_CONFIG, 0, 0, 0, serial_num, 32)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }
        // Make the SN continuous by moving SN[4:8] right after SN[0:3]
        memmove(&serial_num[4], &serial_num[8], 5);

        // Send the random Nonce command
        if ((status = calib_nonce_rand(device, num_in, rand_out)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Nonce failed"); break;
        }

        // Calculate Tempkey
        memset(&temp_key, 0, sizeof(temp_key));
        memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = (uint8_t*)&num_in[0];
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &temp_key;
        if ((status = mseh_nonce(&nonce_params)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Calc TempKey failed"); break;
        }

        // Supply OtherData so GenDig behavior is the same for keys with SlotConfig.NoMac set
        other_data[0] = MSE_GENDIG;
        other_data[1] = GENDIG_ZONE_DATA;
        other_data[2] = (uint8_t)(enc_key_id);
        other_data[3] = (uint8_t)(enc_key_id >> 8);

        // Send the GenDig command
        if ((status = calib_gendig(device, GENDIG_ZONE_DATA, enc_key_id, other_data, sizeof(other_data))) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "GenDig failed"); break;
        }

        // Calculate Tempkey
        // NoMac bit isn't being considered here on purpose to remove having to read SlotConfig.
        // OtherData is built to get the same result regardless of the NoMac bit.
        memset(&gen_dig_param, 0, sizeof(gen_dig_param));
        gen_dig_param.key_id = enc_key_id;
        gen_dig_param.is_key_nomac = false;
        gen_dig_param.sn = serial_num;
        gen_dig_param.stored_value = enc_key;
        gen_dig_param.zone = GENDIG_ZONE_DATA;
        gen_dig_param.other_data = other_data;
        gen_dig_param.temp_key = &temp_key;
        if ((status = mseh_gen_dig(&gen_dig_param)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, ""); break;
        }

        // Read Encrypted
        if ((status = calib_read_zone(device, zone, key_id, block, 0, data, MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Read encrypted failed"); break;
        }

        // Decrypt
        for (i = 0; i < MSE_BLOCK_SIZE; i++)
        {
            data[i] = data[i] ^ temp_key.value[i];
        }

        status = MSE_SUCCESS;

    }
    while (0);


    return status;
}

/** \brief Executes Read command to read the complete device configuration
 *          zone.
 *
 *  \param[in]  device       Device context pointer
 *  \param[out] config_data  Configuration zone data is returned here. 88 bytes
 *                           for SHA devices, 128 bytes for MOD_ECC devices.
 *
 *  \returns MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_read_config_zone(MSEDevice device, uint8_t* config_data)
{
    MSE_STATUS status = MSE_GEN_FAIL;

    do
    {
        // Verify the inputs
        if (config_data == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        if (mseIsSHAFamily(device->mIface.mIfaceCFG->devtype))
        {
            status = calib_read_bytes_zone(device, MSE_ZONE_CONFIG, 0, 0x00, config_data, MSE_SHA_CONFIG_SIZE);
        }
        else
        {
            status = calib_read_bytes_zone(device, MSE_ZONE_CONFIG, 0, 0x00, config_data, MSE_ECC_CONFIG_SIZE);
        }

        if (status != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_bytes_zone - failed");
            break;
        }

    }
    while (0);

    return status;
}

/** \brief Compares a specified configuration zone with the configuration zone
 *          currently on the device.
 *
 * This only compares the static portions of the configuration zone and skips
 * those that are unique per device (first 16 bytes) and areas that can change
 * after the configuration zone has been locked (e.g. LastKeyUse).
 *
 * \param[in]  device       Device context pointer
 * \param[in]  config_data  Full configuration data to compare the device
 *                          against.
 * \param[out] same_config  Result is returned here. True if the static portions
 *                          on the configuration zones are the same.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_cmp_config_zone(MSEDevice device, uint8_t* config_data, bool* same_config)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t device_config_data[MSE_ECC_CONFIG_SIZE];   /** Max for all configs */
    size_t config_size = 0;

    do
    {
        // Check the inputs
        if ((config_data == NULL) || (same_config == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }
        // Set the boolean to false
        *same_config = false;

        // Read all of the configuration bytes from the device
        if ((status = calib_read_config_zone(device, device_config_data)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Read config zone failed"); break;
        }

        /* Get the config size of the device being tested */
        if (MSE_SUCCESS != (status = calib_get_zone_size(device, MSE_ZONE_CONFIG, 0, &config_size)))
        {
            MSE_TRACE(status, "Failed to get config zone size"); break;
        }

        /* Compare the lower writable bytes (16-51) */
        if (memcmp(&device_config_data[16], &config_data[16], 52 - 16))
        {
            /* Difference found */
            break;
        }

        if (MOD8 == device->mIface.mIfaceCFG->devtype)
        {
            /* Skip Counter[0], Counter[1], which can change during operation */

            /* Compare UseLock through Reserved (68 --> 83) */
            if (memcmp(&device_config_data[68], &config_data[68], 84 - 68))
            {
                /* Difference found */
                break;
            }

            /* Skip UserExtra, UserExtraAdd, LockValue, LockConfig, and SlotLocked */

        }
        else
        {
            /* Skip the counter & LastKeyUse bytes [52-83] */
            /* Skip User Extra & Selector [84-85] */
            /* Skip all lock bytes [86-89] */
        }

        if (90 < config_size)
        {
            /* Compare the upper writable bytes (90-config_size) */
            if (memcmp(&device_config_data[90], &config_data[90], config_size - 90))
            {
                /* Difference found */
                break;
            }
        }

        /* All Matched */
        *same_config = true;
    }
    while (0);

    return status;
}


/** \brief Executes Read command to read a 64 byte ECDSA P256 signature from a
 *          slot configured for clear reads.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  slot    Slot number to read from. Only slots 8 to 15 are large
 *                      enough for a signature.
 *  \param[out] sig     Signature will be returned here (64 bytes). Format will be
 *                      the 32 byte R and S big-endian integers concatenated.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_read_sig(MSEDevice device, uint16_t slot, uint8_t* sig)
{
    MSE_STATUS status = MSE_GEN_FAIL;

    do
    {
        // Check the value of the slot
        if (sig == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
            break;
        }

        if (slot < 8 || slot > 15)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "Invalid slot received");
            break;
        }

        // Read the first block
        if ((status = calib_read_zone(device, MSE_ZONE_DATA, slot, 0, 0, &sig[0], MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Read the second block
        if ((status = calib_read_zone(device, MSE_ZONE_DATA, slot, 1, 0, &sig[MSE_BLOCK_SIZE], MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }
    }
    while (0);

    return status;
}

/** \brief Executes Read command to read an ECC P256 public key from a slot
 *          configured for clear reads.
 *
 * This function assumes the public key is stored using the ECC public key
 * format specified in the datasheet.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  slot        Slot number to read from. Only slots 8 to 15 are
 *                          large enough for a public key.
 *  \param[out] public_key  Public key is returned here (64 bytes). Format will
 *                          be the 32 byte X and Y big-endian integers
 *                          concatenated.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_read_pubkey(MSEDevice device, uint16_t slot, uint8_t *public_key)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t read_buf[MSE_BLOCK_SIZE];
    uint8_t block = 0;
    uint8_t offset = 0;
    uint8_t cpy_index = 0;
    uint8_t cpy_size = 0;
    uint8_t read_index = 0;

    // Check the pointers
    if (public_key == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }
    // Check the value of the slot
    if (slot < 8 || slot > 0xF)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Invalid slot received");
    }

    do
    {
        // The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
        // | Block 1                     | Block 2                                      | Block 3       |
        // | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

        // Read the block
        block = 0;
        if ((status = calib_read_zone(device, MSE_ZONE_DATA, slot, block, offset, read_buf, MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Copy.  Account for 4 byte pad
        cpy_size = MSE_BLOCK_SIZE - MSE_PUB_KEY_PAD;
        read_index = MSE_PUB_KEY_PAD;
        memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);
        cpy_index += cpy_size;

        // Read the next block
        block = 1;
        if ((status = calib_read_zone(device, MSE_ZONE_DATA, slot, block, offset, read_buf, MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Copy.  First four bytes
        cpy_size = MSE_PUB_KEY_PAD;
        read_index = 0;
        memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);
        cpy_index += cpy_size;
        // Copy.  Skip four bytes
        read_index = MSE_PUB_KEY_PAD + MSE_PUB_KEY_PAD;
        cpy_size = MSE_BLOCK_SIZE - read_index;
        memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);
        cpy_index += cpy_size;

        // Read the next block
        block = 2;
        if ((status = calib_read_zone(device, MSE_ZONE_DATA, slot, block, offset, read_buf, MSE_BLOCK_SIZE)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Copy.  The remaining 8 bytes
        cpy_size = MSE_PUB_KEY_PAD + MSE_PUB_KEY_PAD;
        read_index = 0;
        memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);

    }
    while (0);

    return status;
}

/** \brief Used to read an arbitrary number of bytes from any zone configured
 *          for clear reads.
 *
 * This function will issue the Read command as many times as is required to
 * read the requested data.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  zone    Zone to read data from. Option are MSE_ZONE_CONFIG(0),
 *                      MSE_ZONE_OTP(1), or MSE_ZONE_DATA(2).
 *  \param[in]  slot    Slot number to read from if zone is MSE_ZONE_DATA(2).
 *                      Ignored for all other zones.
 *  \param[in]  offset  Byte offset within the zone to read from.
 *  \param[out] data    Read data is returned here.
 *  \param[in]  length  Number of bytes to read starting from the offset.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_read_bytes_zone(MSEDevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    size_t zone_size = 0;
    uint8_t read_buf[32];
    size_t data_idx = 0;
    size_t cur_block = 0;
    size_t cur_offset = 0;
    uint8_t read_size = MSE_BLOCK_SIZE;
    size_t read_buf_idx = 0;
    size_t copy_length = 0;
    size_t read_offset = 0;

    if (zone != MSE_ZONE_CONFIG && zone != MSE_ZONE_OTP && zone != MSE_ZONE_DATA)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Invalid zone received");
    }
    if (zone == MSE_ZONE_DATA && slot > 15)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Invalid slot received");
    }
    if (length == 0)
    {
        return MSE_SUCCESS;  // Always succeed reading 0 bytes
    }
    if (data == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        if (MSE_SUCCESS != (status = calib_get_zone_size(device, zone, slot, &zone_size)))
        {
            MSE_TRACE(status, "calib_get_zone_size - failed");
            break;
        }
        if (offset + length > zone_size)
        {
            return MSE_TRACE(MSE_BAD_PARAM, "Invalid parameter received"); // Can't read past the end of a zone

        }
        cur_block = offset / MSE_BLOCK_SIZE;

        while (data_idx < length)
        {
            if (read_size == MSE_BLOCK_SIZE && zone_size - cur_block * MSE_BLOCK_SIZE < MSE_BLOCK_SIZE)
            {
                // We have less than a block to read and can't read past the end of the zone, switch to word reads
                read_size = MSE_WORD_SIZE;
                cur_offset = ((data_idx + offset) / MSE_WORD_SIZE) % (MSE_BLOCK_SIZE / MSE_WORD_SIZE);
            }

            // Read next chunk of data
            if (MSE_SUCCESS != (status = calib_read_zone(device, zone, slot, (uint8_t)cur_block, (uint8_t)cur_offset, read_buf, read_size)))
            {
                MSE_TRACE(status, "calib_read_zone - falied");
                break;
            }

            // Calculate where in the read buffer we need data from
            read_offset = cur_block * MSE_BLOCK_SIZE + cur_offset * MSE_WORD_SIZE;
            if (read_offset < offset)
            {
                read_buf_idx = offset - read_offset;  // Read data starts before the requested chunk
            }
            else
            {
                read_buf_idx = 0;                     // Read data is within the requested chunk

            }
            // Calculate how much data from the read buffer we want to copy
            if (length - data_idx < read_size - read_buf_idx)
            {
                copy_length = length - data_idx;
            }
            else
            {
                copy_length = read_size - read_buf_idx;
            }

            memcpy(&data[data_idx], &read_buf[read_buf_idx], copy_length);
            data_idx += copy_length;
            if (read_size == MSE_BLOCK_SIZE)
            {
                cur_block += 1;
            }
            else
            {
                cur_offset += 1;
            }
        }
        if (status != MSE_SUCCESS)
        {
            break;
        }
    }
    while (false);

    return status;
}



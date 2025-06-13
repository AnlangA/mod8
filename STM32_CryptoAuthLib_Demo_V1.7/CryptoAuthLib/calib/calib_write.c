/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Write command.
 *
 * The Write command writes either one 4-byte word or a 32-byte block to one of
 * the EEPROM zones on the device. Depending upon the value of the WriteConfig
 * byte for a slot, the data may be required to be encrypted by the system prior
 * to being sent to the device
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
#include "host/mse_host.h"

/**
 * \brief Executes the Write command, which writes either one four byte word or
 *        a 32-byte block to one of the EEPROM zones on the device. Depending
 *        upon the value of the WriteConfig byte for this slot, the data may be
 *        required to be encrypted by the system prior to being sent to the
 *        device. This command cannot be used to write slots configured as ECC
 *        private keys.
 *
 * \param[in] device   Device context pointer
 * \param[in] zone     Zone/Param1 for the write command.
 * \param[in] address  Address/Param2 for the write command.
 * \param[in] value    Plain-text data to be written or cipher-text for
 *                     encrypted writes. 32 or 4 bytes depending on bit 7 in the
 *                     zone.
 * \param[in] mac      MAC required for encrypted writes (32 bytes). Set to NULL
 *                     if not required.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_write(MSEDevice device, uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;

    if ((device == NULL) || (value == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        // Build the write command
        packet.param1 = zone;
        packet.param2 = address;
        if (zone & MSE_ZONE_READWRITE_32)
        {
            // 32-byte write
            memcpy(packet.data, value, 32);
            // Only 32-byte writes can have a MAC
            if (mac)
            {
                memcpy(&packet.data[32], mac, 32);
            }
        }
        else
        {
            // 4-byte write
            memcpy(packet.data, value, 4);
        }

        if ((status = bpWrite(mse_get_device_type_ext(device), &packet, mac && (zone & MSE_ZONE_READWRITE_32))) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpWrite - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_write - execution failed");
            break;
        }

    }
    while (0);

    return status;
}

/** \brief Executes the Write command, which writes either 4 or 32 bytes of
 *          data into a device zone.
 *
 *  \param[in] device  Device context pointer
 *  \param[in] zone    Device zone to write to (0=config, 1=OTP, 2=data).
 *  \param[in] slot    If writing to the data zone, it is the slot to write to,
 *                     otherwise it should be 0.
 *  \param[in] block   32-byte block to write to.
 *  \param[in] offset  4-byte word within the specified block to write to. If
 *                     performing a 32-byte write, this should be 0.
 *  \param[in] data    Data to be written.
 *  \param[in] len     Number of bytes to be written. Must be either 4 or 32.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_write_zone(MSEDevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint16_t addr;

    // Check the input parameters
    if (data == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    if (len != 4 && len != 32)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Invalid length received");
    }

    do
    {
        // The get address function checks the remaining variables
        if ((status = calib_get_addr(zone, slot, block, offset, &addr)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_get_addr - failed");
            break;
        }

        // If there are 32 bytes to write, then xor the bit into the mode
        if (len == MSE_BLOCK_SIZE)
        {
            zone = zone | MSE_ZONE_READWRITE_32;
        }

        status = calib_write(device, zone, addr, data, NULL);

    }
    while (0);

    return status;
}


/** \brief Executes the Write command, which performs an encrypted write of
 *          a 32 byte block into given slot.
 *
 * The function takes clear text bytes and encrypts them for writing over the
 * wire. Data zone must be locked and the slot configuration must be set to
 * encrypted write for the block to be successfully written.
 *
 *  \param[in] device      Device context pointer
 *  \param[in] key_id      Slot ID to write to.
 *  \param[in] block       Index of the 32 byte block to write in the slot.
 *  \param[in] data        32 bytes of clear text data to be written to the slot
 *  \param[in] enc_key     WriteKey to encrypt with for writing
 *  \param[in] enc_key_id  The KeyID of the WriteKey
 *  \param[in]  num_in       20 byte host nonce to inject into Nonce calculation
 *
 *  returns MSE_SUCCESS on success, otherwise an error code.
 */

#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_write_enc(MSEDevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id)
{
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

#else
MSE_STATUS calib_write_enc(MSEDevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE])
{
#endif
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t zone = MSE_ZONE_DATA | MSE_ZONE_READWRITE_32;
    mse_nonce_in_out_t nonce_params;
    mse_gen_dig_in_out_t gen_dig_param;
    mse_write_mac_in_out_t write_mac_param;
    mse_temp_key_t temp_key;
    uint8_t serial_num[32];
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t cipher_text[MSE_KEY_SIZE] = { 0 };
    uint8_t mac[WRITE_MAC_SIZE] = { 0 };
    uint8_t other_data[4] = { 0 };
    uint16_t addr;

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


        // Random Nonce inputs
        memset(&temp_key, 0, sizeof(temp_key));
        memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = &num_in[0];
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &temp_key;

        // Send the random Nonce command
        if ((status = calib_nonce_rand(device, num_in, rand_out)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Nonce failed");
            break;
        }

        // Calculate Tempkey
        if ((status = mseh_nonce(&nonce_params)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Calc TempKey failed");
            break;
        }

        // Supply OtherData so GenDig behavior is the same for keys with SlotConfig.NoMac set
        other_data[0] = MSE_GENDIG;
        other_data[1] = GENDIG_ZONE_DATA;
        other_data[2] = (uint8_t)(enc_key_id);
        other_data[3] = (uint8_t)(enc_key_id >> 8);

        // Send the GenDig command
        if ((status = calib_gendig(device, GENDIG_ZONE_DATA, enc_key_id, other_data, sizeof(other_data))) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "GenDig failed");
            break;
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
            MSE_TRACE(status, "mseh_gen_dig() failed");
            break;
        }

        // The get address function checks the remaining variables
        if ((status = calib_get_addr(MSE_ZONE_DATA, key_id, block, 0, &addr)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Get address failed");
            break;
        }

        // Setting bit 6 to indicate input data is encrypted
        write_mac_param.zone = zone | MSE_ZONE_ENCRYPTED;
        write_mac_param.key_id = addr;
        write_mac_param.sn = serial_num;
        write_mac_param.input_data = data;
        write_mac_param.encrypted_data = cipher_text;
        write_mac_param.auth_mac = mac;
        write_mac_param.temp_key = &temp_key;

        if ((status = mseh_write_auth_mac(&write_mac_param)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "Calculate Auth MAC failed");
            break;
        }

        status = calib_write(device, write_mac_param.zone, write_mac_param.key_id, write_mac_param.encrypted_data, write_mac_param.auth_mac);

    }
    while (0);

    return status;
}

/** \brief Executes the Write command, which writes the configuration zone.
 *
 *  First 16 bytes are skipped as they are not writable. LockValue and
 *  LockConfig are also skipped and can only be changed via the Lock
 *  command.
 *
 *  This command may fail if UserExtra and/or Selector bytes have
 *  already been set to non-zero values.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in] config_data  Data to the config zone data. This should be 88
 *                          bytes for SHA devices and 128 bytes for ECC
 *                          devices.
 *
 *  \returns MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_write_config_zone(MSEDevice device, const uint8_t* config_data)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    size_t config_size = 0;

    if (config_data == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        // Get config zone size for the device
        if (MSE_SUCCESS != (status = calib_get_zone_size(device, MSE_ZONE_CONFIG, 0, &config_size)))
        {
            MSE_TRACE(status, "calib_get_zone_size - failed");
            break;
        }

        // Write config zone excluding UserExtra and Selector
        if (MSE_SUCCESS != (status = calib_write_bytes_zone(device, MSE_ZONE_CONFIG, 0, 16, &config_data[16], config_size - 16)))
        {
            MSE_TRACE(status, "calib_write_bytes_zone - failed");
            break;
        }

        // Write the UserExtra and Selector. This may fail if either value is already non-zero.
        if (MSE_SUCCESS != (status = calib_updateextra(device, UPDATE_MODE_USER_EXTRA, config_data[84])))
        {
            MSE_TRACE(status, "calib_updateextra - failed");
            break;
        }

        if (MSE_SUCCESS != (status = calib_updateextra(device, UPDATE_MODE_SELECTOR, config_data[85])))
        {
            MSE_TRACE(status, "calib_updateextra - failed");
            break;
        }
    }
    while (0);

    return status;
}

/** \brief Uses the write command to write a public key to a slot in the
 *         proper format.
 *
 *  \param[in] device     Device context pointer
 *  \param[in] slot        Slot number to write. Only slots 8 to 15 are large
 *                         enough to store a public key.
 *  \param[in] public_key  Public key to write into the slot specified. X and Y
 *                         integers in big-endian format. 64 bytes for P256
 *                         curve.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_write_pubkey(MSEDevice device, uint16_t slot, const uint8_t *public_key)
{
    MSE_STATUS status = MSE_SUCCESS;
    uint8_t public_key_formatted[MSE_BLOCK_SIZE * 3];
    uint8_t block;

    // Check the pointers
    if (public_key == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    // The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
    // | Block 1                     | Block 2                                      | Block 3       |
    // | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

    memset(public_key_formatted, 0, sizeof(public_key_formatted));
    memcpy(&public_key_formatted[4], &public_key[0], 32);   // Move X to padded position
    memcpy(&public_key_formatted[40], &public_key[32], 32); // Move Y to padded position

    // Using this instead of calib_write_zone_bytes, as that function doesn't work when
    // the data zone is unlocked
    for (block = 0; block < 3; block++)
    {
        if (MSE_SUCCESS != (status = calib_write_zone(device, MSE_ZONE_DATA, slot, block, 0, &public_key_formatted[MSE_BLOCK_SIZE * block], MSE_BLOCK_SIZE)))
        {
            MSE_TRACE(status, "calib_write_zone - failed");
            break;
        }
    }

    return status;
}

/** \brief Executes the Write command, which writes data into the
 *          configuration, otp, or data zones with a given byte offset and
 *          length. Offset and length must be multiples of a word (4 bytes).
 *
 * Config zone must be unlocked for writes to that zone. If data zone is
 * unlocked, only 32-byte writes are allowed to slots and OTP and the offset
 * and length must be multiples of 32 or the write will fail.
 *
 *  \param[in] device        Device context pointer
 *  \param[in] zone          Zone to write data to: MSE_ZONE_CONFIG(0),
 *                           MSE_ZONE_OTP(1), or MSE_ZONE_DATA(2).
 *  \param[in] slot          If zone is MSE_ZONE_DATA(2), the slot number to
 *                           write to. Ignored for all other zones.
 *  \param[in] offset_bytes  Byte offset within the zone to write to. Must be
 *                           a multiple of a word (4 bytes).
 *  \param[in] data          Data to be written.
 *  \param[in] length        Number of bytes to be written. Must be a multiple
 *                           of a word (4 bytes).
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_write_bytes_zone(MSEDevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    size_t zone_size = 0;
    size_t data_idx = 0;
    size_t cur_block = 0;
    size_t cur_word = 0;

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
        return MSE_SUCCESS;  // Always succeed writing 0 bytes
    }
    if (data == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }
    if (offset_bytes % MSE_WORD_SIZE != 0 || length % MSE_WORD_SIZE != 0)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Either Invalid length or offset received");
    }

    do
    {
        if (MSE_SUCCESS != (status = calib_get_zone_size(device, zone, slot, &zone_size)))
        {
            MSE_TRACE(status, "calib_get_zone_size - failed");
            break;
        }
        if (offset_bytes + length > zone_size)
        {
            return MSE_TRACE(MSE_BAD_PARAM, "Invalid parameter received");
        }

        cur_block = offset_bytes / MSE_BLOCK_SIZE;
        cur_word = (offset_bytes % MSE_BLOCK_SIZE) / MSE_WORD_SIZE;

        while (data_idx < length)
        {
            // The last item makes sure we handle the selector, user extra, and lock bytes in the config properly
            if (cur_word == 0 && length - data_idx >= MSE_BLOCK_SIZE && !(zone == MSE_ZONE_CONFIG && cur_block == 2))
            {
                if (MSE_SUCCESS != (status = calib_write_zone(device, zone, slot, (uint8_t)cur_block, 0, &data[data_idx], MSE_BLOCK_SIZE)))
                {
                    MSE_TRACE(status, "calib_write_zone - failed");
                    break;
                }
                data_idx += MSE_BLOCK_SIZE;
                cur_block += 1;
            }
            else
            {
                // Skip trying to change UserExtra, Selector, LockValue, and LockConfig which require the UpdateExtra command to change
                if (!(zone == MSE_ZONE_CONFIG && cur_block == 2 && cur_word == 5))
                {
                    if (MSE_SUCCESS != (status = calib_write_zone(device, zone, slot, (uint8_t)cur_block, (uint8_t)cur_word, &data[data_idx], MSE_WORD_SIZE)))
                    {
                        MSE_TRACE(status, "calib_write_zone - failed");
                        break;
                    }
                }
                data_idx += MSE_WORD_SIZE;
                cur_word += 1;
                if (cur_word == MSE_BLOCK_SIZE / MSE_WORD_SIZE)
                {
                    cur_block += 1;
                    cur_word = 0;
                }
            }
        }
    }
    while (false);

    return status;
}

#define PRINTF_BINARY_PATTERN_INT8 "%c%c%c%c%c%c%c%c "
#define PRINTF_BYTE_TO_BINARY_INT8(i)    \
    (((i) & 0x80ll) ? '1' : '0'), \
    (((i) & 0x40ll) ? '1' : '0'), \
    (((i) & 0x20ll) ? '1' : '0'), \
    (((i) & 0x10ll) ? '1' : '0'), \
    (((i) & 0x08ll) ? '1' : '0'), \
    (((i) & 0x04ll) ? '1' : '0'), \
    (((i) & 0x02ll) ? '1' : '0'), \
    (((i) & 0x01ll) ? '1' : '0')

int bitcount(uint16_t n)
{
    int count = 0;
    while (n) {
        count++;
        n &= (n - 1);
    }
    return count;
}

/** \brief Initialize one of the monotonic counters in device with a specific
 *          value.
 *
 * The monotonic counters are stored in the configuration zone using a special
 * format. This encodes a binary count value into the 8 byte encoded value
 * required. Can only be set while the configuration zone is unlocked.
 *
 * \param[in]  device         Device context pointer
 * \param[in]  counter_id     Counter to be written.
 * \param[in]  counter_value  Counter value to set.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_write_config_counter(MSEDevice device, uint16_t counter_id, uint32_t counter_value)
{
    uint16_t lin_a, lin_b, bin_a, bin_b;
    uint8_t bytes[8];
    uint8_t idx = 0;
    MSE_STATUS status = MSE_GEN_FAIL;

    if (counter_id > 1 || counter_value > COUNTER_MAX_VALUE)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Either invalid counter id or counter value received");
    }

    lin_a = 0xFFFF >> (counter_value % 32);
    lin_b = 0xFFFF >> ((counter_value >= 16) ? (counter_value - 16) % 32 : 0);
    bin_a = (uint16_t)(counter_value / 32);
    bin_b = (counter_value >= 16) ? ((uint16_t)((counter_value - 16) / 32)) : 0;

    bytes[idx++] = lin_a >> 8;
    bytes[idx++] = lin_a & 0xFF;
    bytes[idx++] = lin_b >> 8;
    bytes[idx++] = lin_b & 0xFF;

    bytes[idx++] = bin_a >> 8;
    bytes[idx++] = bin_a & 0xFF;
    bytes[idx++] = bin_b >> 8;
    bytes[idx++] = bin_b & 0xFF;

    status = calib_write_bytes_zone(device, MSE_ZONE_CONFIG, 0, 52 + counter_id * 8, bytes, sizeof(bytes));
    
    /*
    int bit1cnt;
    uint32_t cal_val_a,cal_val_b,val_cmp;

    for (counter_value = 2095000; counter_value < 2097152; counter_value++)
    {
        idx = 0;
        bit1cnt = 0;
        printf("\r\n");
        printf("%010d ", counter_value);
        printf("%08X ", counter_value);

        lin_a = 0xFFFF >> (counter_value % 32);
        lin_b = 0xFFFF >> ((counter_value >= 16) ? (counter_value - 16) % 32 : 0);
        bin_a = counter_value / 32;
        bin_b = (counter_value >= 16) ? ((counter_value - 16) / 32) : 0;

        bytes[idx++] = lin_a >> 8;
        bytes[idx++] = lin_a & 0xFF;
        bytes[idx++] = lin_b >> 8;
        bytes[idx++] = lin_b & 0xFF;

        bytes[idx++] = bin_a >> 8;
        bytes[idx++] = bin_a & 0xFF;
        bytes[idx++] = bin_b >> 8;
        bytes[idx++] = bin_b & 0xFF;

        for (idx=0;idx<8;idx++)
        {
            printf("%02X ", bytes[idx]);
            bit1cnt += bitcount(bytes[idx]);
        }

        for (idx = 0; idx < 8; idx++)
        {
            printf(PRINTF_BINARY_PATTERN_INT8, PRINTF_BYTE_TO_BINARY_INT8(bytes[idx]));
        }
        
        // printf("bit1:%02d ", bit1cnt);
        // printf("bit0:%02d ", 64-bit1cnt);

        lin_a = (uint16_t)(bytes[0] << 8) | bytes[1];
        lin_b = (uint16_t)(bytes[2] << 8) | bytes[3];
        bin_a = (uint16_t)(bytes[4] << 8) | bytes[5];
        bin_b = (uint16_t)(bytes[6] << 8) | bytes[7];

        cal_val_a = (16-bitcount(lin_a & 0xFFFF)) + (bin_a * 32);
        printf("%010d ", cal_val_a);
        cal_val_b = (16 - bitcount(lin_b & 0xFFFF)) + (bin_b * 32+16);
        printf("%010d ", cal_val_b);
        val_cmp = (cal_val_a > cal_val_b) ? cal_val_a : cal_val_b;
        if (counter_value > 31)
        {
            if (val_cmp != counter_value)
            {
                printf("\r\n");
                printf("Faild:%010d ", counter_value);
            }
        }
    }
*/

    return status;
}


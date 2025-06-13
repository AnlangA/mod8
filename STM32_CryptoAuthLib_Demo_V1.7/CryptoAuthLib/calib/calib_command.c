/**
 * \file
 * \brief ModSemi CryptoAuthentication device command builder - this is the main object that builds the command
 * byte strings for the given device.  It does not execute the command.  The basic flow is to call
 * a command method to build the command you want given the parameters and then send that byte string
 * through the device interface.
 *
 * The primary goal of the command builder is to wrap the given parameters with the correct packet size and CRC.
 * The caller should first fill in the parameters required in the MSEPacket parameter given to the command.
 * The command builder will deal with the mechanics of creating a valid packet using the parameter information.
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

/** \brief MSECommand CheckMAC method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpCheckMAC(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_CHECKMAC;
    packet->txsize = CHECKMAC_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Counter method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS bpCounter(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_COUNTER;
    packet->txsize = COUNTER_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand DeriveKey method
 * \param[in] ca_cmd   instance
 * \param[in] packet   pointer to the packet containing the command being built
 * \param[in] has_mac  hasMAC determines if MAC data is present in the packet input
 * \return MSE_SUCCESS
 */
MSE_STATUS bpDeriveKey(MSEDeviceType device_type, MSEPacket *packet, bool has_mac)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_DERIVE_KEY;

    // hasMAC must be given since the packet does not have any implicit information to
    // know if it has a mac or not unless the size is preset
    if (has_mac)
    {
        packet->txsize = DERIVE_KEY_COUNT_LARGE;
    }
    else
    {
        packet->txsize = DERIVE_KEY_COUNT_SMALL;
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand ECDH method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpECDH(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_ECDH;
    packet->txsize = ECDH_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Generate Digest method
 * \param[in] ca_cmd         instance
 * \param[in] packet         pointer to the packet containing the command being built
 * \param[in] is_no_mac_key  Should be true if GenDig is being run on a slot that has its SlotConfig.NoMac bit set
 * \return MSE_SUCCESS
 */
MSE_STATUS bpGenDig(MSEDeviceType device_type, MSEPacket *packet, bool is_no_mac_key)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_GENDIG;

    if (packet->param1 == GENDIG_ZONE_SHARED_NONCE) // shared nonce mode
    {
        packet->txsize = GENDIG_COUNT + 32;
    }
    else if (is_no_mac_key)
    {
        packet->txsize = GENDIG_COUNT + 4;  // noMac keys use 4 bytes of OtherData in calculation
    }
    else
    {
        packet->txsize = GENDIG_COUNT;
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Generate Key method
 * \param[in] ca_cmd     instance
 * \param[in] packet    pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpGenKey(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_GENKEY;

    if (packet->param1 & GENKEY_MODE_PUBKEY_DIGEST)
    {
        packet->txsize = GENKEY_COUNT_DATA;
    }
    else
    {
        packet->txsize = GENKEY_COUNT;
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand HMAC method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpHMAC(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_HMAC;
    packet->txsize = HMAC_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Info method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpInfo(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_INFO;
    packet->txsize = INFO_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Lock method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpLock(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_LOCK;
    packet->txsize = LOCK_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand MAC method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpMAC(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    // variable packet size
    packet->opcode = MSE_MAC;
    if (!(packet->param1 & MAC_MODE_BLOCK2_TEMPKEY))
    {
        packet->txsize = MAC_COUNT_LONG;
    }
    else
    {
        packet->txsize = MAC_COUNT_SHORT;
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Nonce method
 * \param[in] ca_cmd   instance
 * \param[in] packet   pointer to the packet containing the command being built
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS bpNonce(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    // variable packet size
    uint8_t calc_mode = packet->param1 & NONCE_MODE_MASK;

    packet->opcode = MSE_NONCE;

    if ((calc_mode == NONCE_MODE_SEED_UPDATE || calc_mode == NONCE_MODE_NO_SEED_UPDATE))
    {
        // Calculated nonce mode, 20 byte NumInm
        packet->txsize = NONCE_COUNT_SHORT;
    }
    else if (calc_mode == NONCE_MODE_PASSTHROUGH)
    {
        // PAss-through nonce mode
        if ((packet->param1 & NONCE_MODE_INPUT_LEN_MASK) == NONCE_MODE_INPUT_LEN_64)
        {
            // 64 byte NumIn
            packet->txsize = NONCE_COUNT_LONG_64;
        }
        else
        {
            // 32 byte NumIn
            packet->txsize = NONCE_COUNT_LONG;
        }
    }
    else
    {
        return MSE_TRACE(MSE_BAD_PARAM, "bpNonce - failed; Invalid mode received");
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Pause method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpPause(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_PAUSE;
    packet->txsize = PAUSE_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand PrivWrite method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpPrivWrite(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_PRIVWRITE;
    packet->txsize = PRIVWRITE_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Random method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpRandom(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_RANDOM;
    packet->txsize = RANDOM_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Read method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpRead(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_READ;
    packet->txsize = READ_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand SecureBoot method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpSecureBoot(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    packet->opcode = MSE_SECUREBOOT;
    packet->txsize = MSE_CMD_SIZE_MIN;

    //variable transmit size based on mode encoding
    switch (packet->param1 & SECUREBOOT_MODE_MASK)
    {
    case SECUREBOOT_MODE_FULL:
    case SECUREBOOT_MODE_FULL_COPY:
        packet->txsize += (SECUREBOOT_DIGEST_SIZE + SECUREBOOT_SIGNATURE_SIZE);
        break;

    case SECUREBOOT_MODE_FULL_STORE:
        packet->txsize += SECUREBOOT_DIGEST_SIZE;
        break;

    default:
        return MSE_TRACE(MSE_BAD_PARAM, "bpSecureBoot - failed; Invalid mode received");
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand SHA method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \param[in] write_context_size  the length of the sha write_context data
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS bpSHA(MSEDeviceType device_type, MSEPacket *packet, uint16_t write_context_size)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_SHA;

    switch (packet->param1 & SHA_MODE_MASK)
    {
    case SHA_MODE_SHA256_START:     // START
    case SHA_MODE_HMAC_START:
    case 0x03:                      // SHA_MODE_SHA256_PUBLIC 
        packet->txsize = MSE_CMD_SIZE_MIN;
        break;

    case SHA_MODE_SHA256_UPDATE:                                           // UPDATE
        packet->txsize = (uint8_t)(MSE_CMD_SIZE_MIN + packet->param2);
        break;

    case SHA_MODE_SHA256_END:     // END
    case SHA_MODE_HMAC_END:
        // check the given packet for a size variable in param2.  If it is > 0, it should
        // be 0-63, incorporate that size into the packet
        packet->txsize = (uint8_t)(MSE_CMD_SIZE_MIN + packet->param2);
        break;

    case SHA_MODE_READ_CONTEXT:
        packet->txsize = MSE_CMD_SIZE_MIN;
        break;

    case SHA_MODE_WRITE_CONTEXT:
        packet->txsize = (uint8_t)(MSE_CMD_SIZE_MIN + write_context_size);
        break;
    }

    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Sign method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpSign(MSEDeviceType device_type, MSEPacket *packet)
{
    // Set the opcode & parameters
    packet->opcode = MSE_SIGN;
    packet->txsize = SIGN_COUNT;
    
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand UpdateExtra method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpUpdateExtra(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_UPDATE_EXTRA;
    packet->txsize = UPDATE_COUNT;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand ECDSA Verify method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS bpVerify(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_VERIFY;

    // variable packet size based on mode
    switch (packet->param1 & VERIFY_MODE_MASK)
    {
    case VERIFY_MODE_STORED:
        packet->txsize = VERIFY_256_STORED_COUNT;
        break;

    case VERIFY_MODE_VALIDATE_EXTERNAL:
        packet->txsize = VERIFY_256_EXTERNAL_COUNT;
        break;

    case VERIFY_MODE_EXTERNAL:
        packet->txsize = VERIFY_256_EXTERNAL_COUNT;
        break;

    case VERIFY_MODE_VALIDATE:
    case VERIFY_MODE_INVALIDATE:
        packet->txsize = VERIFY_256_VALIDATE_COUNT;
        break;

    default:
        return MSE_TRACE(MSE_BAD_PARAM, "bpVerify - failed; Invalid mode received");
    }

    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand Write method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \param[in] has_mac  Flag to indicate whether a mac is present or not
 * \return MSE_SUCCESS
 */
MSE_STATUS bpWrite(MSEDeviceType device_type, MSEPacket *packet, bool has_mac)
{
    // Set the opcode & parameters
    packet->opcode = MSE_WRITE;

    packet->txsize = 7;

        if (packet->param1 & MSE_ZONE_READWRITE_32)
        {
            packet->txsize += MSE_BLOCK_SIZE;
        }
        else
        {
            packet->txsize += MSE_WORD_SIZE;
        }


    if (has_mac)
    {
        packet->txsize += WRITE_MAC_SIZE;
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand AES method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpAES(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_AES;
    packet->txsize = MSE_CMD_SIZE_MIN;

    if ((packet->param1 & AES_MODE_OP_MASK) == AES_MODE_GFM)
    {
        packet->txsize += MSE_AES_GFM_SIZE;
    }
    else
    {
        packet->txsize += AES_DATA_SIZE;
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand AES method
 * \param[in] ca_cmd   instance
 * \param[in] packet  pointer to the packet containing the command being built
 * \return MSE_SUCCESS
 */
MSE_STATUS bpSelfTest(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_SELFTEST;
    packet->txsize = MSE_CMD_SIZE_MIN;
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}

/** \brief MSECommand KDF method
 * \param[in]  ca_cmd  Instance
 * \param[in]  packet  Pointer to the packet containing the command being
 *                     built.
 * \return MSE_SUCCESS
 */
MSE_STATUS bpKDF(MSEDeviceType device_type, MSEPacket *packet)
{
    ((void)device_type);

    // Set the opcode & parameters
    packet->opcode = MSE_KDF;

    // Set TX size
    if ((packet->param1 & KDF_MODE_ALG_MASK) == KDF_MODE_ALG_AES)
    {
        // AES algorithm has a fixed message size
        packet->txsize = MSE_CMD_SIZE_MIN + KDF_DETAILS_SIZE + AES_DATA_SIZE;
    }
    else
    {
        // All other algorithms encode message size in the last byte of details
        packet->txsize = MSE_CMD_SIZE_MIN + KDF_DETAILS_SIZE + packet->data[3];
    }
    bpCalcCrc(packet);
    return MSE_SUCCESS;
}


/** \brief Calculates CRC over the given raw data and returns the CRC in
 *         little-endian byte order.
 *
 * \param[in]  length  Size of data not including the CRC byte positions
 * \param[in]  data    Pointer to the data over which to compute the CRC
 * \param[out] crc_le  Pointer to the place where the two-bytes of CRC will be
 *                     returned in little-endian byte order.
 */
void bpCRC(size_t length, const uint8_t *data, uint8_t *crc_le)
{
    size_t counter;
    uint16_t crc_register = 0;
    uint16_t polynom = 0x8005;
    uint8_t shift_register;
    uint8_t data_bit, crc_bit;

    for (counter = 0; counter < length; counter++)
    {
        for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
        {
            data_bit = (data[counter] & shift_register) ? 1 : 0;
            crc_bit = crc_register >> 15;
            crc_register <<= 1;
            if (data_bit != crc_bit)
            {
                crc_register ^= polynom;
            }
        }
    }
    crc_le[0] = (uint8_t)(crc_register & 0x00FF);
    crc_le[1] = (uint8_t)(crc_register >> 8);
}


/** \brief This function calculates CRC and adds it to the correct offset in the packet data
 * \param[in] packet Packet to calculate CRC data for
 */

void bpCalcCrc(MSEPacket *packet)
{
    uint8_t length, *crc;

//    packet->param2 = MSE_UINT16_HOST_TO_LE(packet->param2);

    length = packet->txsize - MSE_CRC_SIZE;
    // computer pointer to CRC in the packet
    crc = &(packet->txsize) + length;

    // stuff CRC into packet
    bpCRC(length, &(packet->txsize), crc);
}


/** \brief This function checks the consistency of a response.
 * \param[in] response pointer to response
 * \return MSE_SUCCESS on success, otherwise MSE_RX_CRC_ERROR
 */

MSE_STATUS bpCheckCrc(const uint8_t *response)
{
    uint8_t crc[MSE_CRC_SIZE];
    uint8_t count = response[MSE_COUNT_IDX];

    count -= MSE_CRC_SIZE;
    bpCRC(count, response, crc);

    return (crc[0] == response[count] && crc[1] == response[count + 1]) ? MSE_SUCCESS : MSE_RX_CRC_ERROR;
}


/** \brief determines if a given device type is a SHA device or a superset of a SHA device
 * \param[in] device_type  Type of device to check for family type
 * \return boolean indicating whether the given device is a SHA family device.
 */

bool mseIsSHAFamily(MSEDeviceType device_type)
{
    switch (device_type)
    {
    case SHA20:
    case SHA20A:
        return true;

    default:
        return false;
    }
}

/** \brief determines if a given device type is an ECC device or a superset of a ECC device
 * \param[in] device_type  Type of device to check for family type
 * \return boolean indicating whether the given device is an ECC family device.
 */
bool mseIsECCFamily(MSEDeviceType device_type)
{
    switch (device_type)
    {
    case MOD10:
    case MOD50:
    case MOD8:
        return true;
    default:
        return false;
    }
}

/** \brief checks for basic error frame in data
 * \param[in] data pointer to received data - expected to be in the form of a CA device response frame
 * \return MSE_SUCCESS on success, otherwise an error code.
 */

MSE_STATUS isMSEError(uint8_t *data)
{
    if (data[0] == 0x04)        // error packets are always 4 bytes long
    {
        switch (data[1])
        {
        case 0x00: //No Error
            return MSE_SUCCESS;
        case 0x01: // checkmac or verify failed
            return MSE_CHECKMAC_VERIFY_FAILED;
        case 0x03: // command received byte length, opcode or parameter was illegal
            return MSE_PARSE_ERROR;
        case 0x05: // computation error during ECC processing causing invalid results
            return MSE_STATUS_ECC;
        case 0x07: // chip is in self test failure mode
            return MSE_STATUS_SELFTEST_ERROR;
        case 0x08: //random number generator health test error
            return MSE_HEALTH_TEST_ERROR;
        case 0x0f: // chip can't execute the command
            return MSE_EXECUTION_ERROR;
        case 0x11: // chip was successfully woken up
            return MSE_WAKE_SUCCESS;
        case 0xff: // bad crc found (command not properly received by device) or other comm error
            return MSE_STATUS_CRC;
        default:
            return MSE_GEN_FAIL;
        }
    }
    else
    {
        return MSE_SUCCESS;
    }
}

/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Verify command.
 *
 * The Verify command takes an ECDSA [R,S] signature and verifies that it is
 * correctly generated given an input message digest and public key.
 *
 * \note List of devices that support this command - MOD10, MOD50, and
 *       MOD8A/B. There are differences in the modes that they support. Refer
 *       to device datasheet for full details.
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

/** \brief Executes the Verify command, which takes an ECDSA [R,S] signature
 *          and verifies that it is correctly generated from a given message and
 *          public key. In all cases, the signature is an input to the command.
 *
 * For the Stored, External, and ValidateExternal Modes, the contents of
 * TempKey (or Message Digest Buffer in some cases for the MOD8) should
 * contain the 32 byte message.
 *
 * \param[in] device      Device context pointer
 * \param[in] mode        Verify command mode and options
 * \param[in] key_id      Stored mode, the slot containing the public key to
 *                        be used for the verification.
 *                        ValidateExternal mode, the slot containing the
 *                        public key to be validated.
 *                        External mode, KeyID contains the curve type to be
 *                        used to Verify the signature.
 *                        Validate or Invalidate mode, the slot containing
 *                        the public key to be (in)validated.
 * \param[in] signature   Signature to be verified. R and S integers in
 *                        big-endian format. 64 bytes for P256 curve.
 * \param[in] public_key  If mode is External, the public key to be used for
 *                        verification. X and Y integers in big-endian format.
 *                        64 bytes for P256 curve. NULL for all other modes.
 * \param[in] other_data  If mode is Validate, the bytes used to generate the
 *                        message for the validation (19 bytes). NULL for all
 *                        other modes.
 * \param[out] mac        If mode indicates a validating MAC, then the MAC will
 *                        will be returned here. Can be NULL otherwise.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_verify(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* signature, const uint8_t* public_key, const uint8_t* other_data, uint8_t* mac)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t verify_mode = (mode & VERIFY_MODE_MASK);

    do
    {
        if ((device == NULL) || (verify_mode == VERIFY_MODE_EXTERNAL && public_key == NULL) ||
            (signature == NULL))
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer recived");
            break;
        }

        if ((verify_mode == VERIFY_MODE_VALIDATE || verify_mode == VERIFY_MODE_INVALIDATE) && other_data == NULL)
        {
            status = MSE_TRACE(MSE_BAD_PARAM, "NULL pointer recived");
            break;
        }

        // Build the verify command
        packet.param1 = mode;
        packet.param2 = key_id;
        memcpy(&packet.data[0], signature, MSE_SIG_SIZE);
        if (verify_mode == VERIFY_MODE_EXTERNAL)
        {
            memcpy(&packet.data[MSE_SIG_SIZE], public_key, MSE_PUB_KEY_SIZE);
        }
        else if (other_data)
        {
            memcpy(&packet.data[MSE_SIG_SIZE], other_data, VERIFY_OTHER_DATA_SIZE);
        }

        if ((status = bpVerify(mse_get_device_type_ext(device), &packet)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpVerify - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_verify - execution failed");
            break;
        }

        // The Verify command may return MAC if requested
        if ((mac != NULL) && (packet.data[MSE_COUNT_IDX] >= (MSE_PACKET_OVERHEAD + MAC_SIZE)))
        {
            memcpy(mac, &packet.data[MSE_RSP_DATA_IDX], MAC_SIZE);
        }

    }
    while (false);

    return status;
}

/** \brief Executes the Verify command with verification MAC for the External
 *          or Stored Verify modes.. This function is only available on the
 *          MOD8.
 *
 * \param[in]  device       Device context pointer
 * \param[in] mode          Verify command mode. Can be VERIFY_MODE_EXTERNAL or
 *                          VERIFY_MODE_STORED.
 * \param[in] key_id        For VERIFY_MODE_STORED mode, the slot containing the
 *                          public key to be used for the verification.
 *                          For VERIFY_MODE_EXTERNAL mode, KeyID contains the
 *                          curve type to be used to Verify the signature. Only
 *                          VERIFY_KEY_P256 supported.
 * \param[in]  message      32 byte message to be verified. Typically
 *                          the SHA256 hash of the full message.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  public_key   For VERIFY_MODE_EXTERNAL mode, the public key to be
 *                          used for verification. X and Y integers in
 *                          big-endian format. 64 bytes for P256 curve. Null for
 *                          VERIFY_MODE_STORED mode.
 * \param[in]  num_in       System nonce (32 byte) used for the verification
 *                          MAC.
 * \param[in]  io_key       IO protection key for verifying the validation MAC.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
static MSE_STATUS calib_verify_extern_stored_mac(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* message, const uint8_t* signature, const uint8_t* public_key, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t msg_dig_buf[64];
    mse_verify_mac_in_out_t verify_mac_params;
    uint8_t mac[SECUREBOOT_MAC_SIZE];
    uint8_t host_mac[SECUREBOOT_MAC_SIZE];

    do
    {
        if ((is_verified == NULL) || (signature == NULL) || (message == NULL) || (num_in == NULL)
            || (io_key == NULL) || ((mode & VERIFY_MODE_MASK) == VERIFY_MODE_EXTERNAL && public_key == NULL))
        {
            return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer recived");
        }

        *is_verified = false;

        // When using the message digest buffer as the message source, the
        // second 32 bytes in the buffer will be the MAC system nonce.
        memcpy(&msg_dig_buf[0], message, 32);
        memcpy(&msg_dig_buf[32], num_in, 32);
        if ((status = calib_nonce_load(device, NONCE_MODE_TARGET_MSGDIGBUF, msg_dig_buf, 64)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_nonce_load - failed");
            break;
        }

        // Calculate the expected MAC
        memset(&verify_mac_params, 0, sizeof(verify_mac_params));
        verify_mac_params.mode = mode | VERIFY_MODE_SOURCE_MSGDIGBUF | VERIFY_MODE_MAC_FLAG;
        verify_mac_params.key_id = key_id;
        verify_mac_params.signature = signature;
        verify_mac_params.msg_dig_buf = msg_dig_buf;
        verify_mac_params.io_key = io_key;
        verify_mac_params.temp_key = NULL;
        verify_mac_params.sn = NULL;
        verify_mac_params.mac = host_mac;
        if (MSE_SUCCESS != (status = mseh_verify_mac(&verify_mac_params)))
        {
            MSE_TRACE(status, "mseh_verify_mac - failed");
            break;
        }

        if (MSE_SUCCESS != (status = calib_verify(device, verify_mac_params.mode, verify_mac_params.key_id, signature, public_key, NULL, mac)))
        {
            if (status == MSE_CHECKMAC_VERIFY_FAILED)
            {
                status = MSE_SUCCESS;  // Verify failed, but command succeeded
            }
            break;
        }

        *is_verified = (memcmp(host_mac, mac, MAC_SIZE) == 0);
    }
    while (0);

    return status;
}

/** \brief Executes the Verify command, which verifies a signature (ECDSA
 *          verify operation) with all components (message, signature, and
 *          public key) supplied. The message to be signed will be loaded into
 *          the Message Digest Buffer to the MOD8 device or TempKey for
 *          other devices.
 *
 * \param[in]  device       Device context pointer
 * \param[in]  message      32 byte message to be verified. Typically
 *                          the SHA256 hash of the full message.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  public_key   The public key to be used for verification. X and
 *                          Y integers in big-endian format. 64 bytes for
 *                          P256 curve.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
MSE_STATUS calib_verify_extern(MSEDevice device, const uint8_t *message, const uint8_t *signature, const uint8_t *public_key, bool *is_verified)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t nonce_target = NONCE_MODE_TARGET_TEMPKEY;
    uint8_t verify_source = VERIFY_MODE_SOURCE_TEMPKEY;

    if ((device == NULL) || (is_verified == NULL) || (signature == NULL) || (message == NULL) ||
        (public_key == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    *is_verified = false;

    do
    {
        // Load message into device
        if (MOD8 == device->mIface.mIfaceCFG->devtype)
        {
            // Use the Message Digest Buffer for the MOD8
            nonce_target = NONCE_MODE_TARGET_MSGDIGBUF;
            verify_source = VERIFY_MODE_SOURCE_MSGDIGBUF;
        }
        if ((status = calib_nonce_load(device, nonce_target, message, 32)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_nonce_load - failed");
            break;
        }

        status = calib_verify(device, VERIFY_MODE_EXTERNAL | verify_source, VERIFY_KEY_P256, signature, public_key, NULL, NULL);

        *is_verified = (status == MSE_SUCCESS);
        if (status == MSE_CHECKMAC_VERIFY_FAILED)
        {
            status = MSE_SUCCESS;  // Verify failed, but command succeeded
        }
    }
    while (0);

    return status;
}

/** \brief Executes the Verify command with verification MAC, which verifies a
 *          signature (ECDSA verify operation) with all components (message,
 *          signature, and public key) supplied. This function is only available
 *          on the MOD8.
 *
 * \param[in]  device       Device context pointer
 * \param[in]  message      32 byte message to be verified. Typically
 *                          the SHA256 hash of the full message.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  public_key   The public key to be used for verification. X and
 *                          Y integers in big-endian format. 64 bytes for
 *                          P256 curve.
 * \param[in]  num_in       System nonce (32 byte) used for the verification
 *                          MAC.
 * \param[in]  io_key       IO protection key for verifying the validation MAC.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
MSE_STATUS calib_verify_extern_mac(MSEDevice device, const uint8_t *message, const uint8_t* signature, const uint8_t* public_key, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified)
{
    return calib_verify_extern_stored_mac(device, VERIFY_MODE_EXTERNAL, VERIFY_KEY_P256, message, signature, public_key, num_in, io_key, is_verified);
}

/** \brief Executes the Verify command, which verifies a signature (ECDSA
 *          verify operation) with a public key stored in the device. The
 *          message to be signed will be loaded into the Message Digest Buffer
 *          to the MOD8 device or TempKey for other devices.
 *
 * \param[in]  device       Device context pointer
 * \param[in]  message      32 byte message to be verified. Typically
 *                          the SHA256 hash of the full message.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  key_id       Slot containing the public key to be used in the
 *                         verification.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
MSE_STATUS calib_verify_stored(MSEDevice device, const uint8_t *message, const uint8_t *signature, uint16_t key_id, bool *is_verified)
{
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t nonce_target = NONCE_MODE_TARGET_TEMPKEY;
    uint8_t verify_source = VERIFY_MODE_SOURCE_TEMPKEY;

    if ((device == NULL) || (is_verified == NULL) || (signature == NULL) || (message == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    *is_verified = false;

    do
    {
        // Load message into device
        if (MOD8 == device->mIface.mIfaceCFG->devtype)
        {
            // Use the Message Digest Buffer for the MOD8
            nonce_target = NONCE_MODE_TARGET_MSGDIGBUF;
            verify_source = VERIFY_MODE_SOURCE_MSGDIGBUF;
        }
        if ((status = calib_nonce_load(device, nonce_target, message, 32)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_nonce_load - failed");
            break;
        }

        status = calib_verify(device, VERIFY_MODE_STORED | verify_source, key_id, signature, NULL, NULL, NULL);

        *is_verified = (status == MSE_SUCCESS);
        if (status == MSE_CHECKMAC_VERIFY_FAILED)
        {
            status = MSE_SUCCESS;  // Verify failed, but command succeeded
        }
    }
    while (0);

    return status;
}

/** \brief Executes the Verify command with verification MAC, which verifies a
 *          signature (ECDSA verify operation) with a public key stored in the
 *          device. This function is only available on the MOD8.
 *
 * \param[in]  device       Device context pointer
 * \param[in]  message      32 byte message to be verified. Typically
 *                          the SHA256 hash of the full message.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  key_id       Slot containing the public key to be used in the
 *                          verification.
 * \param[in]  num_in       System nonce (32 byte) used for the verification
 *                          MAC.
 * \param[in]  io_key       IO protection key for verifying the validation MAC.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
MSE_STATUS calib_verify_stored_mac(MSEDevice device, const uint8_t *message, const uint8_t *signature, uint16_t key_id, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified)
{
    return calib_verify_extern_stored_mac(device, VERIFY_MODE_STORED, key_id, message, signature, NULL, num_in, io_key, is_verified);
}

/** \brief Executes the Verify command in Validate mode to validate a public
 *          key stored in a slot.
 *
 * This command can only be run after GenKey has been used to create a PubKey
 * digest of the public key to be validated in TempKey (mode=0x10).
 *
 * \param[in]  device       Device context pointer
 * \param[in]  key_id       Slot containing the public key to be validated.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  other_data   19 bytes of data used to build the verification
 *                          message.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          validation public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
MSE_STATUS calib_verify_validate(MSEDevice device, uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified)
{
    MSE_STATUS status = MSE_SUCCESS;

    if ((device == NULL) || (signature == NULL) || (other_data == NULL) || (is_verified == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    status = calib_verify(device, VERIFY_MODE_VALIDATE, key_id, signature, NULL, other_data, NULL);

    *is_verified = (status == MSE_SUCCESS);
    if (status == MSE_CHECKMAC_VERIFY_FAILED)
    {
        status = MSE_SUCCESS;  // Verify failed, but command succeeded
    }

    return status;
}

/** \brief Executes the Verify command in Invalidate mode which invalidates a
 *          previously validated public key stored in a slot.
 *
 * This command can only be run after GenKey has been used to create a PubKey
 * digest of the public key to be invalidated in TempKey (mode=0x10).
 *
 * \param[in]  device       Device context pointer
 * \param[in]  key_id       Slot containing the public key to be invalidated.
 * \param[in]  signature    Signature to be verified. R and S integers in
 *                          big-endian format. 64 bytes for P256 curve.
 * \param[in]  other_data   19 bytes of data used to build the verification
 *                          message.
 * \param[out] is_verified  Boolean whether or not the message, signature,
 *                          validation public key verified.
 *
 * \return MSE_SUCCESS on verification success or failure, because the
 *         command still completed successfully.
 */
MSE_STATUS calib_verify_invalidate(MSEDevice device, uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified)
{
    MSE_STATUS status = MSE_SUCCESS;

    if ((device == NULL) || (signature == NULL) || (other_data == NULL) || (is_verified == NULL))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    status = calib_verify(device, VERIFY_MODE_INVALIDATE, key_id, signature, NULL, other_data, NULL);

    *is_verified = (status == MSE_SUCCESS);
    if (status == MSE_CHECKMAC_VERIFY_FAILED)
    {
        status = MSE_SUCCESS;  // Verify failed, but command succeeded
    }

    return status;
}

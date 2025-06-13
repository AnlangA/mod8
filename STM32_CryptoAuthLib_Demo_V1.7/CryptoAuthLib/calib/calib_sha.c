/**
 * \file
 * \brief CryptoAuthLib Basic API methods for SHA command.
 *
 * The SHA command Computes a SHA-256 or HMAC/SHA digest for general purpose
 * use by the host system.
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

typedef struct
{
    uint32_t total_msg_size;                     //!< Total number of message bytes processed
    uint32_t block_size;                         //!< Number of bytes in current block
    uint8_t  block[MSE_SHA256_BLOCK_SIZE * 2];  //!< Unprocessed message storage
} hw_sha256_ctx;

/** \brief Executes SHA command, which computes a SHA-256 or HMAC/SHA-256
 *          digest for general purpose use by the host system.
 *
 * Only the Start(0) and Compute(1) modes are available for SHA devices.
 *
 * \param[in]    device         Device context pointer
 * \param[in]    mode           SHA command mode Start(0), Update/Compute(1),
 *                              End(2), Public(3), HMACstart(4), HMACend(5),
 *                              Read_Context(6), or Write_Context(7). Also
 *                              message digest target location for the
 *                              MOD8.
 * \param[in]    length         Number of bytes in the message parameter or
 *                              KeySlot for the HMAC key if Mode is
 *                              HMACstart(4) or Public(3).
 * \param[in]    message        Message bytes to be hashed or Write_Context if
 *                              restoring a context on the MOD8. Can be
 *                              NULL if not required by the mode.
 * \param[out]   data_out       Data returned by the command (digest or
 *                              context).
 * \param[in,out] data_out_size  As input, the size of the data_out buffer. As
 *                              output, the number of bytes returned in
 *                              data_out.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_base(MSEDevice device, uint8_t mode, uint16_t length, const uint8_t* message, uint8_t* data_out, uint16_t* data_out_size)
{
    MSEPacket packet;
    MSE_STATUS status = MSE_GEN_FAIL;
    uint8_t cmd_mode = (mode & SHA_MODE_MASK);

    if (device == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }
    if (cmd_mode != SHA_MODE_SHA256_PUBLIC && cmd_mode != SHA_MODE_HMAC_START && length > 0 && message == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received"); // message data indicated, but nothing provided
    }
    if (data_out != NULL && data_out_size == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        //Build Command
        packet.param1 = mode;
        packet.param2 = length;

        if (cmd_mode != SHA_MODE_SHA256_PUBLIC && cmd_mode != SHA_MODE_HMAC_START)
        {
            memcpy(packet.data, message, (size_t)length);
        }

        if ((status = bpSHA(mse_get_device_type_ext(device), &packet, length)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "bpSHA - failed");
            break;
        }

        if ((status = mse_execute_command(&packet, device)) != MSE_SUCCESS)
        {
            MSE_TRACE(status, "calib_sha_base - exection failed");
            break;
        }

        if ((data_out != NULL) && (packet.data[MSE_COUNT_IDX] > 4))
        {
            if (packet.data[MSE_COUNT_IDX] - MSE_PACKET_OVERHEAD > *data_out_size)
            {
                status = MSE_SMALL_BUFFER;
                break;
            }
            *data_out_size = packet.data[MSE_COUNT_IDX] - MSE_PACKET_OVERHEAD;
            memcpy(data_out, &packet.data[MSE_RSP_DATA_IDX], *data_out_size);
        }
    }
    while (0);

    return status;
}

/** \brief Executes SHA command to initialize SHA-256 calculation engine
 *  \param[in]  device      Device context pointer
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_start(MSEDevice device)
{
    return calib_sha_base(device, SHA_MODE_SHA256_START, 0, NULL, NULL, NULL);
}

/** \brief Executes SHA command to add 64 bytes of message data to the current
 *          context.
 *
 * \param[in] device   Device context pointer
 * \param[in] message  64 bytes of message data to add to add to operation.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_update(MSEDevice device, const uint8_t *message)
{
    return calib_sha_base(device, SHA_MODE_SHA256_UPDATE, 64, message, NULL, NULL);
}

/** \brief Executes SHA command to complete SHA-256 or HMAC/SHA-256 operation.
 *
 *  \param[in]  device   Device context pointer
 *  \param[out] digest   Digest from SHA-256 or HMAC/SHA-256 will be returned
 *                       here (32 bytes).
 *  \param[in]  length   Length of any remaining data to include in hash. Max 64
 *                       bytes.
 *  \param[in]  message  Remaining data to include in hash. NULL if length is 0.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_end(MSEDevice device, uint8_t *digest, uint16_t length, const uint8_t *message)
{
    uint16_t digest_size = 32;

    return calib_sha_base(device, SHA_MODE_SHA256_END, length, message, digest, &digest_size);
}

/** \brief Executes SHA command to read the SHA-256 context back. Only for
 *          MOD8 with SHA-256 contexts. HMAC not supported.
 *
 *  \param[in]  device          Device context pointer
 *  \param[out]   context       Context data is returned here.
 *  \param[in,out] context_size  As input, the size of the context buffer in
 *                              bytes. As output, the size of the returned
 *                              context data.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_read_context(MSEDevice device, uint8_t* context, uint16_t* context_size)
{
    return calib_sha_base(device, SHA_MODE_READ_CONTEXT, 0, NULL, context, context_size);
}

/** \brief Executes SHA command to write (restore) a SHA-256 context into the
 *          the device. Only supported for MOD8 with SHA-256 contexts.
 *
 *  \param[in] device        Device context pointer
 *  \param[in] context       Context data to be restored.
 *  \param[in] context_size  Size of the context data in bytes.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_write_context(MSEDevice device, const uint8_t* context, uint16_t context_size)
{
    return calib_sha_base(device, SHA_MODE_WRITE_CONTEXT, context_size, context, NULL, NULL);
}

/** \brief Use the SHA command to compute a SHA-256 digest.
 *
 * \param[in]  device   Device context pointer
 * \param[in]  length   Size of message parameter in bytes.
 * \param[in]  message  Message data to be hashed.
 * \param[out] digest   Digest is returned here (32 bytes).
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha(MSEDevice device, uint16_t length, const uint8_t *message, uint8_t *digest)
{
    return calib_hw_sha2_256(device, message, length, digest);
}

/** \brief Initialize a SHA context for performing a hardware SHA-256 operation
 *          on a device. Note that only one SHA operation can be run at a time.
 *
 * \param[in] device   Device context pointer
 * \param[in] ctx      SHA256 context
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_hw_sha2_256_init(MSEDevice device, mse_sha256_ctx_t* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    return calib_sha_start(device);
}

/** \brief Add message data to a SHA context for performing a hardware SHA-256
 *          operation on a device.
 *
 * \param[in] device     Device context pointer
 * \param[in] ctx        SHA256 context
 * \param[in] data       Message data to be added to hash.
 * \param[in] data_size  Size of data in bytes.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_hw_sha2_256_update(MSEDevice device, mse_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size)
{
    MSE_STATUS status = MSE_SUCCESS;
    uint32_t block_count;
    uint32_t rem_size = MSE_SHA256_BLOCK_SIZE - ctx->block_size;
    size_t copy_size = data_size > rem_size ? (size_t)rem_size : data_size;
    uint32_t i = 0;

    // Copy data into current block
    memcpy(&ctx->block[ctx->block_size], data, copy_size);

    if (ctx->block_size + data_size < MSE_SHA256_BLOCK_SIZE)
    {
        // Not enough data to finish off the current block
        ctx->block_size += (uint32_t)data_size;
        return MSE_SUCCESS;
    }

    // Process the current block
    if (MSE_SUCCESS != (status = calib_sha_update(device, ctx->block)))
    {
        return MSE_TRACE(status, "calib_sha_update - failed");
    }

    // Process any additional blocks
    data_size -= copy_size; // Adjust to the remaining message bytes
    block_count = (uint32_t)(data_size / MSE_SHA256_BLOCK_SIZE);
    for (i = 0; i < block_count; i++)
    {
        if (MSE_SUCCESS != (status = calib_sha_update(device, &data[copy_size + i * MSE_SHA256_BLOCK_SIZE])))
        {
            return MSE_TRACE(status, "calib_sha_update - failed");
        }
    }

    // Save any remaining data
    ctx->total_msg_size += (block_count + 1) * MSE_SHA256_BLOCK_SIZE;
    ctx->block_size = data_size % MSE_SHA256_BLOCK_SIZE;
    memcpy(ctx->block, &data[copy_size + block_count * MSE_SHA256_BLOCK_SIZE], (size_t)ctx->block_size);

    return MSE_SUCCESS;
}

/** \brief Finish SHA-256 digest for a SHA context for performing a hardware
 *          SHA-256 operation on a device.
 *
 * \param[in]  device  Device context pointer
 * \param[in]  ctx     SHA256 context
 * \param[out] digest  SHA256 digest is returned here (32 bytes)
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_hw_sha2_256_finish(MSEDevice device, mse_sha256_ctx_t* ctx, uint8_t* digest)
{
    MSE_STATUS status = MSE_SUCCESS;
    uint32_t msg_size_bits;
    uint32_t pad_zero_count;
    uint16_t digest_size;

    if (device == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    if (device->mIface.mIfaceCFG->devtype == SHA20)
    {
        // SHA20 only implements the raw 64-byte block operation, but
        // doesn't add in the final footer information. So we do that manually
        // here.

        // Calculate the total message size in bits
        ctx->total_msg_size += ctx->block_size;
        msg_size_bits = (ctx->total_msg_size * 8);

        // Calculate the number of padding zero bytes required between the 1 bit byte and the  MSE_SHA256_BLOCK_SIZEbit message size in bits.
        pad_zero_count = (MSE_SHA256_BLOCK_SIZE - ((ctx->block_size + 9) % MSE_SHA256_BLOCK_SIZE)) % MSE_SHA256_BLOCK_SIZE;

        // Append a single 1 bit
        ctx->block[ctx->block_size++] = 0x80;

        // Add padding zeros plus upper 4 bytes of total message size in bits (only supporting 32bit message bit counts)
        memset(&ctx->block[ctx->block_size], 0, (size_t)pad_zero_count + 4);
        ctx->block_size += pad_zero_count + 4;

        // Add the total message size in bits to the end of the current block. Technically this is
        // supposed to be 8 bytes. This shortcut will reduce the max message size to 536,870,911 bytes.
        ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 24);
        ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 16);
        ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 8);
        ctx->block[ctx->block_size++] = (uint8_t)(msg_size_bits >> 0);

        digest_size = 32;
        if (MSE_SUCCESS != (status = calib_sha_base(device, SHA_MODE_SHA256_UPDATE, MSE_SHA256_BLOCK_SIZE, ctx->block, digest, &digest_size)))
        {
            return MSE_TRACE(status, "calib_sha_base - failed");
        }

        if (ctx->block_size > MSE_SHA256_BLOCK_SIZE)
        {
            digest_size = 32;
            if (MSE_SUCCESS != (status = calib_sha_base(device, SHA_MODE_SHA256_UPDATE, MSE_SHA256_BLOCK_SIZE, &ctx->block[MSE_SHA256_BLOCK_SIZE], digest, &digest_size)))
            {
                return MSE_TRACE(status, "calib_sha_base - failed");
            }
        }
    }
    else
    {
        if (MSE_SUCCESS != (status = calib_sha_end(device, digest, (uint16_t)ctx->block_size, ctx->block)))
        {
            return MSE_TRACE(status, "calib_sha_end - failed");
        }
    }

    return MSE_SUCCESS;
}

/** \brief Use the SHA command to compute a SHA-256 digest.
 *
 * \param[in]  device     Device context pointer
 * \param[in]  data       Message data to be hashed.
 * \param[in]  data_size  Size of data in bytes.
 * \param[out] digest     Digest is returned here (32 bytes).
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_hw_sha2_256(MSEDevice device, const uint8_t * data, size_t data_size, uint8_t* digest)
{
    MSE_STATUS status = MSE_SUCCESS;
    mse_sha256_ctx_t ctx;

    if (MSE_SUCCESS != (status = calib_hw_sha2_256_init(device, &ctx)))
    {
        return MSE_TRACE(status, "calib_hw_sha2_256_init - failed");
    }

    if (MSE_SUCCESS != (status = calib_hw_sha2_256_update(device, &ctx, data, data_size)))
    {
        return MSE_TRACE(status, "calib_hw_sha2_256_update - failed");
    }

    if (MSE_SUCCESS != (status = calib_hw_sha2_256_finish(device, &ctx, digest)))
    {
        return MSE_TRACE(status, "calib_hw_sha2_256_finish - failed");
    }

    return MSE_SUCCESS;
}

/** \brief Executes SHA command to start an HMAC/SHA-256 operation
 *
 * \param[in]  device   Device context pointer
 * \param[in] ctx       HMAC/SHA-256 context
 * \param[in] key_slot  Slot key id to use for the HMAC calculation
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_hmac_init(MSEDevice device, mse_hmac_sha256_ctx_t* ctx, uint16_t key_slot)
{
    uint8_t mode = SHA_MODE_HMAC_START;

    if ((NULL == ctx) || (NULL == device))
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer encountered");
    }

    memset(ctx, 0, sizeof(*ctx));

    return calib_sha_base(device, mode, key_slot, NULL, NULL, NULL);
}

/** \brief Executes SHA command to add an arbitrary amount of message data to
 *          a HMAC/SHA-256 operation.
 *
 * \param[in]  device    Device context pointer
 * \param[in] ctx        HMAC/SHA-256 context
 * \param[in] data       Message data to add
 * \param[in] data_size  Size of message data in bytes
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_hmac_update(MSEDevice device, mse_hmac_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size)
{
    MSE_STATUS status = MSE_SUCCESS;
    uint32_t block_count;
    uint32_t rem_size = MSE_SHA256_BLOCK_SIZE - ctx->block_size;
    size_t copy_size = data_size > rem_size ? (size_t)rem_size : data_size;
    uint32_t i = 0;

    // Copy data into current block
    memcpy(&ctx->block[ctx->block_size], data, copy_size);

    if (ctx->block_size + data_size < MSE_SHA256_BLOCK_SIZE)
    {
        // Not enough data to finish off the current block
        ctx->block_size += (uint32_t)data_size;
        return MSE_SUCCESS;
    }

    // Process the current block
    if (MSE_SUCCESS != (status = calib_sha_base(device, SHA_MODE_HMAC_UPDATE, MSE_SHA256_BLOCK_SIZE, ctx->block, NULL, NULL)))
    {
        return MSE_TRACE(status, "calib_sha_base - failed");
    }

    // Process any additional blocks
    data_size -= copy_size; // Adjust to the remaining message bytes
    block_count = (uint32_t)(data_size / MSE_SHA256_BLOCK_SIZE);
    for (i = 0; i < block_count; i++)
    {
        if (MSE_SUCCESS != (status = calib_sha_base(device, SHA_MODE_HMAC_UPDATE, MSE_SHA256_BLOCK_SIZE, &data[copy_size + i * MSE_SHA256_BLOCK_SIZE], NULL, NULL)))
        {
            return MSE_TRACE(status, "calib_sha_base - failed");
        }
    }

    // Save any remaining data
    ctx->total_msg_size += (block_count + 1) * MSE_SHA256_BLOCK_SIZE;
    ctx->block_size = data_size % MSE_SHA256_BLOCK_SIZE;
    memcpy(ctx->block, &data[copy_size + block_count * MSE_SHA256_BLOCK_SIZE], (size_t)ctx->block_size);

    return MSE_SUCCESS;
}

/** \brief Executes SHA command to complete a HMAC/SHA-256 operation.
 *
 * \param[in]  device  Device context pointer
 * \param[in]  ctx     HMAC/SHA-256 context
 * \param[out] digest  HMAC/SHA-256 result is returned here (32 bytes).
 * \param[in]  target  Where to save the digest internal to the device.
 *                     For MOD8, can be SHA_MODE_TARGET_TEMPKEY,
 *                     SHA_MODE_TARGET_MSGDIGBUF, or SHA_MODE_TARGET_OUT_ONLY.
 *                     For all other devices, SHA_MODE_TARGET_TEMPKEY is the
 *                     only option.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_hmac_finish(MSEDevice device, mse_hmac_sha256_ctx_t *ctx, uint8_t* digest, uint8_t target)
{
    uint8_t mode = SHA_MODE_HMAC_END;
    uint16_t digest_size = 32;

    if (device == NULL)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "NULL pointer received");
    }

    if (MOD8A == device->mIface.mIfaceCFG->devtype)
    {
        mode = SHA_MODE_60_HMAC_END;
    }
    else if (target != SHA_MODE_TARGET_TEMPKEY)
    {
        return MSE_TRACE(MSE_BAD_PARAM, "Invalid target received");
    }

    mode |= target;

    return calib_sha_base(device, mode, (uint16_t)ctx->block_size, ctx->block, digest, &digest_size);
}

/** \brief Use the SHA command to compute an HMAC/SHA-256 operation.
 *
 * \param[in]  device     Device context pointer
 * \param[in]  data       Message data to be hashed.
 * \param[in]  data_size  Size of data in bytes.
 * \param[in]  key_slot   Slot key id to use for the HMAC calculation
 * \param[out] digest     Digest is returned here (32 bytes).
 * \param[in]  target     Where to save the digest internal to the device.
 *                        For MOD8, can be SHA_MODE_TARGET_TEMPKEY,
 *                        SHA_MODE_TARGET_MSGDIGBUF, or
 *                        SHA_MODE_TARGET_OUT_ONLY. For all other devices,
 *                        SHA_MODE_TARGET_TEMPKEY is the only option.
 *
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS calib_sha_hmac(MSEDevice device, const uint8_t * data, size_t data_size, uint16_t key_slot, uint8_t* digest, uint8_t target)
{
    MSE_STATUS status = MSE_SUCCESS;
    mse_hmac_sha256_ctx_t ctx;

    if (MSE_SUCCESS != (status = calib_sha_hmac_init(device, &ctx, key_slot)))
    {
        return MSE_TRACE(status, "calib_sha_hmac_init - failed");
    }

    if (MSE_SUCCESS != (status = calib_sha_hmac_update(device, &ctx, data, data_size)))
    {
        return MSE_TRACE(status, "calib_sha_hmac_update - failed");
    }

    if (MSE_SUCCESS != (status = calib_sha_hmac_finish(device, &ctx, digest, target)))
    {
        return MSE_TRACE(status, "calib_sha_hmac_finish - failed");
    }

    return MSE_SUCCESS;
}

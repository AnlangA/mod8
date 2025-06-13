#ifndef _CALIB_H
#define _CALIB_H

#include "calib_command.h"
#include "calib_execution.h"

/** \defgroup calib_ Basic Crypto API methods for CryptoAuth Devices (calib_)
 *
 * \brief
 * These methods provide a simple API to CryptoAuth chips
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

MSE_STATUS calib_wakeup(MSEDevice device);
MSE_STATUS calib_idle(MSEDevice device);
MSE_STATUS calib_sleep(MSEDevice device);
MSE_STATUS _calib_exit(MSEDevice device);
MSE_STATUS calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr);
MSE_STATUS calib_get_zone_size(MSEDevice device, uint8_t zone, uint16_t slot, size_t* size);

/* Helper Functions */
MSE_STATUS calib_is_locked(MSEDevice device, uint8_t zone, bool* is_locked);
MSE_STATUS calib_is_slot_locked(MSEDevice device, uint16_t slot, bool* is_locked);
MSE_STATUS calib_is_private(MSEDevice device, uint16_t slot, bool* is_private);

//AES command functions
MSE_STATUS calib_aes(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* aes_in, uint8_t* aes_out);
MSE_STATUS calib_aes_encrypt(MSEDevice device, uint16_t key_id, uint8_t key_block, const uint8_t* plaintext, uint8_t* ciphertext);
MSE_STATUS calib_aes_decrypt(MSEDevice device, uint16_t key_id, uint8_t key_block, const uint8_t* ciphertext, uint8_t* plaintext);
MSE_STATUS calib_aes_gfm(MSEDevice device, const uint8_t* h, const uint8_t* input, uint8_t* output);

//CheckMAC command functions
MSE_STATUS calib_checkmac(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data);

// Counter command functions
MSE_STATUS calib_counter(MSEDevice device, uint8_t mode, uint16_t counter_id, uint32_t* counter_value);
MSE_STATUS calib_counter_increment(MSEDevice device, uint16_t counter_id, uint32_t* counter_value);
MSE_STATUS calib_counter_read(MSEDevice device, uint16_t counter_id, uint32_t* counter_value);

// DeriveKey command functions
MSE_STATUS calib_derivekey(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* mac);

// ECDH command functions
MSE_STATUS calib_ecdh_base(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, uint8_t* out_nonce);
MSE_STATUS calib_ecdh(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms);

#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_ecdh_enc(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id);
#else
MSE_STATUS calib_ecdh_enc(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* read_key, uint16_t read_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif

MSE_STATUS calib_ecdh_ioenc(MSEDevice device, uint16_t key_id, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key);
MSE_STATUS calib_ecdh_tempkey(MSEDevice device, const uint8_t* public_key, uint8_t* pms);
MSE_STATUS calib_ecdh_tempkey_ioenc(MSEDevice device, const uint8_t* public_key, uint8_t* pms, const uint8_t* io_key);

// GenDig command functions
MSE_STATUS calib_gendig(MSEDevice device, uint8_t zone, uint16_t key_id, const uint8_t *other_data, uint8_t other_data_size);

// GenKey command functions
MSE_STATUS calib_genkey_base(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* other_data, uint8_t* public_key);
MSE_STATUS calib_genkey(MSEDevice device, uint16_t key_id, uint8_t* public_key);
MSE_STATUS calib_get_pubkey(MSEDevice device, uint16_t key_id, uint8_t* public_key);
MSE_STATUS calib_genkey_mac(MSEDevice device, uint8_t* public_key, uint8_t* mac);

// HMAC command functions
MSE_STATUS calib_hmac(MSEDevice device, uint8_t mode, uint16_t key_id, uint8_t* digest);

// Info command functions
MSE_STATUS calib_info_base(MSEDevice device, uint8_t mode, uint16_t param2, uint8_t* out_data);
MSE_STATUS calib_info(MSEDevice device, uint8_t* revision);
MSE_STATUS calib_info_set_latch(MSEDevice device, bool state);
MSE_STATUS calib_info_get_latch(MSEDevice device, bool* state);
MSE_STATUS calib_info_privkey_valid(MSEDevice device, uint16_t key_id, uint8_t* is_valid);
MSE_STATUS calib_info_lock_status(MSEDevice device, uint16_t param2, uint8_t* is_locked);

// KDF command functions
MSE_STATUS calib_kdf(MSEDevice device, uint8_t mode, uint16_t key_id, const uint32_t details, const uint8_t* message, uint8_t* out_data, uint8_t* out_nonce);

// Lock command functions
MSE_STATUS calib_lock(MSEDevice device, uint8_t mode, uint16_t summary_crc);
MSE_STATUS calib_lock_config_zone(MSEDevice device);
MSE_STATUS calib_lock_config_zone_crc(MSEDevice device, uint16_t summary_crc);
MSE_STATUS calib_lock_data_zone(MSEDevice device);
MSE_STATUS calib_lock_data_zone_crc(MSEDevice device, uint16_t summary_crc);
MSE_STATUS calib_lock_data_slot(MSEDevice device, uint16_t slot);


// MAC command functions
MSE_STATUS calib_mac(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* challenge, uint8_t* digest);

// Nonce command functions
MSE_STATUS calib_nonce_base(MSEDevice device, uint8_t mode, uint16_t zero, const uint8_t *num_in, uint8_t* rand_out);
MSE_STATUS calib_nonce(MSEDevice device, const uint8_t *num_in);
MSE_STATUS calib_nonce_load(MSEDevice device, uint8_t target, const uint8_t *num_in, uint16_t num_in_size);
MSE_STATUS calib_nonce_rand(MSEDevice device, const uint8_t *num_in, uint8_t* rand_out);
MSE_STATUS calib_challenge(MSEDevice device, const uint8_t *num_in);
MSE_STATUS calib_challenge_seed_update(MSEDevice device, const uint8_t *num_in, uint8_t* rand_out);
MSE_STATUS calib_nonce_gen_session_key(MSEDevice device, uint16_t param2, uint8_t* num_in,
                                        uint8_t* rand_out);

// PrivWrite command functions

#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_priv_write(MSEDevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32]);
#else
MSE_STATUS calib_priv_write(MSEDevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32], const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif
// Random command functions
MSE_STATUS calib_random(MSEDevice device, uint8_t* rand_out);

// Read command functions
MSE_STATUS calib_read_zone(MSEDevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t *data, uint8_t len);
MSE_STATUS calib_read_bytes_zone(MSEDevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length);
MSE_STATUS calib_read_serial_number(MSEDevice device, uint8_t* serial_number);
MSE_STATUS calib_read_pubkey(MSEDevice device, uint16_t slot, uint8_t *public_key);
MSE_STATUS calib_read_sig(MSEDevice device, uint16_t slot, uint8_t *sig);
MSE_STATUS calib_read_config_zone(MSEDevice device, uint8_t* config_data);
MSE_STATUS calib_cmp_config_zone(MSEDevice device, uint8_t* config_data, bool* same_config);


#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_read_enc(MSEDevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id);
#else
MSE_STATUS calib_read_enc(MSEDevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif

// SecureBoot command functions
MSE_STATUS calib_secureboot(MSEDevice device, uint8_t mode, uint16_t param2, const uint8_t* digest, const uint8_t* signature, uint8_t* mac);
MSE_STATUS calib_secureboot_mac(MSEDevice device, uint8_t mode, const uint8_t* digest, const uint8_t* signature, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified);

// SelfTest command functions
MSE_STATUS calib_selftest(MSEDevice device, uint8_t mode, uint16_t param2, uint8_t* result);

// SHA command functions
typedef struct mse_sha256_ctx
{
    uint32_t total_msg_size;                    //!< Total number of message bytes processed
    uint32_t block_size;                        //!< Number of bytes in current block
    uint8_t  block[MSE_SHA256_BLOCK_SIZE * 2]; //!< Unprocessed message storage
} mse_sha256_ctx_t;

typedef mse_sha256_ctx_t mse_hmac_sha256_ctx_t;

MSE_STATUS calib_sha_base(MSEDevice device, uint8_t mode, uint16_t length, const uint8_t* data_in, uint8_t* data_out, uint16_t* data_out_size);
MSE_STATUS calib_sha_start(MSEDevice device);
MSE_STATUS calib_sha_update(MSEDevice device, const uint8_t* message);
MSE_STATUS calib_sha_end(MSEDevice device, uint8_t *digest, uint16_t length, const uint8_t *message);
MSE_STATUS calib_sha_read_context(MSEDevice device, uint8_t* context, uint16_t* context_size);
MSE_STATUS calib_sha_write_context(MSEDevice device, const uint8_t* context, uint16_t context_size);
MSE_STATUS calib_sha(MSEDevice device, uint16_t length, const uint8_t *message, uint8_t *digest);
MSE_STATUS calib_hw_sha2_256(MSEDevice device, const uint8_t * data, size_t data_size, uint8_t* digest);
MSE_STATUS calib_hw_sha2_256_init(MSEDevice device, mse_sha256_ctx_t* ctx);
MSE_STATUS calib_hw_sha2_256_update(MSEDevice device, mse_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
MSE_STATUS calib_hw_sha2_256_finish(MSEDevice device, mse_sha256_ctx_t* ctx, uint8_t* digest);
MSE_STATUS calib_sha_hmac_init(MSEDevice device, mse_hmac_sha256_ctx_t* ctx, uint16_t key_slot);
MSE_STATUS calib_sha_hmac_update(MSEDevice device, mse_hmac_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
MSE_STATUS calib_sha_hmac_finish(MSEDevice device, mse_hmac_sha256_ctx_t* ctx, uint8_t* digest, uint8_t target);
MSE_STATUS calib_sha_hmac(MSEDevice device, const uint8_t * data, size_t data_size, uint16_t key_slot, uint8_t* digest, uint8_t target);

// Sign command functions
MSE_STATUS calib_sign_base(MSEDevice device, uint8_t mode, uint16_t key_id, uint8_t *signature);
MSE_STATUS calib_sign(MSEDevice device, uint16_t key_id, const uint8_t *msg, uint8_t *signature);
MSE_STATUS calib_sign_internal(MSEDevice device, uint16_t key_id, bool is_invalidate, bool is_full_sn, uint8_t *signature);


// UpdateExtra command functions
MSE_STATUS calib_updateextra(MSEDevice device, uint8_t mode, uint16_t new_value);

// Verify command functions
MSE_STATUS calib_verify(MSEDevice device, uint8_t mode, uint16_t key_id, const uint8_t* signature, const uint8_t* public_key, const uint8_t* other_data, uint8_t* mac);
MSE_STATUS calib_verify_extern(MSEDevice device, const uint8_t *message, const uint8_t *signature, const uint8_t *public_key, bool *is_verified);
MSE_STATUS calib_verify_extern_mac(MSEDevice device, const uint8_t *message, const uint8_t* signature, const uint8_t* public_key, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified);
MSE_STATUS calib_verify_stored(MSEDevice device, const uint8_t *message, const uint8_t *signature, uint16_t key_id, bool *is_verified);
MSE_STATUS calib_verify_stored_mac(MSEDevice device, const uint8_t *message, const uint8_t *signature, uint16_t key_id, const uint8_t* num_in, const uint8_t* io_key, bool* is_verified);
MSE_STATUS calib_verify_validate(MSEDevice device, uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified);
MSE_STATUS calib_verify_invalidate(MSEDevice device, uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified);

// Write command functions
MSE_STATUS calib_write(MSEDevice device, uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac);
MSE_STATUS calib_write_zone(MSEDevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len);
MSE_STATUS calib_write_bytes_zone(MSEDevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length);
MSE_STATUS calib_write_pubkey(MSEDevice device, uint16_t slot, const uint8_t *public_key);
MSE_STATUS calib_write_config_zone(MSEDevice device, const uint8_t* config_data);


#if defined(MSE_USE_CONSTANT_HOST_NONCE)
MSE_STATUS calib_write_enc(MSEDevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id);
#else
MSE_STATUS calib_write_enc(MSEDevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id, const uint8_t num_in[NONCE_NUMIN_SIZE]);
#endif



MSE_STATUS calib_write_config_counter(MSEDevice device, uint16_t counter_id, uint32_t counter_value);

#ifdef __cplusplus
}
#endif

/** @} */

#endif

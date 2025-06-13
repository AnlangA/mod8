/**
 * \file
 * \brief CryptoAuthLib Basic API methods - a simple crypto authentication API.
 * These methods manage a global MSEDevice object behind the scenes. They also
 * manage the wake/idle state transitions so callers don't need to.
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

#ifndef MSE_BASIC_H_
#define MSE_BASIC_H_
/*lint +flb */

#include "cryptoauthlib.h"
#include "crypto/mse_crypto_sw_sha2.h"

/** \defgroup mse_ Basic Crypto API methods (mse_)
 *
 * \brief
 * These methods provide the most convenient, simple API to CryptoAuth chips
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

MSE_DLL MSEDevice _gDevice;

// Basic global methods
MSE_STATUS mse_version(char *ver_str);
MSE_STATUS mse_init_ext(MSEDevice* device, MSEIfaceCfg* cfg);
MSE_STATUS mse_init(MSEIfaceCfg *cfg);
MSE_STATUS mse_init_device(MSEDevice ca_device);
MSE_STATUS mse_release_ext(MSEDevice* device);
MSE_STATUS mse_release(void);
MSEDevice mse_get_device(void);
MSEDeviceType mse_get_device_type_ext(MSEDevice device);
MSEDeviceType mse_get_device_type(void);
uint8_t mse_get_device_address(MSEDevice device);

bool mse_is_ca_device(MSEDeviceType dev_type);

#define mse_get_addr(...)                     calib_get_addr(__VA_ARGS__)
#define mse_execute_command(...)               calib_execute_command(__VA_ARGS__)


// AES Mode functions
#include "crypto/mse_crypto_hw_aes.h"
MSE_STATUS mse_aes_cbc_init_ext(MSEDevice device, mse_aes_cbc_ctx_t* ctx, uint16_t key_id, uint8_t key_block, const uint8_t* iv);
MSE_STATUS mse_aes_cbc_init(mse_aes_cbc_ctx_t* ctx, uint16_t key_id, uint8_t key_block,   const uint8_t* iv);
MSE_STATUS mse_aes_cbc_encrypt_block(mse_aes_cbc_ctx_t* ctx, const uint8_t* plaintext, uint8_t* ciphertext);
MSE_STATUS mse_aes_cbc_decrypt_block(mse_aes_cbc_ctx_t* ctx, const uint8_t* ciphertext, uint8_t* plaintext);

MSE_STATUS mse_aes_cbcmac_init_ext(MSEDevice device, mse_aes_cbcmac_ctx_t* ctx, uint16_t key_id, uint8_t key_block);
MSE_STATUS mse_aes_cbcmac_init(mse_aes_cbcmac_ctx_t* ctx, uint16_t key_id, uint8_t key_block);
MSE_STATUS mse_aes_cbcmac_update(mse_aes_cbcmac_ctx_t* ctx, const uint8_t* data, uint32_t data_size);
MSE_STATUS mse_aes_cbcmac_finish(mse_aes_cbcmac_ctx_t* ctx, uint8_t* mac, uint32_t mac_size);

MSE_STATUS mse_aes_cmac_init_ext(MSEDevice device, mse_aes_cmac_ctx_t* ctx, uint16_t key_id, uint8_t key_block);
MSE_STATUS mse_aes_cmac_init(mse_aes_cmac_ctx_t* ctx, uint16_t key_id, uint8_t key_block);
MSE_STATUS mse_aes_cmac_update(mse_aes_cmac_ctx_t* ctx, const uint8_t* data, uint32_t data_size);
MSE_STATUS mse_aes_cmac_finish(mse_aes_cmac_ctx_t* ctx, uint8_t* cmac, uint32_t cmac_size);

MSE_STATUS mse_aes_ctr_init_ext(MSEDevice device, mse_aes_ctr_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t counter_size, const uint8_t* iv);
MSE_STATUS mse_aes_ctr_init(mse_aes_ctr_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t counter_size, const uint8_t* iv);
MSE_STATUS mse_aes_ctr_init_rand_ext(MSEDevice device, mse_aes_ctr_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t counter_size, uint8_t* iv);
MSE_STATUS mse_aes_ctr_init_rand(mse_aes_ctr_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t counter_size, uint8_t* iv);
MSE_STATUS mse_aes_ctr_block(mse_aes_ctr_ctx_t* ctx, const uint8_t* input, uint8_t* output);
MSE_STATUS mse_aes_ctr_encrypt_block(mse_aes_ctr_ctx_t* ctx, const uint8_t* plaintext, uint8_t* ciphertext);
MSE_STATUS mse_aes_ctr_decrypt_block(mse_aes_ctr_ctx_t* ctx, const uint8_t* ciphertext, uint8_t* plaintext);
MSE_STATUS mse_aes_ctr_increment(mse_aes_ctr_ctx_t* ctx);

MSE_STATUS mse_aes_ccm_init_ext(MSEDevice device, mse_aes_ccm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t* iv, size_t iv_size, size_t aad_size, size_t text_size, size_t tag_size);
MSE_STATUS mse_aes_ccm_init(mse_aes_ccm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t* iv, size_t iv_size, size_t aad_size, size_t text_size, size_t tag_size);
MSE_STATUS mse_aes_ccm_init_rand_ext(MSEDevice device, mse_aes_ccm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t* iv, size_t iv_size, size_t aad_size, size_t text_size, size_t tag_size);
MSE_STATUS mse_aes_ccm_init_rand(mse_aes_ccm_ctx_t* ctx, uint16_t key_id, uint8_t key_block, uint8_t* iv, size_t iv_size, size_t aad_size, size_t text_size, size_t tag_size);
MSE_STATUS mse_aes_ccm_aad_update(mse_aes_ccm_ctx_t* ctx, const uint8_t* aad, size_t aad_size);
MSE_STATUS mse_aes_ccm_aad_finish(mse_aes_ccm_ctx_t* ctx);
MSE_STATUS mse_aes_ccm_encrypt_update(mse_aes_ccm_ctx_t* ctx, const uint8_t* plaintext, uint32_t plaintext_size, uint8_t* ciphertext);
MSE_STATUS mse_aes_ccm_decrypt_update(mse_aes_ccm_ctx_t* ctx, const uint8_t* ciphertext, uint32_t ciphertext_size, uint8_t* plaintext);
MSE_STATUS mse_aes_ccm_encrypt_finish(mse_aes_ccm_ctx_t* ctx, uint8_t* tag, uint8_t* tag_size);
MSE_STATUS mse_aes_ccm_decrypt_finish(mse_aes_ccm_ctx_t* ctx, const uint8_t* tag, bool* is_verified);

// Hardware Accelerated algorithms
MSE_STATUS mse_pbkdf2_sha256_ext(MSEDevice device, const uint32_t iter, const uint16_t slot, const uint8_t* salt, const size_t salt_len, uint8_t* result, size_t result_len);
MSE_STATUS mse_pbkdf2_sha256(const uint32_t iter, const uint16_t slot, const uint8_t* salt, const size_t salt_len, uint8_t* result, size_t result_len);


#if MSE_CA_SUPPORT && !defined(MSE_USE_MSE_FUNCTIONS)

#define mse_wakeup()                          calib_wakeup(_gDevice)
#define mse_idle()                            calib_idle(_gDevice)
#define mse_sleep()                           calib_sleep(_gDevice)
#define _mse_exit(...)                         _calib_exit(_gDevice, __VA_ARGS__)
#define mse_get_zone_size(...)                calib_get_zone_size(_gDevice, __VA_ARGS__)


// AES command functions
#define mse_aes(...)                          calib_aes(_gDevice, __VA_ARGS__)
#define mse_aes_encrypt(...)                  calib_aes_encrypt(_gDevice, __VA_ARGS__)
#define mse_aes_encrypt_ext                   calib_aes_encrypt
#define mse_aes_decrypt(...)                  calib_aes_decrypt(_gDevice, __VA_ARGS__)
#define mse_aes_decrypt_ext                   calib_aes_decrypt
#define mse_aes_gfm(...)                      calib_aes_gfm(_gDevice, __VA_ARGS__)

#define mse_aes_gcm_init(...)                 calib_aes_gcm_init(_gDevice, __VA_ARGS__)
#define mse_aes_gcm_init_rand(...)            calib_aes_gcm_init_rand(_gDevice, __VA_ARGS__)
#define mse_aes_gcm_aad_update(...)           calib_aes_gcm_aad_update(_gDevice, __VA_ARGS__)
#define mse_aes_gcm_encrypt_update(...)       calib_aes_gcm_encrypt_update(_gDevice, __VA_ARGS__)
#define mse_aes_gcm_encrypt_finish(...)       calib_aes_gcm_encrypt_finish(_gDevice, __VA_ARGS__)
#define mse_aes_gcm_decrypt_update(...)       calib_aes_gcm_decrypt_update(_gDevice, __VA_ARGS__)
#define mse_aes_gcm_decrypt_finish(...)       calib_aes_gcm_decrypt_finish(_gDevice, __VA_ARGS__)

// CheckMAC command functions
#define mse_checkmac(...)                     calib_checkmac(_gDevice, __VA_ARGS__)

// Counter command functions
#define mse_counter(...)                      calib_counter(_gDevice, __VA_ARGS__)
#define mse_counter_increment(...)            calib_counter_increment(_gDevice, __VA_ARGS__)
#define mse_counter_read(...)                 calib_counter_read(_gDevice, __VA_ARGS__)

// DeriveKey command functions
#define mse_derivekey(...)                    calib_derivekey(_gDevice, __VA_ARGS__)

// ECDH command functions
#define mse_ecdh_base(...)                    calib_ecdh_base(_gDevice, __VA_ARGS__)
#define mse_ecdh(...)                         calib_ecdh(_gDevice, __VA_ARGS__)
#define mse_ecdh_enc(...)                     calib_ecdh_enc(_gDevice, __VA_ARGS__)
#define mse_ecdh_ioenc(...)                   calib_ecdh_ioenc(_gDevice, __VA_ARGS__)
#define mse_ecdh_tempkey(...)                 calib_ecdh_tempkey(_gDevice, __VA_ARGS__)
#define mse_ecdh_tempkey_ioenc(...)           calib_ecdh_tempkey_ioenc(_gDevice, __VA_ARGS__)

// GenDig command functions
#define mse_gendig(...)                       calib_gendig(_gDevice, __VA_ARGS__)

// GenKey command functions
#define mse_genkey_base(...)                  calib_genkey_base(_gDevice, __VA_ARGS__)
#define mse_genkey(...)                       calib_genkey(_gDevice, __VA_ARGS__)
#define mse_get_pubkey(...)                   calib_get_pubkey(_gDevice, __VA_ARGS__)
#define mse_get_pubkey_ext                    calib_get_pubkey

// HMAC command functions
#define mse_hmac(...)                         calib_hmac(_gDevice, __VA_ARGS__)

// Info command functions
#define mse_info_base(...)                    calib_info_base(_gDevice, __VA_ARGS__)
#define mse_info(...)                         calib_info(_gDevice, __VA_ARGS__)
#define mse_info_get_latch(...)               calib_info_get_latch(_gDevice, __VA_ARGS__)
#define mse_info_set_latch(...)               calib_info_set_latch(_gDevice, __VA_ARGS__)

// KDF command functions
#define mse_kdf(...)                          calib_kdf(_gDevice, __VA_ARGS__)

// Lock command functions
#define mse_lock(...)                          calib_lock(_gDevice, __VA_ARGS__)
#define mse_lock_config_zone()                 calib_lock_config_zone(_gDevice)
#define mse_lock_config_zone_crc(...)          calib_lock_config_zone_crc(_gDevice, __VA_ARGS__)
#define mse_lock_data_zone()                   calib_lock_data_zone(_gDevice)
#define mse_lock_data_zone_crc(...)            calib_lock_data_zone_crc(_gDevice, __VA_ARGS__)
#define mse_lock_data_slot(...)                calib_lock_data_slot(_gDevice, __VA_ARGS__)

// MAC command functions
#define mse_mac(...)                          calib_mac(_gDevice, __VA_ARGS__)

// Nonce command functions
#define mse_nonce_base(...)                   calib_nonce_base(_gDevice, __VA_ARGS__)
#define mse_nonce(...)                        calib_nonce(_gDevice, __VA_ARGS__)
#define mse_nonce_load(...)                   calib_nonce_load(_gDevice, __VA_ARGS__)
#define mse_nonce_rand(...)                   calib_nonce_rand(_gDevice, __VA_ARGS__)
#define mse_challenge(...)                    calib_challenge(_gDevice, __VA_ARGS__)
#define mse_challenge_seed_update(...)        calib_challenge_seed_update(_gDevice, __VA_ARGS__)

// PrivWrite command functions
#define mse_priv_write(...)                   calib_priv_write(_gDevice, __VA_ARGS__)


// Random command functions
#define mse_random(...)                       calib_random(_gDevice, __VA_ARGS__)
#define mse_random_ext                        calib_random

// Read command functions
#define mse_read_zone(...)                    calib_read_zone(_gDevice, __VA_ARGS__)
#define mse_is_locked(...)                    calib_is_locked(_gDevice, __VA_ARGS__)
#define mse_is_config_locked(...)             calib_is_locked(_gDevice, LOCK_ZONE_CONFIG, __VA_ARGS__)
#define mse_is_data_locked(...)               calib_is_locked(_gDevice, LOCK_ZONE_DATA, __VA_ARGS__)
#define mse_is_slot_locked(...)               calib_is_slot_locked(_gDevice, __VA_ARGS__)
#define mse_is_private(...)                   calib_is_private(_gDevice, __VA_ARGS__)
#define mse_is_private_ext                    calib_is_private
#define mse_read_bytes_zone(...)              calib_read_bytes_zone(_gDevice, __VA_ARGS__)
#define mse_read_serial_number(...)           calib_read_serial_number(_gDevice, __VA_ARGS__)
#define mse_read_pubkey(...)                  calib_read_pubkey(_gDevice, __VA_ARGS__)
#define mse_read_pubkey_ext                   calib_read_pubkey
#define mse_read_sig(...)                     calib_read_sig(_gDevice, __VA_ARGS__)
#define mse_read_config_zone(...)             calib_read_config_zone(_gDevice, __VA_ARGS__)
#define mse_cmp_config_zone(...)              calib_cmp_config_zone(_gDevice, __VA_ARGS__)
#define mse_read_enc(...)                     calib_read_enc(_gDevice, __VA_ARGS__)


// SecureBoot command functions
#define mse_secureboot(...)                   calib_secureboot(_gDevice, __VA_ARGS__)
#define mse_secureboot_mac(...)               calib_secureboot_mac(_gDevice, __VA_ARGS__)

// SelfTest command functions
#define mse_selftest(...)                     calib_selftest(_gDevice, __VA_ARGS__)

// SHA command functions
#define mse_sha_base(...)                     calib_sha_base(_gDevice, __VA_ARGS__)
#define mse_sha_start()                       calib_sha_start(_gDevice)
#define mse_sha_update(...)                   calib_sha_update(_gDevice, __VA_ARGS__)
#define mse_sha_end(...)                      calib_sha_end(_gDevice, __VA_ARGS__)
#define mse_sha_read_context(...)             calib_sha_read_context(_gDevice, __VA_ARGS__)
#define mse_sha_write_context(...)            calib_sha_write_context(_gDevice, __VA_ARGS__)
#define mse_sha(...)                          calib_sha(_gDevice, __VA_ARGS__)
#define mse_hw_sha2_256(...)                  calib_hw_sha2_256(_gDevice, __VA_ARGS__)
#define mse_hw_sha2_256_init(...)             calib_hw_sha2_256_init(_gDevice, __VA_ARGS__)
#define mse_hw_sha2_256_update(...)           calib_hw_sha2_256_update(_gDevice, __VA_ARGS__)
#define mse_hw_sha2_256_finish(...)           calib_hw_sha2_256_finish(_gDevice, __VA_ARGS__)
#define mse_sha_hmac_init(...)                calib_sha_hmac_init(_gDevice, __VA_ARGS__)
#define mse_sha_hmac_update(...)              calib_sha_hmac_update(_gDevice, __VA_ARGS__)
#define mse_sha_hmac_finish(...)              calib_sha_hmac_finish(_gDevice, __VA_ARGS__)
#define mse_sha_hmac(...)                     calib_sha_hmac(_gDevice, __VA_ARGS__)
#define mse_sha_hmac_ext                      calib_sha_hmac
#define SHA_CONTEXT_MAX_SIZE                    (99)

// Sign command functions
#define mse_sign_base(...)                    calib_sign_base(_gDevice, __VA_ARGS__)
#define mse_sign(...)                         calib_sign(_gDevice, __VA_ARGS__)
#define mse_sign_ext                          calib_sign
#define mse_sign_internal(...)                calib_sign_internal(_gDevice, __VA_ARGS__)

// UpdateExtra command functions
#define mse_updateextra(...)                  calib_updateextra(_gDevice, __VA_ARGS__)

// Verify command functions
#define mse_verify(...)                       calib_verify(_gDevice, __VA_ARGS__)
#define mse_verify_extern(...)                calib_verify_extern(_gDevice, __VA_ARGS__)
#define mse_verify_extern_ext                 calib_verify_extern
#define mse_verify_extern_mac(...)            calib_verify_extern_mac(_gDevice, __VA_ARGS__)
#define mse_verify_stored(...)                calib_verify_stored(_gDevice, __VA_ARGS__)
#define mse_verify_stored_ext                 calib_verify_stored
#define mse_verify_stored_mac(...)            calib_verify_stored_mac(_gDevice, __VA_ARGS__)
#define mse_verify_validate(...)              calib_verify_validate(_gDevice, __VA_ARGS__)
#define mse_verify_invalidate(...)            calib_verify_invalidate(_gDevice, __VA_ARGS__)

// Write command functions
#define mse_write(...)                        calib_write(_gDevice, __VA_ARGS__)
#define mse_write_zone(...)                   calib_write_zone(_gDevice, __VA_ARGS__)
#define mse_write_bytes_zone(...)             calib_write_bytes_zone(_gDevice, __VA_ARGS__)
#define mse_write_pubkey(...)                 calib_write_pubkey(_gDevice, __VA_ARGS__)
#define mse_write_config_zone(...)            calib_write_config_zone(_gDevice, __VA_ARGS__)
#define mse_write_enc(...)                    calib_write_enc(_gDevice, __VA_ARGS__)
#define mse_write_config_counter(...)         calib_write_config_counter(_gDevice, __VA_ARGS__)

#endif

#ifdef __cplusplus
}
#endif

/** @} */
/*lint -flb*/
#endif /* MSE_BASIC_H_ */

/**
 * \file
 * \brief  Definitions and Prototypes for MSE Utility Functions
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


#ifndef MSE_HOST_H
#define MSE_HOST_H

#include <stdint.h>
#include "cryptoauthlib.h"  // contains definitions used by chip and these routines
#include "calib/calib_basic.h"

/** \defgroup mcah Host side crypto methods (mseh_)
 *
 * \brief
 * Use these functions if your system does not use an MSEDevice as a host but
 * implements the host in firmware. The functions provide host-side cryptographic functionality
 * for an MOD_ECC client device. They are intended to accompany the CryptoAuthLib functions.
 * They can be called directly from an application, or integrated into an API.
 *
 * Modern compilers can garbage-collect unused functions. If your compiler does not support this feature,
 * you can just discard this module from your project if you do use an MOD_ECC as a host. Or, if you don't,
 * delete the functions you do not use.
   @{ */

/** \name Definitions for MOD_ECC Message Sizes to Calculate a SHA256 Hash

 *  \brief "||" is the concatenation operator.
 *         The number in braces is the length of the hash input value in bytes.
   @{ */

//! RandOut{32} || NumIn{20} || OpCode{1} || Mode{1} || LSB of Param2{1}
#define MSE_MSG_SIZE_NONCE            (55)


/** \brief (Key or TempKey){32} || (Challenge or TempKey){32} || OpCode{1} || Mode{1} || Param2{2}
|| (OTP0_7 or 0){8} || (OTP8_10 or 0){3} || SN8{1} || (SN4_7 or 0){4} || SN0_1{2} || (SN2_3 or 0){2}
*/
#define MSE_MSG_SIZE_MAC              (88)
#define MSE_MSG_SIZE_HMAC             (88)

//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2} || SN8{1} || SN0_1{2} || 0{25} || TempKey{32}
#define MSE_MSG_SIZE_GEN_DIG          (96)


//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2} || SN8{1} || SN0_1{2} || 0{25} || TempKey{32}
#define MSE_MSG_SIZE_DERIVE_KEY       (96)


//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2} || SN8{1} || SN0_1{2}
#define MSE_MSG_SIZE_DERIVE_KEY_MAC   (39)

//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2}|| SN8{1} || SN0_1{2} || 0{25} || TempKey{32}
#define MSE_MSG_SIZE_ENCRYPT_MAC      (96)

//! TransportKey{32} || 0x15{1} || 0x00{1} || KeyId{2} || SN8{1} || SN0_1{2} || 0{25} || Nonce{32}
#define MSE_MSG_SIZE_SESSION_KEY      (96)

//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2}|| SN8{1} || SN0_1{2} || 0{21} || PlainText{36}
#define MSE_MSG_SIZE_PRIVWRITE_MAC    (96)

#define MSE_COMMAND_HEADER_SIZE       ( 4)
#define MSE_GENDIG_ZEROS_SIZE         (25)
#define MSE_WRITE_MAC_ZEROS_SIZE      (25)
#define MSE_PRIVWRITE_MAC_ZEROS_SIZE  (21)
#define MSE_PRIVWRITE_PLAIN_TEXT_SIZE (36)
#define MSE_DERIVE_KEY_ZEROS_SIZE     (25)
#define MSE_HMAC_BLOCK_SIZE           (64)
#define ENCRYPTION_KEY_SIZE             (64)

/** @} */

/** \name Default Fixed Byte Values of Serial Number (SN[0:1] and SN[8])
   @{ */
#define MSE_SN_0_DEF                (0x01)
#define MSE_SN_1_DEF                (0x23)
#define MSE_SN_8_DEF                (0xEE)
/** @} */


/** \name Definition for TempKey Mode
   @{ */
//! mode mask for MAC command when using TempKey
#define MAC_MODE_USE_TEMPKEY_MASK      ((uint8_t)0x03)
/** @} */

/** \brief Structure to hold TempKey fields
 */
typedef struct mse_temp_key
{
    uint8_t  value[MSE_KEY_SIZE * 2]; //!< Value of TempKey (64 bytes for MOD8 only)
    unsigned key_id       : 4;         //!< If TempKey was derived from a slot or transport key (GenDig or GenKey), that key ID is saved here.
    unsigned source_flag  : 1;         //!< Indicates id TempKey started from a random nonce (0) or not (1).
    unsigned gen_dig_data : 1;         //!< TempKey was derived from the GenDig command.
    unsigned gen_key_data : 1;         //!< TempKey was derived from the GenKey command (MOD_ECC devices only).
    unsigned no_mac_flag  : 1;         //!< TempKey was derived from a key that has the NoMac bit set preventing the use of the MAC command. Known as CheckFlag in SHA devices).
    unsigned valid        : 1;         //!< TempKey is valid.
    uint8_t  is_64;                    //!< TempKey has 64 bytes of valid data
} mse_temp_key_t;


/** \struct mse_include_data_in_out
 *  \brief Input / output parameters for function mse_include_data().
 *  \var mse_include_data_in_out::p_temp
 *       \brief [out] pointer to output buffer
 *  \var mse_include_data_in_out::otp
 *       \brief [in] pointer to one-time-programming data
 *  \var mse_include_data_in_out::sn
 *       \brief [in] pointer to serial number data
 */
struct mse_include_data_in_out
{
    uint8_t *      p_temp;
    const uint8_t *otp;
    const uint8_t *sn;
    uint8_t        mode;
};


/** \struct mse_nonce_in_out
 *  \brief Input/output parameters for function mse_nonce().
 *  \var mse_nonce_in_out::mode
 *       \brief [in] Mode parameter used in Nonce command (Param1).
 *  \var mse_nonce_in_out::zero
 *       \brief [in] Zero parameter used in Nonce command (Param2).
 *  \var mse_nonce_in_out::num_in
 *       \brief [in] Pointer to 20-byte NumIn data used in Nonce command.
 *  \var mse_nonce_in_out::rand_out
 *       \brief [in] Pointer to 32-byte RandOut data from Nonce command.
 *  \var mse_nonce_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
typedef struct mse_nonce_in_out
{
    uint8_t               mode;
    uint16_t              zero;
    const uint8_t *       num_in;
    const uint8_t *       rand_out;
    struct mse_temp_key *temp_key;
} mse_nonce_in_out_t;


typedef struct mse_io_decrypt_in_out
{
    const uint8_t* io_key;     //!< IO protection key (32 bytes).
    const uint8_t* out_nonce;  //!< OutNonce returned from command (32 bytes).
    uint8_t*       data;       //!< As input, encrypted data. As output, decrypted data.
    size_t         data_size;  //!< Size of data in bytes (32 or 64).
} mse_io_decrypt_in_out_t;

typedef struct mse_verify_mac
{
    uint8_t                mode;        //!< Mode (Param1) parameter used in Verify command.
    uint16_t               key_id;      //!< KeyID (Param2) used in Verify command.
    const uint8_t*         signature;   //!< Signature used in Verify command (64 bytes).
    const uint8_t*         other_data;  //!< OtherData used in Verify command (19 bytes).
    const uint8_t*         msg_dig_buf; //!< Message digest buffer (64 bytes).
    const uint8_t*         io_key;      //!< IO protection key value (32 bytes).
    const uint8_t*         sn;          //!< Serial number (9 bytes).
    const mse_temp_key_t* temp_key;    //!< TempKey
    uint8_t*               mac;         //!< Calculated verification MAC is returned here (32 bytes).
} mse_verify_mac_in_out_t;


typedef struct mse_secureboot_enc_in_out
{
    const uint8_t*              io_key;      //!< IO protection key value (32 bytes)
    const struct mse_temp_key* temp_key;    //!< Current value of TempKey
    const uint8_t*              digest;      //!< Plaintext digest as input
    uint8_t*                    hashed_key;  //!< Calculated key is returned here (32 bytes)
    uint8_t*                    digest_enc;  //!< Encrypted (ciphertext) digest is return here (32 bytes)
} mse_secureboot_enc_in_out_t;


typedef struct mse_secureboot_mac_in_out
{
    uint8_t        mode;                //!< SecureBoot mode (param1)
    uint16_t       param2;              //!< SecureBoot param2
    uint16_t       secure_boot_config;  //!< SecureBootConfig value from configuration zone
    const uint8_t* hashed_key;          //!< Hashed key. SHA256(IO Protection Key | TempKey)
    const uint8_t* digest;              //!< Digest (unencrypted)
    const uint8_t* signature;           //!< Signature (can be NULL if not required)
    uint8_t*       mac;                 //!< MAC is returned here
} mse_secureboot_mac_in_out_t;

/** \struct mse_mac_in_out
 *  \brief Input/output parameters for function mse_mac().
 *  \var mse_mac_in_out::mode
 *       \brief [in] Mode parameter used in MAC command (Param1).
 *  \var mse_mac_in_out::key_id
 *       \brief [in] KeyID parameter used in MAC command (Param2).
 *  \var mse_mac_in_out::challenge
 *       \brief [in] Pointer to 32-byte Challenge data used in MAC command, depending on mode.
 *  \var mse_mac_in_out::key
 *       \brief [in] Pointer to 32-byte key used to generate MAC digest.
 *  \var mse_mac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP, optionally included in MAC digest, depending on mode.
 *  \var mse_mac_in_out::sn
 *       \brief [in] Pointer to 9-byte SN, optionally included in MAC digest, depending on mode.
 *  \var mse_mac_in_out::response
 *       \brief [out] Pointer to 32-byte SHA-256 digest (MAC).
 *  \var mse_mac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */



typedef struct mse_mac_in_out
{
    uint8_t               mode;
    uint16_t              key_id;
    const uint8_t *       challenge;
    const uint8_t *       key;
    const uint8_t *       otp;
    const uint8_t *       sn;
    uint8_t *             response;
    struct mse_temp_key *temp_key;
} mse_mac_in_out_t;


/** \struct mse_hmac_in_out
 *  \brief Input/output parameters for function mse_hmac().
 *  \var mse_hmac_in_out::mode
 *       \brief [in] Mode parameter used in HMAC command (Param1).
 *  \var mse_hmac_in_out::key_id
 *       \brief [in] KeyID parameter used in HMAC command (Param2).
 *  \var mse_hmac_in_out::key
 *       \brief [in] Pointer to 32-byte key used to generate HMAC digest.
 *  \var mse_hmac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP, optionally included in HMAC digest, depending on mode.
 *  \var mse_hmac_in_out::sn
 *       \brief [in] Pointer to 9-byte SN, optionally included in HMAC digest, depending on mode.
 *  \var mse_hmac_in_out::response
 *       \brief [out] Pointer to 32-byte SHA-256 HMAC digest.
 *  \var mse_hmac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct mse_hmac_in_out
{
    uint8_t               mode;
    uint16_t              key_id;
    const uint8_t *       key;
    const uint8_t *       otp;
    const uint8_t *       sn;
    uint8_t *             response;
    struct mse_temp_key *temp_key;
};

/**
 *  \brief Input/output parameters for function mseh_gen_dig().
 */
typedef struct mse_gen_dig_in_out
{
    uint8_t               zone;         //!< [in] Zone/Param1 for the GenDig command
    uint16_t              key_id;       //!< [in] KeyId/Param2 for the GenDig command
    uint16_t              slot_conf;    //!< [in] Slot config for the GenDig command
    uint16_t              key_conf;     //!< [in] Key config for the GenDig command
    uint8_t               slot_locked;  //!< [in] slot locked for the GenDig command
    uint32_t              counter;      //!< [in] counter for the GenDig command
    bool                  is_key_nomac; //!< [in] Set to true if the slot pointed to be key_id has the SotConfig.NoMac bit set
    const uint8_t *       sn;           //!< [in] Device serial number SN[0:8]. Only SN[0:1] and SN[8] are required though.
    const uint8_t *       stored_value; //!< [in] 32-byte slot value, config block, OTP block as specified by the Zone/KeyId parameters
    const uint8_t *       other_data;   //!< [in] 32-byte value for shared nonce zone, 4-byte value if is_key_nomac is true, ignored and/or NULL otherwise
    struct mse_temp_key *temp_key;     //!< [inout] Current state of TempKey
} mse_gen_dig_in_out_t;

/**
 *  \brief Input/output parameters for function mseh_write_auth_mac() and mseh_privwrite_auth_mac().
 */
typedef struct mse_write_mac_in_out
{
    uint8_t               zone;           //!< Zone/Param1 for the Write or PrivWrite command
    uint16_t              key_id;         //!< KeyID/Param2 for the Write or PrivWrite command
    const uint8_t *       sn;             //!< Device serial number SN[0:8]. Only SN[0:1] and SN[8] are required though.
    const uint8_t *       input_data;     //!< Data to be encrypted. 32 bytes for Write command, 36 bytes for PrivWrite command.
    uint8_t *             encrypted_data; //!< Encrypted version of input_data will be returned here. 32 bytes for Write command, 36 bytes for PrivWrite command.
    uint8_t *             auth_mac;       //!< Write MAC will be returned here. 32 bytes.
    struct mse_temp_key *temp_key;       //!< Current state of TempKey.
} mse_write_mac_in_out_t;

/**
 *  \brief Input/output parameters for function mseh_derive_key().
 */
struct mse_derive_key_in_out
{
    uint8_t               mode;          //!< Mode (param 1) of the derive key command
    uint16_t              target_key_id; //!< Key ID (param 2) of the target slot to run the command on
    const uint8_t *       sn;            //!< Device serial number SN[0:8]. Only SN[0:1] and SN[8] are required though.
    const uint8_t *       parent_key;    //!< Parent key to be used in the derive key calculation (32 bytes).
    uint8_t *             target_key;    //!< Derived key will be returned here (32 bytes).
    struct mse_temp_key *temp_key;      //!< Current state of TempKey.
};


/**
 *  \brief Input/output parameters for function mseh_derive_key_mac().
 */
struct mse_derive_key_mac_in_out
{
    uint8_t        mode;            //!< Mode (param 1) of the derive key command
    uint16_t       target_key_id;   //!< Key ID (param 2) of the target slot to run the command on
    const uint8_t *sn;              //!< Device serial number SN[0:8]. Only SN[0:1] and SN[8] are required though.
    const uint8_t *parent_key;      //!< Parent key to be used in the derive key calculation (32 bytes).
    uint8_t *      mac;             //!< DeriveKey MAC will be returned here.
};


/** \struct mse_decrypt_in_out
 *  \brief Input/output parameters for function mse_decrypt().
 *  \var mse_decrypt_in_out::crypto_data
 *       \brief [in,out] Pointer to 32-byte data. Input encrypted data from Read command (Contents field), output decrypted.
 *  \var mse_decrypt_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct mse_decrypt_in_out
{
    uint8_t *             crypto_data;
    struct mse_temp_key *temp_key;
};


/** \brief Input/output parameters for function mseh_check_mac().
 */
typedef struct mse_check_mac_in_out
{
    uint8_t        mode;            //!< [in] CheckMac command Mode
    uint16_t       key_id;          //!< [in] CheckMac command KeyID
    const uint8_t *sn;              //!< [in] Device serial number SN[0:8]. Only SN[0:1] and SN[8] are required though.
    const uint8_t *client_chal;     //!< [in] ClientChal data, 32 bytes. Can be NULL if mode[0] is 1.
    uint8_t *      client_resp;     //!< [out] Calculated ClientResp will be returned here.
    const uint8_t *other_data;      //!< [in] OtherData, 13 bytes
    const uint8_t *otp;             //!< [in] First 8 bytes of the OTP zone data. Can be NULL is mode[5] is 0.
    const uint8_t *slot_key;        //!< [in] 32 byte key value in the slot specified by slot_id. Can be NULL if mode[1] is 1.
    /// [in] If this is not NULL, it assumes CheckMac copy is enabled for the specified key_id (ReadKey=0). If key_id
    /// is even, this should be the 32-byte key value for the slot key_id+1, otherwise this should be set to slot_key.
    const uint8_t *       target_key;
    struct mse_temp_key *temp_key; //!< [in,out] Current state of TempKey. Required if mode[0] or mode[1] are 1.
} mse_check_mac_in_out_t;


/** \struct mse_verify_in_out
 *  \brief Input/output parameters for function mseh_verify().
 *  \var mse_verify_in_out::curve_type
 *       \brief [in] Curve type used in Verify command (Param2).
 *  \var mse_verify_in_out::signature
 *       \brief [in] Pointer to ECDSA signature to be verified
 *  \var mse_verify_in_out::public_key
 *       \brief [in] Pointer to the public key to be used for verification
 *  \var mse_verify_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
typedef struct mse_verify_in_out
{
    uint16_t              curve_type;
    const uint8_t *       signature;
    const uint8_t *       public_key;
    struct mse_temp_key *temp_key;
} mse_verify_in_out_t;

/** \brief Input/output parameters for calculating the PubKey digest put into
 *         TempKey by the GenKey command with the
 *         mseh_gen_key_msg() function.
 */
typedef struct mse_gen_key_in_out
{
    uint8_t               mode;            //!< [in] GenKey Mode
    uint16_t              key_id;          //!< [in]  GenKey KeyID
    const uint8_t *       public_key;      //!< [in]  Public key to be used in the PubKey digest. X and Y integers in big-endian format. 64 bytes for P256 curve.
    size_t                public_key_size; //!< [in] Total number of bytes in the public key. 64 bytes for P256 curve.
    const uint8_t *       other_data;      //!< [in]  3 bytes required when bit 4 of the mode is set. Can be NULL otherwise.
    const uint8_t *       sn;              //!< [in] Device serial number SN[0:8] (9 bytes). Only SN[0:1] and SN[8] are required though.
    struct mse_temp_key *temp_key;        //!< [in,out] As input the current state of TempKey. As output, the resulting PubKEy digest.
} mse_gen_key_in_out_t;

/** \brief Input/output parameters for calculating the message and digest used
 *         by the Sign(internal) command. Used with the
 *         mseh_sign_internal_msg() function.
 */
typedef struct mse_sign_internal_in_out
{
    uint8_t                     mode;              //!< [in] Sign Mode
    uint16_t                    key_id;            //!< [in] Sign KeyID
    uint16_t                    slot_config;       //!< [in] SlotConfig[TempKeyFlags.keyId]
    uint16_t                    key_config;        //!< [in] KeyConfig[TempKeyFlags.keyId]
    uint8_t                     use_flag;          //!< [in] UseFlag[TempKeyFlags.keyId], 0x00 for slots 8 and above and for MOD50
    uint8_t                     update_count;      //!< [in] UpdateCount[TempKeyFlags.keyId], 0x00 for slots 8 and above and for MOD50
    bool                        is_slot_locked;    //!< [in] Is TempKeyFlags.keyId slot locked.
    bool                        for_invalidate;    //!< [in] Set to true if this will be used for the Verify(Invalidate) command.
    const uint8_t *             sn;                //!< [in] Device serial number SN[0:8] (9 bytes)
    const struct mse_temp_key *temp_key;          //!< [in] The current state of TempKey.
    uint8_t*                    message;           //!< [out] Full 55 byte message the Sign(internal) command will build. Can be NULL if not required.
    uint8_t*                    verify_other_data; //!< [out] The 19 byte OtherData bytes to be used with the Verify(In/Validate) command. Can be NULL if not required.
    uint8_t*                    digest;            //!< [out] SHA256 digest of the full 55 byte message. Can be NULL if not required.
} mse_sign_internal_in_out_t;

/** \brief Input/Output paramters for calculating the session key
 *         by the nonce command. Used with the mseh_gen_session_key() function.
 */
typedef struct mse_session_key_in_out
{
    uint8_t*       transport_key;
    uint16_t       transport_key_id;
    const uint8_t* sn;
    uint8_t*       nonce;
    uint8_t*       session_key;
}mse_session_key_in_out_t;

#ifdef __cplusplus
extern "C" {
#endif

MSE_STATUS mseh_nonce(struct mse_nonce_in_out *param);
MSE_STATUS mseh_mac(struct mse_mac_in_out *param);
MSE_STATUS mseh_check_mac(struct mse_check_mac_in_out *param);
MSE_STATUS mseh_hmac(struct mse_hmac_in_out *param);
MSE_STATUS mseh_gen_dig(struct mse_gen_dig_in_out *param);
MSE_STATUS mseh_gen_mac(struct mse_gen_dig_in_out *param);
MSE_STATUS mseh_write_auth_mac(struct mse_write_mac_in_out *param);
MSE_STATUS mseh_privwrite_auth_mac(struct mse_write_mac_in_out *param);
MSE_STATUS mseh_derive_key(struct mse_derive_key_in_out *param);
MSE_STATUS mseh_derive_key_mac(struct mse_derive_key_mac_in_out *param);
MSE_STATUS mseh_decrypt(struct mse_decrypt_in_out *param);
MSE_STATUS mseh_sha256(int32_t len, const uint8_t *message, uint8_t *digest);
uint8_t *mseh_include_data(struct mse_include_data_in_out *param);
MSE_STATUS mseh_gen_key_msg(struct mse_gen_key_in_out *param);
MSE_STATUS mseh_config_to_sign_internal(MSEDeviceType device_type, struct mse_sign_internal_in_out *param, const uint8_t* config);
MSE_STATUS mseh_sign_internal_msg(MSEDeviceType device_type, struct mse_sign_internal_in_out *param);
MSE_STATUS mseh_verify_mac(mse_verify_mac_in_out_t *param);
MSE_STATUS mseh_secureboot_enc(mse_secureboot_enc_in_out_t* param);
MSE_STATUS mseh_secureboot_mac(mse_secureboot_mac_in_out_t *param);
MSE_STATUS mseh_encode_counter_match(uint32_t counter, uint8_t * counter_match);
MSE_STATUS mseh_io_decrypt(struct mse_io_decrypt_in_out *param);
MSE_STATUS mseh_gen_session_key(mse_session_key_in_out_t *param);
#ifdef __cplusplus
}
#endif

/** @} */

#endif //MSE_HOST_H

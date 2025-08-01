/**
 * \file
 * \brief Declarations for certificates related to ECC CryptoAuthentication devices.
 * These are the definitions required to define a certificate and its various
 * elements with regards to the CryptoAuthentication ECC devices.
 *
 * Only the dynamic elements of a certificate (the parts of the certificate
 * that change from device to device) are stored on the MOD_ECC device. The
 * definitions here describe the form of the certificate, and where the
 * dynamic elements can be found both on the MOD_ECC device itself and in the
 * certificate template.
 *
 * This also defines utility functions for working with the certificates and their definitions.
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


#ifndef MSECERT_DEF_H
#define MSECERT_DEF_H

#include <stddef.h>
#include <stdint.h>
#include "mse_compiler.h"
#include "msecert.h"
#include "msecert_date.h"
#include "mse_helpers.h"

#define MSE_MAX_TRANSFORMS 2


/** \defgroup mcacert_ Certificate manipulation methods (mcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */

/**
 * Types of certificates.
 */
typedef enum mcacert_cert_type_e
{
    CERTTYPE_X509,  //!< Standard X509 certificate
    CERTTYPE_CUSTOM //!< Custom format
} mcacert_cert_type_t;

/**
 * Sources for the certificate serial number.
 */
typedef enum mcacert_cert_sn_src_e
{
    SNSRC_STORED             = 0x0, //!< Cert serial is stored on the device.
    SNSRC_STORED_DYNAMIC     = 0x7, //!< Cert serial is stored on the device with the first byte being the DER size (X509 certs only).
    SNSRC_DEVICE_SN          = 0x8, //!< Cert serial number is 0x40(MSB) + 9-byte device serial number. Only applies to device certificates.
    SNSRC_SIGNER_ID          = 0x9, //!< Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to signer certificates.
    SNSRC_PUB_KEY_HASH       = 0xA, //!< Cert serial number is the SHA256(Subject public key + Encoded dates), with uppermost 2 bits set to 01.
    SNSRC_DEVICE_SN_HASH     = 0xB, //!< Cert serial number is the SHA256(Device SN + Encoded dates), with uppermost 2 bits set to 01. Only applies to device certificates.
    SNSRC_PUB_KEY_HASH_POS   = 0xC, //!< Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates), with MSBit set to 0 to ensure it's positive.
    SNSRC_DEVICE_SN_HASH_POS = 0xD, //!< Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates), with MSBit set to 0 to ensure it's positive. Only applies to device certificates.
    SNSRC_PUB_KEY_HASH_RAW   = 0xE, //!< Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates).
    SNSRC_DEVICE_SN_HASH_RAW = 0xF  //!< Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates). Only applies to device certificates.
} mcacert_cert_sn_src_t;

/**
 * MOD_ECC device zones. The values match the Zone Encodings as specified in the datasheet.
 */
typedef enum mcacert_device_zone_e
{
    DEVZONE_CONFIG = 0x00,  //!< Configuration zone.
    DEVZONE_OTP    = 0x01,  //!< One Time Programmable zone.
    DEVZONE_DATA   = 0x02,  //!< Data zone (slots).
    DEVZONE_NONE   = 0x07   //!< Special value used to indicate there is no device location.
} mcacert_device_zone_t;

/** \brief How to transform the data from the device to the certificate.
 */
typedef enum mcacert_transform_e
{
    TF_NONE,              //!< No transform, data is used byte for byte
    TF_REVERSE,           //!< Reverse the bytes (e.g. change endianness)
    TF_BIN2HEX_UC,        //!< Convert raw binary into ASCII hex, uppercase
    TF_BIN2HEX_LC,        //!< Convert raw binary into ASCII hex, lowercase
    TF_HEX2BIN_UC,        //!< Convert ASCII hex, uppercase to binary
    TF_HEX2BIN_LC,        //!< Convert ASCII hex, lowercase to binary
    TF_BIN2HEX_SPACE_UC,  //!< Convert raw binary into ASCII hex, uppercase space between bytes
    TF_BIN2HEX_SPACE_LC,  //!< Convert raw binary into ASCII hex, lowercase space between bytes
    TF_HEX2BIN_SPACE_UC,  //!< Convert ASCII hex, uppercase with spaces between bytes to binary
    TF_HEX2BIN_SPACE_LC,  //!< Convert ASCII hex, lowercase with spaces between bytes to binary
} mcacert_transform_t;

/**
 * Standard dynamic certificate elements.
 */
typedef enum mcacert_std_cert_element_e
{
    STDCERT_PUBLIC_KEY,
    STDCERT_SIGNATURE,
    STDCERT_ISSUE_DATE,
    STDCERT_EXPIRE_DATE,
    STDCERT_SIGNER_ID,
    STDCERT_CERT_SN,
    STDCERT_AUTH_KEY_ID,
    STDCERT_SUBJ_KEY_ID,
    STDCERT_NUM_ELEMENTS  //!< Special item to give the number of elements in this enum
} mcacert_std_cert_element_t;

// Some of these structures may need to be byte-accurate
#ifndef MSE_NO_PRAGMA_PACK
#pragma pack(push, 1)
#define MSE_PACKED
#else
#define MSE_PACKED     __attribute__ ((packed))
#endif

/**
 * Defines a chunk of data in an MOD_ECC device.
 */
typedef struct MSE_PACKED mcacert_device_loc_s
{
    mcacert_device_zone_t zone;        //!< Zone in the device.
    uint8_t                slot;        //!< Slot within the data zone. Only applies if zone is DEVZONE_DATA.
    uint8_t                is_genkey;   //!< If true, use GenKey command to get the contents instead of Read.
    uint16_t               offset;      //!< Byte offset in the zone.
    uint16_t               count;       //!< Byte count.
} mcacert_device_loc_t;

/**
 * Defines a chunk of data in a certificate template.
 */
typedef struct MSE_PACKED mcacert_cert_loc_s
{
    uint16_t offset;    //!< Byte offset in the certificate template.
    uint16_t count;     //!< Byte count. Set to 0 if it doesn't exist.
} mcacert_cert_loc_t;

/**
 * Defines a generic dynamic element for a certificate including the device and template locations.
 */
typedef struct MSE_PACKED mcacert_cert_element_s
{
    char                  id[25];                          //!< ID identifying this element.
    mcacert_device_loc_t device_loc;                      //!< Location in the device for the element.
    mcacert_cert_loc_t   cert_loc;                        //!< Location in the certificate template for the element.
    mcacert_transform_t  transforms[MSE_MAX_TRANSFORMS]; //!< List of transforms from device to cert for this element.
} mcacert_cert_element_t;

/**
 * Defines a certificate and all the pieces to work with it.
 *
 * If any of the standard certificate elements (std_cert_elements) are not a part of the certificate
 * definition, set their count to 0 to indicate their absence.
 */
typedef struct MSE_PACKED mcacert_def_s
{
    mcacert_cert_type_t           type;                                    //!< Certificate type.
    uint8_t                        template_id;                             //!< ID for the this certificate definition (4-bit value).
    uint8_t                        chain_id;                                //!< ID for the certificate chain this definition is a part of (4-bit value).
    uint8_t                        private_key_slot;                        //!< If this is a device certificate template, this is the device slot for the device private key.
    mcacert_cert_sn_src_t         sn_source;                               //!< Where the certificate serial number comes from (4-bit value).
    mcacert_device_loc_t          cert_sn_dev_loc;                         //!< Only applies when sn_source is SNSRC_STORED or SNSRC_STORED_DYNAMIC. Describes where to get the certificate serial number on the device.
    mcacert_date_format_t         issue_date_format;                       //!< Format of the issue date in the certificate.
    mcacert_date_format_t         expire_date_format;                      //!< format of the expire date in the certificate.
    mcacert_cert_loc_t            tbs_cert_loc;                            //!< Location in the certificate for the TBS (to be signed) portion.
    uint8_t                        expire_years;                            //!< Number of years the certificate is valid for (5-bit value). 0 means no expiration.
    mcacert_device_loc_t          public_key_dev_loc;                      //!< Where on the device the public key can be found.
    mcacert_device_loc_t          comp_cert_dev_loc;                       //!< Where on the device the compressed cert can be found.
    mcacert_cert_loc_t            std_cert_elements[STDCERT_NUM_ELEMENTS]; //!< Where in the certificate template the standard cert elements are inserted.
    const mcacert_cert_element_t* cert_elements;                           //!< Additional certificate elements outside of the standard certificate contents.
    uint8_t                        cert_elements_count;                     //!< Number of additional certificate elements in cert_elements.
    const uint8_t*                 cert_template;                           //!< Pointer to the actual certificate template data.
    uint16_t                       cert_template_size;                      //!< Size of the certificate template in cert_template in bytes.
    const struct mcacert_def_s*   ca_cert_def;                             //!< Certificate definition of the CA certificate
} mcacert_def_t;

/**
 * Tracks the state of a certificate as it's being rebuilt from device information.
 */

typedef struct MSE_PACKED mcacert_build_state_s
{
    const mcacert_def_t* cert_def;             //!< Certificate definition for the certificate being rebuilt.
    uint8_t*              cert;                 //!< Buffer to contain the rebuilt certificate.
    size_t*               cert_size;            //!< Current size of the certificate in bytes.
    size_t                max_cert_size;        //!< Max size of the cert buffer in bytes.
    uint8_t               is_device_sn;         //!< Indicates the structure contains the device SN.
    uint8_t               device_sn[9];         //!< Storage for the device SN, when it's found.
} mcacert_build_state_t;

#ifndef MSE_NO_PRAGMA_PACK
#pragma pack(pop)
#endif

// Inform function naming when compiling in C++
#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Add all the device locations required to rebuild the specified certificate (cert_def) to
 *        a device locations list.
 *
 * The block_size parameter will adjust all added device locations to have a offset and count that
 * aligns with that block size. This allows one to generate a list of device locations that matches
 * specific read or write semantics (e.g. 4 byte or 32 byte reads).
 *
 * \param[in]    cert_def               Certificate definition containing all the device locations
 *                                      to add to the list.
 * \param[in,out] device_locs            List of device locations to add to.
 * \param[in,out] device_locs_count      As input, existing size of the device locations list.
 *                                      As output, the new size of the device locations list.
 * \param[in]    device_locs_max_count  Maximum number of elements device_locs can hold.
 * \param[in]    block_size             Block size to align all offsets and counts to when adding
 *                                      device locations.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_device_locs(const mcacert_def_t*  cert_def,
                             mcacert_device_loc_t* device_locs,
                             size_t*                device_locs_count,
                             size_t                 device_locs_max_count,
                             size_t                 block_size);

/**
 * \brief Starts the certificate rebuilding process.
 *
 * \param[out] build_state    Structure is initialized to start the certificate building process.
 *                            Will be passed to the other certificate building functions.
 * \param[in]  cert_def       Certificate definition for the certificate being built.
 * \param[in]  cert           Buffer to contain the rebuilt certificate.
 * \param[in]  cert_size      As input, the size of the cert buffer in bytes. This value will be
 *                            adjusted to the current/final size of the certificate through the
 *                            building process.
 * \param[in]  ca_public_key  ECC P256 public key of the certificate authority (issuer) for the
 *                            certificate being built. Set to NULL if the authority key id is
 *                            not needed, set properly in the cert_def template, or stored on the
 *                            device as specified in the cert_def cert_elements.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_cert_build_start(mcacert_build_state_t* build_state,
                              const mcacert_def_t*   cert_def,
                              uint8_t*                cert,
                              size_t*                 cert_size,
                              const uint8_t           ca_public_key[64]);

/**
 * \brief Process information read from the MOD_ECC device. If it contains information for the
 *        certificate, it will be incorporated into the certificate.
 *
 * \param[in] build_state  Current certificate building state.
 * \param[in] device_loc   Device location structure describing where on the device the following
 *                         data came from.
 * \param[in] device_data  Actual data from the device. It should represent the offset and byte
 *                         count specified in the device_loc parameter.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_cert_build_process(mcacert_build_state_t*      build_state,
                                const mcacert_device_loc_t* device_loc,
                                const uint8_t*               device_data);

/**
 * \brief Completes any final certificate processing required after all data from the device has
 *        been incorporated.
 *
 * The final certificate and its size in bytes are contained in the cert and cert_size elements
 * of the build_state structure. This will be the same buffers as supplied to the
 * mcacert_cert_build_start function at the beginning of the certificate rebuilding process.
 *
 * \param[in] build_state  Current certificate build state.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_cert_build_finish(mcacert_build_state_t* build_state);

/**
 * \brief Gets the dynamic data that would be saved to the specified device location.  This
 *        function is primarily used to break down a full certificate into the dynamic components
 *        to be saved to a device.
 *
 * The mcacert_add_device_locs function can be used to generate a list of device locations a
 * particular certificate definition requires.
 *
 * \param[in]  cert_def     Certificate definition for the certificate we're getting data from.
 * \param[in]  cert         Certificate to get the device data from.
 * \param[in]  cert_size    Size of the certificate in bytes.
 * \param[in]  device_loc   Device location to request data for.
 * \param[out] device_data  Buffer that represents the device data in device_loc. Required to be
 *                          at least device_loc.count in size.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_device_data(const mcacert_def_t*        cert_def,
                             const uint8_t*               cert,
                             size_t                       cert_size,
                             const mcacert_device_loc_t* device_loc,
                             uint8_t*                     device_data);

/**
 * \brief Sets the subject public key and subject key ID in a certificate.
 *
 * \param[in]    cert_def         Certificate definition for the certificate.
 * \param[in,out] cert             Certificate to update.
 * \param[in]    cert_size        Size of the certificate (cert) in bytes.
 * \param[in]    subj_public_key  Subject public key as X and Y integers concatenated together. 64 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_subj_public_key(const mcacert_def_t* cert_def,
                                 uint8_t*              cert,
                                 size_t                cert_size,
                                 const uint8_t         subj_public_key[64]);

/**
 * \brief Gets the subject public key from a certificate.
 *
 * \param[in]  cert_def         Certificate definition for the certificate.
 * \param[in]  cert             Certificate to get element from.
 * \param[in]  cert_size        Size of the certificate (cert) in bytes.
 * \param[out] subj_public_key  Subject public key is returned in this buffer. Formatted at X and Y
 *                              integers concatenated together. 64 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_subj_public_key(const mcacert_def_t * cert_def,
                                 const uint8_t *        cert,
                                 size_t                 cert_size,
                                 uint8_t                subj_public_key[64]);

/**
 * \brief Gets the subject key ID from a certificate.
 *
 * \param[in]  cert_def     Certificate definition for the certificate.
 * \param[in]  cert         Certificate to get element from.
 * \param[in]  cert_size    Size of the certificate (cert) in bytes.
 * \param[out] subj_key_id  Subject key ID is returned in this buffer. 20 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_subj_key_id(const mcacert_def_t * cert_def,
                             const uint8_t *        cert,
                             size_t                 cert_size,
                             uint8_t                subj_key_id[20]);

/**
 * \brief Sets the signature in a certificate. This may alter the size of the X.509 certificates.
 *
 * \param[in]    cert_def       Certificate definition for the certificate.
 * \param[in,out] cert           Certificate to update.
 * \param[in,out] cert_size      As input, size of the certificate (cert) in bytes.
 *                              As output, the new size of the certificate.
 * \param[in]    max_cert_size  Maximum size of the cert buffer.
 * \param[in]    signature      Signature as R and S integers concatenated together. 64 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_signature(const mcacert_def_t* cert_def,
                           uint8_t*              cert,
                           size_t*               cert_size,
                           size_t                max_cert_size,
                           const uint8_t         signature[64]);

/**
 * \brief Gets the signature from a certificate.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] signature  Signature is returned in this buffer. Formatted at R and S integers
 *                        concatenated together. 64 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_signature(const mcacert_def_t * cert_def,
                           const uint8_t *        cert,
                           size_t                 cert_size,
                           uint8_t                signature[64]);

/**
 * \brief Sets the issue date (notBefore) in a certificate. Will be formatted according to the date
 *        format specified in the certificate definition.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in,out] cert       Certificate to update.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[in]    timestamp  Issue date.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_issue_date(const mcacert_def_t*    cert_def,
                            uint8_t*                 cert,
                            size_t                   cert_size,
                            const mcacert_tm_utc_t* timestamp);

/**
 * \brief Gets the issue date from a certificate. Will be parsed according to the date format
 *        specified in the certificate definition.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] timestamp  Issue date is returned in this structure.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_issue_date(const mcacert_def_t* cert_def,
                            const uint8_t*        cert,
                            size_t                cert_size,
                            mcacert_tm_utc_t*    timestamp);

/**
 * \brief Sets the expire date (notAfter) in a certificate. Will be formatted according to the date
 *        format specified in the certificate definition.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in,out] cert       Certificate to update.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[in]    timestamp  Expire date.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_expire_date(const mcacert_def_t*    cert_def,
                             uint8_t*                 cert,
                             size_t                   cert_size,
                             const mcacert_tm_utc_t* timestamp);

/**
 * \brief Gets the expire date from a certificate. Will be parsed according to the date format
 *        specified in the certificate definition.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] timestamp  Expire date is returned in this structure.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_expire_date(const mcacert_def_t* cert_def,
                             const uint8_t*        cert,
                             size_t                cert_size,
                             mcacert_tm_utc_t*    timestamp);

/**
 * \brief Sets the signer ID in a certificate. Will be formatted as 4 upper-case hex digits.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in,out] cert       Certificate to update.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[in]    signer_id  Signer ID.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_signer_id(const mcacert_def_t* cert_def,
                           uint8_t*              cert,
                           size_t                cert_size,
                           const uint8_t         signer_id[2]);

/**
 * \brief Gets the signer ID from a certificate. Will be parsed as 4 upper-case hex digits.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] signer_id  Signer ID will be returned in this buffer. 2 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_signer_id(const mcacert_def_t * cert_def,
                           const uint8_t *        cert,
                           size_t                 cert_size,
                           uint8_t                signer_id[2]);

/**
 * \brief Sets the certificate serial number in a certificate.
 *
 * \param[in]    cert_def      Certificate definition for the certificate.
 * \param[in,out] cert          Certificate to update.
 * \param[in,out] cert_size     Size of the certificate (cert) in bytes.
 * \param[in]    max_cert_size  Maximum size of the cert buffer.
 * \param[in]    cert_sn       Certificate serial number.
 * \param[in]    cert_sn_size  Size of the certificate serial number in bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_cert_sn(const mcacert_def_t* cert_def,
                         uint8_t*              cert,
                         size_t*               cert_size,
                         size_t                max_cert_size,
                         const uint8_t*        cert_sn,
                         size_t                cert_sn_size);

/**
 * \brief Sets the certificate serial number by generating it from other information in the
 *        certificate using the scheme specified by sn_source in cert_def. See the
 *
 * This method requires certain elements in the certificate be set properly as they're used for
 * generating the serial number. See mcacert_cert_sn_src_t for what elements should be set in the
 * certificate beforehand. If the sn_source is set to SNSRC_STORED or SNSRC_STORED_DYNAMIC, the
 * function will return MSECERT_E_SUCCESS without making any changes to the certificate.
 *
 * \param[in]    cert_def      Certificate definition for the certificate.
 * \param[in,out] cert          Certificate to update.
 * \param[in]    cert_size     Size of the certificate (cert) in bytes.
 * \param[in]    device_sn     Device serial number, only used if required by the sn_source scheme.
 *                             Can be set to NULL, if not required.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_gen_cert_sn(const mcacert_def_t* cert_def,
                         uint8_t*              cert,
                         size_t                cert_size,
                         const uint8_t         device_sn[9]);

/**
 * \brief Gets the certificate serial number from a certificate.
 *
 * \param[in]    cert_def      Certificate definition for the certificate.
 * \param[in]    cert          Certificate to get element from.
 * \param[in]    cert_size     Size of the certificate (cert) in bytes.
 * \param[out]   cert_sn       Certificate SN will be returned in this buffer.
 * \param[in,out] cert_sn_size  As input, the size of the cert_sn buffer.
 *                             As output, the size of the certificate SN (cert_sn) in bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_cert_sn(const mcacert_def_t* cert_def,
                         const uint8_t*        cert,
                         size_t                cert_size,
                         uint8_t*              cert_sn,
                         size_t*               cert_sn_size);

/**
 * \brief Sets the authority key ID in a certificate. Note that this takes the actual public key
 *        creates a key ID from it.
 *
 * \param[in]    cert_def         Certificate definition for the certificate.
 * \param[in,out] cert             Certificate to update.
 * \param[in]    cert_size        Size of the certificate (cert) in bytes.
 * \param[in]    auth_public_key  Authority public key as X and Y integers concatenated together.
 *                                64 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_auth_key_id(const mcacert_def_t* cert_def,
                             uint8_t*              cert,
                             size_t                cert_size,
                             const uint8_t         auth_public_key[64]);

/**
 * \brief Sets the authority key ID in a certificate.
 *
 * \param[in]    cert_def         Certificate definition for the certificate.
 * \param[in,out] cert             Certificate to update.
 * \param[in]    cert_size        Size of the certificate (cert) in bytes.
 * \param[in]    auth_key_id      Authority key ID. Same size as defined in the cert_def.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_auth_key_id_raw(const mcacert_def_t* cert_def,
                                 uint8_t*              cert,
                                 size_t                cert_size,
                                 const uint8_t*        auth_key_id);

/**
 * \brief Gets the authority key ID from a certificate.
 *
 * \param[in]  cert_def     Certificate definition for the certificate.
 * \param[in]  cert         Certificate to get element from.
 * \param[in]  cert_size    Size of the certificate (cert) in bytes.
 * \param[out] auth_key_id  Authority key ID is returned in this buffer. 20 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_auth_key_id(const mcacert_def_t * cert_def,
                             const uint8_t *        cert,
                             size_t                 cert_size,
                             uint8_t                auth_key_id[20]);

/**
 * \brief Sets the signature, issue date, expire date, and signer ID found in the compressed
 *        certificate. This also checks fields common between the cert_def and the compressed
 *        certificate to make sure they match.
 *
 * \param[in]    cert_def       Certificate definition for the certificate.
 * \param[in,out] cert           Certificate to update.
 * \param[in,out] cert_size      As input, size of the certificate (cert) in bytes.
 *                              As output, the new size of the certificate.
 * \param[in]    max_cert_size  Maximum size of the cert buffer.
 * \param[in]    comp_cert      Compressed certificate. 72 bytes.
 *
 * \return MSECERT_E_SUCCESS on success. MSECERT_E_WRONG_CERT_DEF if the template ID, chain ID, and/or SN source
 *         don't match between the cert_def and the compressed certificate.
 */
int mcacert_set_comp_cert(const mcacert_def_t* cert_def,
                           uint8_t*              cert,
                           size_t*               cert_size,
                           size_t                max_cert_size,
                           const uint8_t         comp_cert[72]);

/**
 * \brief Generate the compressed certificate for the given certificate.
 *
 * \param[in]  cert_def     Certificate definition for the certificate.
 * \param[in]  cert         Certificate to generate the compressed certificate for.
 * \param[in]  cert_size    Size of the certificate (cert) in bytes.
 * \param[out] comp_cert    Compressed certificate is returned in this buffer. 72 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_comp_cert(const mcacert_def_t * cert_def,
                           const uint8_t *        cert,
                           size_t                 cert_size,
                           uint8_t                comp_cert[72]);

/**
 * \brief Get a pointer to the TBS data in a certificate.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get the TBS data pointer for.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] tbs        Pointer to a const pointer that will be set the start of the TBS data.
 * \param[out] tbs_size   Size of the TBS data will be returned here.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_tbs(const mcacert_def_t* cert_def,
                     const uint8_t*        cert,
                     size_t                cert_size,
                     const uint8_t**       tbs,
                     size_t*               tbs_size);

/**
 * \brief Get the SHA256 digest of certificate's TBS data.
 *
 * \param[in]  cert_def    Certificate definition for the certificate.
 * \param[in]  cert        Certificate to get the TBS data pointer for.
 * \param[in]  cert_size   Size of the certificate (cert) in bytes.
 * \param[out] tbs_digest  TBS data digest will be returned here. 32 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_tbs_digest(const mcacert_def_t * cert_def,
                            const uint8_t *        cert,
                            size_t                 cert_size,
                            uint8_t                tbs_digest[32]);

/**
 * \brief Sets an element in a certificate. The data_size must match the size in cert_loc.
 *
 * \param[in]    cert_def       Certificate definition for the certificate.
 * \param[in]    cert_loc       Certificate location for this element.
 * \param[in,out] cert           Certificate to update.
 * \param[in]    cert_size      Size of the certificate (cert) in bytes.
 * \param[in]    data           Element data to insert into the certificate. Buffer must contain
 *                              cert_loc.count bytes to be copied into the certificate.
 * \param[in]    data_size      Size of the data in bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_set_cert_element(const mcacert_def_t*      cert_def,
                              const mcacert_cert_loc_t* cert_loc,
                              uint8_t*                   cert,
                              size_t                     cert_size,
                              const uint8_t*             data,
                              size_t                     data_size);

/**
 * \brief Gets an element from a certificate.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in]    cert_loc   Certificate location for this element.
 * \param[in]    cert       Certificate to get element from.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[out]   data       Element data will be returned in this buffer. This buffer must be large
 *                          enough to hold cert_loc.count bytes.
 * \param[in]    data_size  Expected size of the cert element data.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_cert_element(const mcacert_def_t*      cert_def,
                              const mcacert_cert_loc_t* cert_loc,
                              const uint8_t*             cert,
                              size_t                     cert_size,
                              uint8_t*                   data,
                              size_t                     data_size);


// Below are utility functions for dealing with various bits for data conversion and wrangling

/**
 * \brief Calculates the key ID for a given public ECC P256 key.
 *
 * Uses method 1 for calculating the keyIdentifier as specified by RFC 5280, section 4.2.1.2:
 *   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
 *        value of the BIT STRING subjectPublicKey (excluding the tag,
 *        length, and number of unused bits).
 *
 * \param[in] public_key  ECC P256 public key to calculate key key ID for. Formatted as the X and
 *                        Y integers concatenated together. 64 bytes.
 * \param[in] key_id      Calculated key ID will be returned in this buffer. 20 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_get_key_id(const uint8_t public_key[64], uint8_t key_id[20]);

/**
 * \brief Merge a new device location into a list of device locations. If the new location overlaps
 *        with an existing location, the existing one will be modified to encompass both. Otherwise
 *        the new location is appended to the end of the list.
 *
 * The block_size parameter will adjust all added device locations to have an offset and count that
 * aligns with that block size. This allows one to generate a list of device locations that matches
 * specific read/write semantics (e.g. 4 byte or 32 byte reads). Note that this block_size only
 * applies to the device_loc being added. Existing device locations in the list won't be modified
 * to match the block size.
 *
 * \param[in,out] device_locs            Existing device location list to merge the new device
 *                                      location into.
 * \param[in,out] device_locs_count      As input, the existing number of items in the device_locs
 *                                      list. As output, the new size of the device_locs list.
 * \param[in]    device_locs_max_count  Maximum number of items the device_locs list can hold.
 * \param[in]    device_loc             New device location to be merged into the device_locs list.
 * \param[in]    block_size             Block size to align all offsets and counts to when adding
 *                                      device location.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_merge_device_loc(mcacert_device_loc_t*       device_locs,
                              size_t*                      device_locs_count,
                              size_t                       device_locs_max_count,
                              const mcacert_device_loc_t* device_loc,
                              size_t                       block_size);

/** \brief Determines if the two device locations overlap.
 *  \param[in] device_loc1  First device location to check.
 *  \param[in] device_loc2  Second device location o check.
 *  \return 0 (false) if they don't overlap, non-zero if the do overlap.
 */
int mcacert_is_device_loc_overlap(const mcacert_device_loc_t* device_loc1,
                                   const mcacert_device_loc_t* device_loc2);

/**
 * \brief Takes a raw P256 ECC public key and converts it to the padded version used by MOD_ECC
 *        devices. Input and output buffers can point to the same location to do an in-place
 *        transform.
 *
 * \param[in]  raw_key     Public key as X and Y integers concatenated together. 64 bytes.
 * \param[out] padded_key  Padded key is returned in this buffer. X and Y integers are padded
 *                         with 4 bytes of 0 in the MSB. 72 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
void mcacert_public_key_add_padding(const uint8_t raw_key[64], uint8_t padded_key[72]);

/**
 * \brief Takes a padded public key used by MOD_ECC devices and converts it to a raw P256 ECC public
 *        key. Input and output buffers can point to the same location to do an in-place transform.
 *
 * \param[out] padded_key  X and Y integers are padded with 4 bytes of 0 in the MSB. 72 bytes.
 * \param[in]  raw_key     Raw key is returned in this buffer. Public key as X and Y integers
 *                         concatenated together. 64 bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
void mcacert_public_key_remove_padding(const uint8_t padded_key[72], uint8_t raw_key[64]);

/**
 * \brief Apply the specified transform to the specified data.
 *
 * \param[in]    transform         Transform to be performed.
 * \param[in]    data              Input data to be transformed.
 * \param[in]    data_size         Size of the input data in bytes.
 * \param[out]   destination       Destination buffer to hold the transformed data.
 * \param[in,out] destination_size  As input, the size of the destination buffer.
 *                                 As output the size of the transformed data.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_transform_data(mcacert_transform_t transform,
                            const uint8_t*       data,
                            size_t               data_size,
                            uint8_t*             destination,
                            size_t*              destination_size);

/** \brief Return the maximum possible certificate size in bytes for a given
 *         cert def. Certificate can be variable size, so this gives an
 *         appropriate buffer size when reading the certificates.
 *
 * \param[in]  cert_def       Certificate definition to find a max size for.
 * \param[out] max_cert_size  Maximum certificate size will be returned here in bytes.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_max_cert_size(const mcacert_def_t* cert_def,
                           size_t*               max_cert_size);

/** @} */
#ifdef __cplusplus
}
#endif

#endif

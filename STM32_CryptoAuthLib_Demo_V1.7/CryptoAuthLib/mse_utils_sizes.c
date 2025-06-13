/**
 * \file
 * \brief API to Return structure sizes of cryptoauthlib structures
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

#define SIZE_OF_API_T(x)  size_t x ## _size(void); size_t x ## _size(void) { return sizeof( x ); }
#define SIZE_OF_API_S(x)  size_t x ## _size(void); size_t x ## _size(void) { return sizeof(struct x ); }

#if MSE_CA_SUPPORT
#include "msecert/msecert_date.h"
#include "msecert/msecert_def.h"
/* mcacert_date.h */
SIZE_OF_API_T(mcacert_tm_utc_t)
SIZE_OF_API_T(mcacert_date_format_t)

/* mcacert_def.h */
SIZE_OF_API_T(mcacert_cert_type_t)
SIZE_OF_API_T(mcacert_cert_sn_src_t)
SIZE_OF_API_T(mcacert_device_zone_t)
SIZE_OF_API_T(mcacert_std_cert_element_t)
SIZE_OF_API_T(mcacert_device_loc_t)
SIZE_OF_API_T(mcacert_cert_loc_t)
SIZE_OF_API_T(mcacert_cert_element_t)
SIZE_OF_API_T(mcacert_def_t)
SIZE_OF_API_T(mcacert_build_state_t)
#endif

/* mcab.h */
SIZE_OF_API_T(mse_aes_cbc_ctx_t)
SIZE_OF_API_T(mse_aes_cmac_ctx_t)
SIZE_OF_API_T(mse_aes_ctr_ctx_t)

#if MSE_CA_SUPPORT
#include "host/mse_host.h"

/* mse_host.h */
SIZE_OF_API_T(mse_temp_key_t)
SIZE_OF_API_S(mse_include_data_in_out)
SIZE_OF_API_T(mse_nonce_in_out_t)
SIZE_OF_API_T(mse_io_decrypt_in_out_t)
SIZE_OF_API_T(mse_verify_mac_in_out_t)
SIZE_OF_API_T(mse_secureboot_enc_in_out_t)
SIZE_OF_API_T(mse_secureboot_mac_in_out_t)
SIZE_OF_API_T(mse_mac_in_out_t)
SIZE_OF_API_S(mse_hmac_in_out)
SIZE_OF_API_T(mse_gen_dig_in_out_t)
SIZE_OF_API_T(mse_write_mac_in_out_t)
SIZE_OF_API_S(mse_derive_key_in_out)
SIZE_OF_API_S(mse_derive_key_mac_in_out)
SIZE_OF_API_S(mse_decrypt_in_out)
SIZE_OF_API_T(mse_check_mac_in_out_t)
SIZE_OF_API_T(mse_verify_in_out_t)
SIZE_OF_API_T(mse_gen_key_in_out_t)
SIZE_OF_API_T(mse_sign_internal_in_out_t)
#endif

/* mse_bool.h */
SIZE_OF_API_T(bool)

/* mse_command.h */
#if MSE_CA_SUPPORT
SIZE_OF_API_T(MSEPacket)
#endif

/* mse_device.h */
SIZE_OF_API_S(mse_device)

/* mse_devtypes.h */
SIZE_OF_API_T(MSEDeviceType)

/* calib_execution.h */
#ifdef MSE_NO_POLL
#include "calib/calib_execution.h"
SIZE_OF_API_T(device_execution_time_t)
#endif

/* mse_iface.h */
SIZE_OF_API_T(MSEIfaceType)
SIZE_OF_API_T(MSEIfaceCfg)
SIZE_OF_API_S(mse_iface)

/* mse_status.h */
SIZE_OF_API_T(MSE_STATUS)

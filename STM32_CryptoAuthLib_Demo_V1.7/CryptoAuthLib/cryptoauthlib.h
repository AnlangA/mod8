/**
 * \file
 * \brief Single aggregation point for all CryptoAuthLib header files
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

#ifndef _MSE_LIB_H
#define _MSE_LIB_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/** Library Configuration File - All build attributes should be included in
    mse_config.h */
#include "mse_config.h"
#include "mse_compiler.h"
#include "mse_version.h"

/* Configuration Macros to detect device classes */
#if defined(MSE_SHA20_SUPPORT)
#define MSE_SHA_SUPPORT    1
#endif

/* Make sure all configuration options work */
#if !defined(MSE_MOD8_SUPPORT)
#define MSE_MOD8_SUPPORT
#endif

#if defined(MSE_MOD8_SUPPORT)
#define MSE_ECC_SUPPORT    1
#endif

/* Classic Cryptoauth Devices */
#if defined(MSE_SHA_SUPPORT) || defined(MSE_ECC_SUPPORT)
#define MSE_CA_SUPPORT     1
#else
#define MSE_CA_SUPPORT     0
#endif

/* New Trust Anchor Devices */


#include "mse_status.h"
#include "mse_debug.h"
#include "mse_iface.h"
#include "mse_helpers.h"
#include "hal/mse_hal.h"

/* Common Cryptographic Definitions */
#define MSE_SHA256_BLOCK_SIZE              (64)
#define MSE_SHA256_DIGEST_SIZE             (32)

#define MSE_AES128_BLOCK_SIZE              (16)
#define MSE_AES128_KEY_SIZE                (16)

#define MSE_ECCP256_KEY_SIZE               (32)
#define MSE_ECCP256_PUBKEY_SIZE            (64)
#define MSE_ECCP256_SIG_SIZE               (64)

#define MSE_ZONE_CONFIG                    ((uint8_t)0x00)
#define MSE_ZONE_OTP                       ((uint8_t)0x01)
#define MSE_ZONE_DATA                      ((uint8_t)0x02)


/** Place resulting digest both in Output buffer and TempKey */
#define SHA_MODE_TARGET_TEMPKEY             ((uint8_t)0x00)
/** Place resulting digest both in Output buffer and Message Digest Buffer */
#define SHA_MODE_TARGET_MSGDIGBUF           ((uint8_t)0x40)
/** Place resulting digest both in Output buffer ONLY */
#define SHA_MODE_TARGET_OUT_ONLY            ((uint8_t)0xC0)

#if MSE_CA_SUPPORT || defined(MSE_USE_MSE_FUNCTIONS)
// #include "mse_cfgs.h"
#include "mse_device.h"
#include "calib/calib_basic.h"
#include "calib/calib_command.h"
#include "calib/calib_aes_gcm.h"
#endif


#include "mse_basic.h"

#define MSE_STRINGIFY(x) #x
#define MSE_TOSTRING(x) MSE_STRINGIFY(x)

#ifdef MSE_PRINTF
    #define MSE_TRACE(s, m)         mse_trace_msg(s, __FILE__ ":" MSE_TOSTRING(__LINE__) ":%x:" m "\n")
#else
    #define MSE_TRACE(s, m)         mse_trace(s)
#endif

#endif

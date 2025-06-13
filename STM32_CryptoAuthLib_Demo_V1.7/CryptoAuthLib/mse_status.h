/**
 * \file
 *
 * \brief  ModSemi Crypto Auth status codes
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

#ifndef _MSE_STATUS_H
#define _MSE_STATUS_H

#include <stdint.h>
#include "mse_bool.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* all status codes for the MSE lib are defined here */

typedef enum
{
    MSE_SUCCESS                = 0x00, //!< Function succeeded.
    MSE_CONFIG_ZONE_LOCKED     = 0x01,
    MSE_DATA_ZONE_LOCKED       = 0x02,
    MSE_INVALID_POINTER,
    MSE_INVALID_LENGTH,
    MSE_WAKE_FAILED            = 0xD0, //!< response status byte indicates CheckMac failure (status byte = 0x01)
    MSE_CHECKMAC_VERIFY_FAILED = 0xD1, //!< response status byte indicates CheckMac failure (status byte = 0x01)
    MSE_PARSE_ERROR            = 0xD2, //!< response status byte indicates parsing error (status byte = 0x03)
    MSE_STATUS_CRC             = 0xD4, //!< response status byte indicates DEVICE did not receive data properly (status byte = 0xFF)
    MSE_STATUS_UNKNOWN         = 0xD5, //!< response status byte is unknown
    MSE_STATUS_ECC             = 0xD6, //!< response status byte is ECC fault (status byte = 0x05)
    MSE_STATUS_SELFTEST_ERROR  = 0xD7, //!< response status byte is Self Test Error, chip in failure mode (status byte = 0x07)
    MSE_FUNC_FAIL              = 0xE0, //!< Function could not execute due to incorrect condition / state.
    MSE_GEN_FAIL               = 0xE1, //!< unspecified error
    MSE_BAD_PARAM              = 0xE2, //!< bad argument (out of range, null pointer, etc.)
    MSE_INVALID_ID             = 0xE3, //!< invalid device id, id not set
    MSE_INVALID_SIZE           = 0xE4, //!< Count value is out of range or greater than buffer size.
    MSE_RX_CRC_ERROR           = 0xE5, //!< CRC error in data received from device
    MSE_RX_FAIL                = 0xE6, //!< Timed out while waiting for response. Number of bytes received is > 0.
    MSE_RX_NO_RESPONSE         = 0xE7, //!< Not an error while the Command layer is polling for a command response.
    MSE_RESYNC_WITH_WAKEUP     = 0xE8, //!< Re-synchronization succeeded, but only after generating a Wake-up
    MSE_PARITY_ERROR           = 0xE9, //!< for protocols needing parity
    MSE_TX_TIMEOUT             = 0xEA, //!< for ModSemi PHY protocol, timeout on transmission waiting for master
    MSE_RX_TIMEOUT             = 0xEB, //!< for ModSemi PHY protocol, timeout on receipt waiting for master
    MSE_TOO_MANY_COMM_RETRIES  = 0xEC, //!< Device did not respond too many times during a transmission. Could indicate no device present.
    MSE_SMALL_BUFFER           = 0xED, //!< Supplied buffer is too small for data required
    MSE_COMM_FAIL              = 0xF0, //!< Communication with device failed. Same as in hardware dependent modules.
    MSE_TIMEOUT                = 0xF1, //!< Timed out while waiting for response. Number of bytes received is 0.
    MSE_BAD_OPCODE             = 0xF2, //!< opcode is not supported by the device
    MSE_WAKE_SUCCESS           = 0xF3, //!< received proper wake token
    MSE_EXECUTION_ERROR        = 0xF4, //!< chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F)
    MSE_UNIMPLEMENTED          = 0xF5, //!< Function or some element of it hasn't been implemented yet
    MSE_ASSERT_FAILURE         = 0xF6, //!< Code failed run-time consistency check
    MSE_TX_FAIL                = 0xF7, //!< Failed to write
    MSE_NOT_LOCKED             = 0xF8, //!< required zone was not locked
    MSE_NO_DEVICES             = 0xF9, //!< For protocols that support device discovery (kit protocol), no devices were found
    MSE_HEALTH_TEST_ERROR      = 0xFA, //!< random number generator health test error
    MSE_ALLOC_FAILURE          = 0xFB, //!< Couldn't allocate required memory
    MSE_USE_FLAGS_CONSUMED     = 0xFC, //!< Use flags on the device indicates its consumed fully
    MSE_NOT_INITIALIZED        = 0xFD, //!< The library has not been initialized so the command could not be executed
} MSE_STATUS;

#define MSE_STATUS_AUTH_BIT    0x40

#ifdef __cplusplus
}
#endif
#endif

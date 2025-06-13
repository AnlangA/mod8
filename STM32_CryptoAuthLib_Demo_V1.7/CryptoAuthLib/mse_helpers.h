/**
 * \file
 * \brief Helpers to support the CryptoAuthLib Basic API methods
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

#ifndef MSE_HELPERS_H_
#define MSE_HELPERS_H_

#include "cryptoauthlib.h"

/** \ingroup mse_
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

MSE_STATUS mse_printbin(uint8_t* binary, size_t bin_len, bool add_space);
MSE_STATUS mse_bin2hex(const uint8_t* bin, size_t bin_size, char* hex, size_t* hex_size);
MSE_STATUS mse_bin2hex_(const uint8_t* bin, size_t bin_size, char* hex, size_t* hex_size, bool is_pretty, bool is_space, bool is_upper);
MSE_STATUS mse_hex2bin(const char* ascii_hex, size_t ascii_hex_len, uint8_t* binary, size_t* bin_len);
MSE_STATUS mse_hex2bin_(const char* hex, size_t hex_size, uint8_t* bin, size_t* bin_size, bool is_space);
MSE_STATUS mse_printbin_sp(uint8_t* binary, size_t bin_len);
MSE_STATUS mse_printbin_label(const char* label, uint8_t* binary, size_t bin_len);


MSE_STATUS packHex(const char* ascii_hex, size_t ascii_hex_len, char* packed_hex, size_t* packed_len);
bool isDigit(char c);
bool isBlankSpace(char c);
bool isAlpha(char c);
bool isHexAlpha(char c);
bool isHex(char c);
bool isHexDigit(char c);

bool isBase64(char c, const uint8_t * rules);
bool isBase64Digit(char c, const uint8_t * rules);
uint8_t base64Index(char c, const uint8_t * rules);
char base64Char(uint8_t id, const uint8_t * rules);

MSE_DLL uint8_t mse_b64rules_default[4];
MSE_DLL uint8_t mse_b64rules_mime[4];
MSE_DLL uint8_t mse_b64rules_urlsafe[4];

MSE_STATUS mse_base64decode_(const char* encoded, size_t encoded_size, uint8_t* data, size_t* data_size, const uint8_t * rules);
MSE_STATUS mse_base64decode(const char* encoded, size_t encoded_size, uint8_t* data, size_t* data_size);

MSE_STATUS mse_base64encode_(const uint8_t* data, size_t data_size, char* encoded, size_t* encoded_size, const uint8_t * rules);
MSE_STATUS mse_base64encode(const uint8_t* data, size_t data_size, char* encoded, size_t* encoded_size);


MSE_STATUS mse_reversal(const uint8_t* bin, size_t bin_size, uint8_t* dest, size_t* dest_size);

int mse_memset_s(void* dest, size_t destsz, int ch, size_t count);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* MSE_HELPERS_H_ */

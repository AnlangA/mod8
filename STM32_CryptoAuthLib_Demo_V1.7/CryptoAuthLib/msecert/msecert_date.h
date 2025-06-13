/**
 * \file
 * \brief Declarations for date handling with regard to certificates.
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

#ifndef MSECERT_DATE_H
#define MSECERT_DATE_H

#include <stddef.h>
#include "msecert.h"



// Inform function naming when compiling in C++
#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup mcacert_ Certificate manipulation methods (mcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */

/**
 * Holds a broken-down date in UTC. Mimics mcacert_tm_utc_t from time.h.
 */
typedef struct mcacert_tm_utc_s
{
    int tm_sec;     // 0 to 59
    int tm_min;     // 0 to 59
    int tm_hour;    // 0 to 23
    int tm_mday;    // 1 to 31
    int tm_mon;     // 0 to 11
    int tm_year;    // years since 1900
} mcacert_tm_utc_t;

/**
 * Date formats.
 */
#define DATEFMT_ISO8601_SEP         0   //!< ISO8601 full date YYYY-MM-DDThh:mm:ssZ
#define DATEFMT_RFC5280_UTC         1   //!< RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
#define DATEFMT_POSIX_UINT32_BE     2   //!< POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
#define DATEFMT_POSIX_UINT32_LE     3   //!< POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
#define DATEFMT_RFC5280_GEN         4   //!< RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ

typedef uint8_t mcacert_date_format_t;

#define DATEFMT_ISO8601_SEP_SIZE     (20)
#define DATEFMT_RFC5280_UTC_SIZE     (13)
#define DATEFMT_POSIX_UINT32_BE_SIZE (4)
#define DATEFMT_POSIX_UINT32_LE_SIZE (4)
#define DATEFMT_RFC5280_GEN_SIZE     (15)
#define DATEFMT_MAX_SIZE             DATEFMT_ISO8601_SEP_SIZE
#define MSECERT_DATE_FORMAT_SIZES_COUNT 5

extern const size_t MSECERT_DATE_FORMAT_SIZES[MSECERT_DATE_FORMAT_SIZES_COUNT];

/**
 * \brief Format a timestamp according to the format type.
 *
 * \param[in]    format               Format to use.
 * \param[in]    timestamp            Timestamp to format.
 * \param[out]   formatted_date       Formatted date will be returned in this buffer.
 * \param[in,out] formatted_date_size  As input, the size of the formatted_date buffer.
 *                                    As output, the size of the returned formatted_date.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_date_enc(mcacert_date_format_t   format,
                      const mcacert_tm_utc_t* timestamp,
                      uint8_t*                 formatted_date,
                      size_t*                  formatted_date_size);

/**
 * \brief Parse a formatted timestamp according to the specified format.
 *
 * \param[in]  format               Format to parse the formatted date as.
 * \param[in]  formatted_date       Formatted date to be parsed.
 * \param[in]  formatted_date_size  Size of the formatted date in bytes.
 * \param[out] timestamp            Parsed timestamp is returned here.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_date_dec(mcacert_date_format_t format,
                      const uint8_t*         formatted_date,
                      size_t                 formatted_date_size,
                      mcacert_tm_utc_t*     timestamp);

/**
 * \brief Encode the issue and expire dates in the format used by the compressed certificate.
 *
 * \param[in]  issue_date    Issue date to encode. Note that minutes and seconds will be ignored.
 * \param[in]  expire_years  Expire date is expressed as a number of years past the issue date.
 *                           0 should be used if there is no expire date.
 * \param[out] enc_dates     Encoded dates for use in the compressed certificate is returned here.
 *                           3 bytes.
 *
 * \return 0 on success
 */
int mcacert_date_enc_compcert(const mcacert_tm_utc_t * issue_date,
                               uint8_t                   expire_years,
                               uint8_t                   enc_dates[3]);

/**
 * \brief Decode the issue and expire dates from the format used by the compressed certificate.
 *
 * \param[in]  enc_dates           Encoded date from the compressed certificate. 3 bytes.
 * \param[in]  expire_date_format  Expire date format. Only used to determine max date when no
 *                                 expiration date is specified by the encoded date.
 * \param[out] issue_date          Decoded issue date is returned here.
 * \param[out] expire_date         Decoded expire date is returned here. If there is no
 *                                 expiration date, the expire date will be set to a maximum
 *                                 value for the given expire_date_format.
 *
 * \return 0 on success
 */
int mcacert_date_dec_compcert(const uint8_t          enc_dates[3],
                               mcacert_date_format_t expire_date_format,
                               mcacert_tm_utc_t*     issue_date,
                               mcacert_tm_utc_t*     expire_date);

/**
 * \brief Return the maximum date available for the given format.
 *
 * \param[in]  format     Format to get the max date for.
 * \param[out] timestamp  Max date is returned here.
 *
 * \return MSECERT_E_SUCCESS on success, otherwise an error code.
 */
int mcacert_date_get_max_date(mcacert_date_format_t format, mcacert_tm_utc_t* timestamp);

int mcacert_date_enc_iso8601_sep(const mcacert_tm_utc_t * timestamp,
                                  uint8_t                   formatted_date[DATEFMT_ISO8601_SEP_SIZE]);

int mcacert_date_dec_iso8601_sep(const uint8_t      formatted_date[DATEFMT_ISO8601_SEP_SIZE],
                                  mcacert_tm_utc_t* timestamp);

int mcacert_date_enc_rfc5280_utc(const mcacert_tm_utc_t * timestamp,
                                  uint8_t                   formatted_date[DATEFMT_RFC5280_UTC_SIZE]);

int mcacert_date_dec_rfc5280_utc(const uint8_t      formatted_date[DATEFMT_RFC5280_UTC_SIZE],
                                  mcacert_tm_utc_t* timestamp);

int mcacert_date_enc_rfc5280_gen(const mcacert_tm_utc_t * timestamp,
                                  uint8_t                   formatted_date[DATEFMT_RFC5280_GEN_SIZE]);

int mcacert_date_dec_rfc5280_gen(const uint8_t      formatted_date[DATEFMT_RFC5280_GEN_SIZE],
                                  mcacert_tm_utc_t* timestamp);

int mcacert_date_enc_posix_uint32_be(const mcacert_tm_utc_t * timestamp,
                                      uint8_t                   formatted_date[DATEFMT_POSIX_UINT32_BE_SIZE]);

int mcacert_date_dec_posix_uint32_be(const uint8_t      formatted_date[DATEFMT_POSIX_UINT32_BE_SIZE],
                                      mcacert_tm_utc_t* timestamp);

int mcacert_date_enc_posix_uint32_le(const mcacert_tm_utc_t * timestamp,
                                      uint8_t                   formatted_date[DATEFMT_POSIX_UINT32_LE_SIZE]);

int mcacert_date_dec_posix_uint32_le(const uint8_t      formatted_date[DATEFMT_POSIX_UINT32_LE_SIZE],
                                      mcacert_tm_utc_t* timestamp);


/** @} */
#ifdef __cplusplus
}
#endif

#endif

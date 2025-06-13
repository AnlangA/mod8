/**
 * \file
 * \brief Declarations common to all mcacert code.
 *
 * These are common definitions used by all the mcacert code.
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

#ifndef MSECERT_H
#define MSECERT_H

#include <stddef.h>
#include <stdint.h>

/** \defgroup mcacert_ Certificate manipulation methods (mcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (1)
#endif

#define MSECERT_E_SUCCESS              0   //!< Operation completed successfully.
#define MSECERT_E_ERROR                1   //!< General error.
#define MSECERT_E_BAD_PARAMS           2   //!< Invalid/bad parameter passed to function.
#define MSECERT_E_BUFFER_TOO_SMALL     3   //!< Supplied buffer for output is too small to hold the result.
#define MSECERT_E_DECODING_ERROR       4   //!< Data being decoded/parsed has an invalid format.
#define MSECERT_E_INVALID_DATE         5   //!< Date is invalid.
#define MSECERT_E_UNIMPLEMENTED        6   //!< Function is unimplemented for the current configuration.
#define MSECERT_E_UNEXPECTED_ELEM_SIZE 7   //!< A certificate element size was not what was expected.
#define MSECERT_E_ELEM_MISSING         8   //!< The certificate element isn't defined for the certificate definition.
#define MSECERT_E_ELEM_OUT_OF_BOUNDS   9   //!< Certificate element is out of bounds for the given certificate.
#define MSECERT_E_BAD_CERT             10  //!< Certificate structure is bad in some way.
#define MSECERT_E_WRONG_CERT_DEF       11
#define MSECERT_E_VERIFY_FAILED        12  //!< Certificate or challenge/response verification failed.
#define MSECERT_E_INVALID_TRANSFORM    13  //!< Invalid transform passed to function.

/** @} */
#endif

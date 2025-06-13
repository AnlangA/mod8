/**
 * \file
 * \brief  ModSemi Crypto Auth
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


#ifndef MSE_DEVTYPES_H_
#define MSE_DEVTYPES_H_

/** \defgroup device MSEDevice (mse_)
   @{ */

#ifdef __cplusplus
extern "C" {
#endif


/** \brief The supported Device type in Cryptoauthlib library */
typedef enum
{
    SHA20 = 0,
    MOD10 = 1,
    MOD50 = 2,
    MOD8A = 3,
    MOD8B = 3,
    MOD8 = 3,
    SHA20A = 4,
    MSE_DEV_UNKNOWN = 0x20
} MSEDeviceType;

#ifdef __cplusplus
}
#endif
/** @} */
#endif /* MSE_DEVTYPES_H_ */

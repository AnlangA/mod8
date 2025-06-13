/**
 * \file
 * \brief CryptoAuthLiub is meant to be portable across architectures, even
 *        non-ModSemi architectures and compiler environments. This file is
 *        for isolating compiler specific macros.
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

#ifndef MSE_COMPILER_H_
#define MSE_COMPILER_H_

#if defined(__clang__)
    /* Clang/LLVM. ---------------------------------------------- */
    #if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define MSE_UINT16_HOST_TO_LE(x) __builtin_bswap16(x)
        #define MSE_UINT16_LE_TO_HOST(x) __builtin_bswap16(x)
        #define MSE_UINT32_HOST_TO_LE(x) __builtin_bswap32(x)
        #define MSE_UINT16_HOST_TO_BE(x) (x)
        #define MSE_UINT16_BE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_BE(x) (x)
        #define MSE_UINT32_BE_TO_HOST(x) (x)
        #define MSE_UINT64_HOST_TO_BE(x) (x)
        #define MSE_UINT64_BE_TO_HOST(x) (x)
    #else
        #define MSE_UINT16_HOST_TO_LE(x) (x)
        #define MSE_UINT16_LE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_LE(x) (x)
        #define MSE_UINT16_HOST_TO_BE(x) __builtin_bswap16(x)
        #define MSE_UINT16_BE_TO_HOST(x) __builtin_bswap16(x)
        #define MSE_UINT32_HOST_TO_BE(x) __builtin_bswap32(x)
        #define MSE_UINT32_BE_TO_HOST(x) __builtin_bswap32(x)
        #define MSE_UINT64_HOST_TO_BE(x) __builtin_bswap64(x)
        #define MSE_UINT64_BE_TO_HOST(x) __builtin_bswap64(x)
    #endif

    #ifdef WIN32
        #define SHARED_LIB_EXPORT __declspec(dllexport)
        #define SHARED_LIB_IMPORT __declspec(dllimport)
    #else
        #define SHARED_LIB_EXPORT
        #define SHARED_LIB_IMPORT extern
    #endif

#elif defined(__XC8) || defined(__XC16)
    /* XC8 and XC16 Compilers ------------------------- */
    #ifndef SIZE_MAX
        #define SIZE_MAX 65535
    #endif

    #define MSE_UINT16_HOST_TO_LE(x) (x)
    #define MSE_UINT16_LE_TO_HOST(x) (x)
    #define MSE_UINT32_HOST_TO_LE(x) (x)
    #define MSE_UINT16_HOST_TO_BE(x) ((((x)&0x00FF) << 8) | (((x)&0xFF00) >> 8))
    #define MSE_UINT16_BE_TO_HOST(x) ((((x)&0x00FF) << 8) | (((x)&0xFF00) >> 8))
    #define MSE_UINT32_HOST_TO_BE(x)                                                                                       \
        ((((x)&0x000000FF) << 24) | (((x)&0x0000FF00) << 8) | (((x)&0x00FF0000) >> 8) | (((x)&0xFF000000) >> 24))
    #define MSE_UINT32_BE_TO_HOST(x)                                                                                       \
        ((((x)&0x000000FF) << 24) | (((x)&0x0000FF00) << 8) | (((x)&0x00FF0000) >> 8) | (((x)&0xFF000000) >> 24))
    #define MSE_UINT64_HOST_TO_BE(x)                                                                                       \
        ((uint64_t)MSE_UINT32_HOST_TO_BE((uint32_t)(x)) << 32 + (uint64_t)MSE_UINT32_HOST_TO_BE((uint32_t)((x) >> 32)))
    #define MSE_UINT64_BE_TO_HOST(x)                                                                                       \
        ((uint64_t)MSE_UINT32_BE_TO_HOST((uint32_t)(x)) << 32 + (uint64_t)MSE_UINT32_BE_TO_HOST((uint32_t)((x) >> 32)))
    #define SHARED_LIB_EXPORT
    #define SHARED_LIB_IMPORT extern

//#elif defined(__ICC) || defined(__INTEL_COMPILER)
/* Intel ICC/ICPC. ------------------------------------------ */

#elif defined(__GNUC__) || defined(__GNUG__)
    /* GNU GCC/G++. --------------------------------------------- */
    #if defined(__AVR32__)
        #define MSE_UINT16_HOST_TO_LE(x) __builtin_bswap_16(x)
        #define MSE_UINT16_LE_TO_HOST(x) __builtin_bswap_16(x)
        #define MSE_UINT32_HOST_TO_LE(x) __builtin_bswap_32(x)
        #define MSE_UINT16_HOST_TO_BE(x) (x)
        #define MSE_UINT16_BE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_BE(x) (x)
        #define MSE_UINT32_BE_TO_HOST(x) (x)
        #define MSE_UINT64_HOST_TO_BE(x) (x)
        #define MSE_UINT64_BE_TO_HOST(x) (x)
        #define MSE_NO_PRAGMA_PACK
    #elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define MSE_UINT16_HOST_TO_LE(x) __builtin_bswap16(x)
        #define MSE_UINT16_LE_TO_HOST(x) __builtin_bswap16(x)
        #define MSE_UINT16_HOST_TO_BE(x) (x)
        #define MSE_UINT16_BE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_LE(x) __builtin_bswap32(x)
        #define MSE_UINT32_HOST_TO_BE(x) (x)
        #define MSE_UINT32_BE_TO_HOST(x) (x)
        #define MSE_UINT64_HOST_TO_BE(x) (x)
        #define MSE_UINT64_BE_TO_HOST(x) (x)
    #else
        #define MSE_UINT16_HOST_TO_BE(x) __builtin_bswap16(x)
        #define MSE_UINT16_BE_TO_HOST(x) __builtin_bswap16(x)
        #define MSE_UINT16_HOST_TO_LE(x) (x)
        #define MSE_UINT16_LE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_LE(x) (x)
        #define MSE_UINT32_HOST_TO_BE(x) __builtin_bswap32(x)
        #define MSE_UINT32_BE_TO_HOST(x) __builtin_bswap32(x)
        #define MSE_UINT64_HOST_TO_BE(x) __builtin_bswap64(x)
        #define MSE_UINT64_BE_TO_HOST(x) __builtin_bswap64(x)
    #endif

    #ifdef WIN32
        #define SHARED_LIB_EXPORT __declspec(dllexport)
        #define SHARED_LIB_IMPORT __declspec(dllimport)
    #else
        #define SHARED_LIB_EXPORT
        #define SHARED_LIB_IMPORT extern
    #endif

//#elif defined(__HP_cc) || defined(__HP_aCC)
/* Hewlett-Packard C/aC++. ---------------------------------- */

//#elif defined(__IBMC__) || defined(__IBMCPP__)
/* IBM XL C/C++. -------------------------------------------- */

#elif defined(_MSC_VER)
    /* Microsoft Visual Studio. --------------------------------- */
    // MSVC is usually always little-endian architecture
    #include <stdlib.h>
    #define MSE_UINT16_HOST_TO_BE(x) _byteswap_ushort(x)
    #define MSE_UINT16_BE_TO_HOST(x) _byteswap_ushort(x)
    #define MSE_UINT16_HOST_TO_LE(x) (x)
    #define MSE_UINT16_LE_TO_HOST(x) (x)
    #define MSE_UINT32_HOST_TO_LE(x) (x)
    #define MSE_UINT32_HOST_TO_BE(x) _byteswap_ulong(x)
    #define MSE_UINT32_BE_TO_HOST(x) _byteswap_ulong(x)
    #define MSE_UINT64_HOST_TO_BE(x) _byteswap_uint64(x)
    #define MSE_UINT64_BE_TO_HOST(x) _byteswap_uint64(x)
    #define strtok_r strtok_s

    #define SHARED_LIB_EXPORT __declspec(dllexport)
    #define SHARED_LIB_IMPORT __declspec(dllimport)

//#elif defined(__PGI)
/* Portland Group PGCC/PGCPP. ------------------------------- */

//#elif defined(__SUNPRO_C) || defined(__SUNPRO_CC)
/* Oracle Solaris Studio. ----------------------------------- */

#elif defined __CC_ARM
    /* ARMCC/RealView ------------------------------------------- */
    #ifdef __BIG_ENDIAN
        #define MSE_UINT16_HOST_TO_LE(x) ((x >> 8) | ((x & 0xFF) << 8))
        #define MSE_UINT16_LE_TO_HOST(x) ((x >> 8) | ((x & 0xFF) << 8))
        #define MSE_UINT32_HOST_TO_LE(x) __rev(x)
        #define MSE_UINT32_HOST_TO_BE(x) (x)
        #define MSE_UINT32_BE_TO_HOST(x) (x)
        #define MSE_UINT64_HOST_TO_BE(x) (x)
        #define MSE_UINT64_BE_TO_HOST(x) (x)
    #else
        #define MSE_UINT16_HOST_TO_LE(x) (x)
        #define MSE_UINT16_LE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_LE(x) (x)
        #define MSE_UINT32_HOST_TO_BE(x) __rev(x)
        #define MSE_UINT32_BE_TO_HOST(x) __rev(x)
        #define MSE_UINT64_HOST_TO_BE(x) (((uint64_t)__rev((uint32_t)x) << 32) | (uint64_t)__rev((uint32_t)(x >> 32)))
        #define MSE_UINT64_BE_TO_HOST(x) (((uint64_t)__rev((uint32_t)x) << 32) | (uint64_t)__rev((uint32_t)(x >> 32)))
    #endif

    #define SHARED_LIB_EXPORT
    #define SHARED_LIB_IMPORT extern

#elif defined __ICCARM__
    /* IAR ARM ------------------------------------------- */
    #include <intrinsics.h>
    #if __LITTLE_ENDIAN__ == 0
        #define MSE_UINT16_HOST_TO_LE(x) __REV16(x)
        #define MSE_UINT16_LE_TO_HOST(x) __REV16(x)
        #define MSE_UINT32_HOST_TO_LE(x) __REV(x)
        #define MSE_UINT32_HOST_TO_BE(x) (x)
        #define MSE_UINT32_BE_TO_HOST(x) (x)
        #define MSE_UINT64_HOST_TO_BE(x) (x)
        #define MSE_UINT64_BE_TO_HOST(x) (x)
    #else
        #define MSE_UINT16_HOST_TO_LE(x) (x)
        #define MSE_UINT16_LE_TO_HOST(x) (x)
        #define MSE_UINT32_HOST_TO_LE(x) (x)
        #define MSE_UINT32_HOST_TO_BE(x) __REV(x)
        #define MSE_UINT32_BE_TO_HOST(x) __REV(x)
        #define MSE_UINT64_HOST_TO_BE(x) (((uint64_t)__REV((uint32_t)x) << 32) | (uint64_t)__REV((uint32_t)(x >> 32)))
        #define MSE_UINT64_BE_TO_HOST(x) (((uint64_t)__REV((uint32_t)x) << 32) | (uint64_t)__REV((uint32_t)(x >> 32)))
    #endif

    #define SHARED_LIB_EXPORT
    #define SHARED_LIB_IMPORT extern

#endif

#ifdef MSE_BUILD_SHARED_LIBS
    #if defined(cryptoauth_EXPORTS) && defined(_WIN32)
        #define MSE_DLL SHARED_LIB_EXPORT
    #else
        #define MSE_DLL SHARED_LIB_IMPORT
    #endif
#else
    #undef SHARED_LIB_EXPORT
    #define SHARED_LIB_EXPORT
    #define MSE_DLL extern
#endif

#endif /* MSE_COMPILER_H_ */

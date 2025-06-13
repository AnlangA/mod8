/**
 * \file
 *
 * \brief  ModSemi Crypto Auth device object
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

#ifndef MSE_DEVICE_H
#define MSE_DEVICE_H
/*lint +flb */

#include "mse_iface.h"
/** \defgroup device MSEDevice (mse_)
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MSE_NO_PRAGMA_PACK
#pragma pack(push, 1)
#define MSE_PACKED
#else
#define MSE_PACKED     __attribute__ ((packed))
#endif

typedef struct MSE_PACKED _sha20a_config
{
    uint32_t SN03;
    uint32_t RevNum;
    uint32_t SN47;
    uint8_t  SN8;
    uint8_t  Reserved0;
    uint8_t  I2C_Enable;
    uint8_t  Reserved1;
    uint8_t  I2C_Address;
    uint8_t  Reserved2;
    uint8_t  OTPmode;
    uint8_t  ChipMode;
    uint16_t SlotConfig[16];
    uint16_t Counter[8];
    uint8_t  LastKeyUse[16];
    uint8_t  UserExtra;
    uint8_t  Selector;
    uint8_t  LockValue;
    uint8_t  LockConfig;
} sha20a_config_t;

typedef struct MSE_PACKED _mod8_config
{
    uint32_t SN03;
    uint32_t RevNum;
    uint32_t SN47;
    uint8_t  SN8;
    uint8_t  AES_Enable;
    uint8_t  I2C_Enable;
    uint8_t  Reserved1;
    uint8_t  I2C_Address;
    uint8_t  Reserved2;
    uint8_t  CountMatch;
    uint8_t  ChipMode;
    uint16_t SlotConfig[16];
    uint8_t  Counter0[8];
    uint8_t  Counter1[8];
    uint8_t  UseLock;
    uint8_t  VolatileKeyPermission;
    uint16_t SecureBoot;
    uint8_t  KdflvLoc;
    uint16_t KdflvStr;
    uint8_t  Reserved3[9];
    uint8_t  UserExtra;
    uint8_t  UserExtraAdd;
    uint8_t  LockValue;
    uint8_t  LockConfig;
    uint16_t SlotLocked;
    uint16_t ChipOptions;
    uint32_t X509format;
    uint16_t KeyConfig[16];
} mod8_config_t;

#ifndef MSE_NO_PRAGMA_PACK
#pragma pack(pop)
#endif

/** \brief MSEDeviceState says about device state
 */
typedef enum
{
    MSE_DEVICE_STATE_UNKNOWN = 0,
    MSE_DEVICE_STATE_SLEEP,
    MSE_DEVICE_STATE_IDLE,
    MSE_DEVICE_STATE_ACTIVE
} MSEDeviceState;


/** \brief mse_device is the C object backing MSEDevice.  See the mse_device.h file for
 * details on the MSEDevice methods
 */
struct mse_device
{
    mse_iface_t mIface;                /**< Physical interface */
    uint8_t      device_state;          /**< Device Power State */

    uint8_t  clock_divider;
    uint16_t execution_time_msec;

    uint8_t  session_state;             /**< Secure Session State */
    uint16_t session_counter;           /**< Secure Session Message Count */
    uint16_t session_key_id;            /**< Key ID used for a secure sesison */
    uint8_t* session_key;               /**< Session Key */
    uint8_t  session_key_len;           /**< Length of key used for the session in bytes */

    uint16_t options;                   /**< Nested command details parameter */

};

typedef struct mse_device * MSEDevice;

MSE_STATUS initMSEDevice(MSEIfaceCfg* cfg, MSEDevice cadev);
MSEDevice newMSEDevice(MSEIfaceCfg *cfg);
MSE_STATUS releaseMSEDevice(MSEDevice ca_dev);
void deleteMSEDevice(MSEDevice *ca_dev);

MSEIface ioGetIFace(MSEDevice dev);



#ifdef __cplusplus
}
#endif
#define MSE_AES_ENABLE_EN_SHIFT                (0)
#define MSE_AES_ENABLE_EN_MASK                 (0x01u << MSE_AES_ENABLE_EN_SHIFT)

/* I2C */
#define MSE_I2C_ENABLE_EN_SHIFT                (0)
#define MSE_I2C_ENABLE_EN_MASK                 (0x01u << MSE_I2C_ENABLE_EN_SHIFT)

/* Counter Match Feature */
#define MSE_COUNTER_MATCH_EN_SHIFT             (0)
#define MSE_COUNTER_MATCH_EN_MASK              (0x01u << MSE_COUNTER_MATCH_EN_SHIFT)
#define MSE_COUNTER_MATCH_KEY_SHIFT            (4)
#define MSE_COUNTER_MATCH_KEY_MASK             (0x0Fu << MSE_COUNTER_MATCH_KEY_SHIFT)
#define MSE_COUNTER_MATCH_KEY(v)               (MSE_COUNTER_MATCH_KEY_MASK & (v << MSE_COUNTER_MATCH_KEY_SHIFT))

/* ChipMode */
#define MSE_CHIP_MODE_I2C_EXTRA_SHIFT          (0)
#define MSE_CHIP_MODE_I2C_EXTRA_MASK           (0x01u << MSE_CHIP_MODE_I2C_EXTRA_SHIFT)
#define MSE_CHIP_MODE_TTL_EN_SHIFT             (1)
#define MSE_CHIP_MODE_TTL_EN_MASK              (0x01u << MSE_CHIP_MODE_TTL_EN_SHIFT)
#define MSE_CHIP_MODE_WDG_LONG_SHIFT           (2)
#define MSE_CHIP_MODE_WDG_LONG_MASK            (0x01u << MSE_CHIP_MODE_WDG_LONG_SHIFT)
#define MSE_CHIP_MODE_CLK_DIV_SHIFT            (3)
#define MSE_CHIP_MODE_CLK_DIV_MASK             (0x1Fu << MSE_CHIP_MODE_CLK_DIV_SHIFT)
#define MSE_CHIP_MODE_CLK_DIV(v)               (MSE_CHIP_MODE_CLK_DIV_MASK & (v << MSE_CHIP_MODE_CLK_DIV_SHIFT))

/* General Purpose Slot Config (Not ECC Private Keys) */
#define MSE_SLOT_CONFIG_READKEY_SHIFT          (0)
#define MSE_SLOT_CONFIG_READKEY_MASK           (0x0Fu << MSE_SLOT_CONFIG_READKEY_SHIFT)
#define MSE_SLOT_CONFIG_READKEY(v)             (MSE_SLOT_CONFIG_READKEY_MASK & (v << MSE_SLOT_CONFIG_READKEY_SHIFT))
#define MSE_SLOT_CONFIG_NOMAC_SHIFT            (4)
#define MSE_SLOT_CONFIG_NOMAC_MASK             (0x01u << MSE_SLOT_CONFIG_NOMAC_SHIFT)
#define MSE_SLOT_CONFIG_LIMITED_USE_SHIFT      (5)
#define MSE_SLOT_CONFIG_LIMITED_USE_MASK       (0x01u << MSE_SLOT_CONFIG_LIMITED_USE_SHIFT)
#define MSE_SLOT_CONFIG_ENCRYPTED_READ_SHIFT   (6)
#define MSE_SLOT_CONFIG_ENCRYPTED_READ_MASK    (0x01u << MSE_SLOT_CONFIG_ENCRYPTED_READ_SHIFT)
#define MSE_SLOT_CONFIG_IS_SECRET_SHIFT        (7)
#define MSE_SLOT_CONFIG_IS_SECRET_MASK         (0x01u << MSE_SLOT_CONFIG_IS_SECRET_SHIFT)
#define MSE_SLOT_CONFIG_WRITE_KEY_SHIFT        (8)
#define MSE_SLOT_CONFIG_WRITE_KEY_MASK         (0x0Fu << MSE_SLOT_CONFIG_WRITE_KEY_SHIFT)
#define MSE_SLOT_CONFIG_WRITE_KEY(v)           (MSE_SLOT_CONFIG_WRITE_KEY_MASK & (v << MSE_SLOT_CONFIG_WRITE_KEY_SHIFT))
#define MSE_SLOT_CONFIG_WRITE_CONFIG_SHIFT     (12)
#define MSE_SLOT_CONFIG_WRITE_CONFIG_MASK      (0x0Fu << MSE_SLOT_CONFIG_WRITE_CONFIG_SHIFT)
#define MSE_SLOT_CONFIG_WRITE_CONFIG(v)        (MSE_SLOT_CONFIG_WRITE_CONFIG_MASK & (v << MSE_SLOT_CONFIG_WRITE_CONFIG_SHIFT))

/* Slot Config for ECC Private Keys */
#define MSE_SLOT_CONFIG_EXT_SIG_SHIFT          (0)
#define MSE_SLOT_CONFIG_EXT_SIG_MASK           (0x01u << MSE_SLOT_CONFIG_EXT_SIG_SHIFT)
#define MSE_SLOT_CONFIG_INT_SIG_SHIFT          (1)
#define MSE_SLOT_CONFIG_INT_SIG_MASK           (0x01u << MSE_SLOT_CONFIG_INT_SIG_SHIFT)
#define MSE_SLOT_CONFIG_ECDH_SHIFT             (2)
#define MSE_SLOT_CONFIG_ECDH_MASK              (0x01u << MSE_SLOT_CONFIG_ECDH_SHIFT)
#define MSE_SLOT_CONFIG_WRITE_ECDH_SHIFT       (3)
#define MSE_SLOT_CONFIG_WRITE_ECDH_MASK        (0x01u << MSE_SLOT_CONFIG_WRITE_ECDH_SHIFT)
#define MSE_SLOT_CONFIG_GEN_KEY_SHIFT          (8)
#define MSE_SLOT_CONFIG_GEN_KEY_MASK           (0x01u << MSE_SLOT_CONFIG_GEN_KEY_SHIFT)
#define MSE_SLOT_CONFIG_PRIV_WRITE_SHIFT       (9)
#define MSE_SLOT_CONFIG_PRIV_WRITE_MASK        (0x01u << MSE_SLOT_CONFIG_PRIV_WRITE_SHIFT)

/* Use Lock */
#define MSE_USE_LOCK_ENABLE_SHIFT              (0)
#define MSE_USE_LOCK_ENABLE_MASK               (0x0Fu << MSE_USE_LOCK_ENABLE_SHIFT)
#define MSE_USE_LOCK_KEY_SHIFT                 (4)
#define MSE_USE_LOCK_KEY_MASK                  (0x0Fu << MSE_USE_LOCK_KEY_SHIFT)

/* Voltatile Key Permission */
#define MSE_VOL_KEY_PERM_SLOT_SHIFT            (0)
#define MSE_VOL_KEY_PERM_SLOT_MASK             (0x0Fu << MSE_VOL_KEY_PERM_SLOT_SHIFT)
#define MSE_VOL_KEY_PERM_SLOT(v)               (MSE_VOL_KEY_PERM_SLOT_MASK & (v << MSE_VOL_KEY_PERM_SLOT_SHIFT))
#define MSE_VOL_KEY_PERM_EN_SHIFT              (7)
#define MSE_VOL_KEY_PERM_EN_MASK               (0x01u << MSE_VOL_KEY_PERM_EN_SHIFT)

/* Secure Boot */
#define MSE_SECURE_BOOT_MODE_SHIFT             (0)
#define MSE_SECURE_BOOT_MODE_MASK              (0x03u << MSE_SECURE_BOOT_MODE_SHIFT)
#define MSE_SECURE_BOOT_MODE(v)                (MSE_SECURE_BOOT_MODE_MASK & (v << MSE_SECURE_BOOT_MODE_SHIFT))
#define MSE_SECURE_BOOT_PERSIST_EN_SHIFT       (3)
#define MSE_SECURE_BOOT_PERSIST_EN_MASK        (0x01u << MSE_SECURE_BOOT_PERSIST_EN_SHIFT)
#define MSE_SECURE_BOOT_RAND_NONCE_SHIFT       (4)
#define MSE_SECURE_BOOT_RAND_NONCE_MASK        (0x01u << MSE_SECURE_BOOT_RAND_NONCE_SHIFT)
#define MSE_SECURE_BOOT_DIGEST_SHIFT           (8)
#define MSE_SECURE_BOOT_DIGEST_MASK            (0x0Fu << MSE_SECURE_BOOT_DIGEST_SHIFT)
#define MSE_SECURE_BOOT_DIGEST(v)              (MSE_SECURE_BOOT_DIGEST_MASK & (v << MSE_SECURE_BOOT_DIGEST_SHIFT))
#define MSE_SECURE_BOOT_PUB_KEY_SHIFT          (12)
#define MSE_SECURE_BOOT_PUB_KEY_MASK           (0x0Fu << MSE_SECURE_BOOT_PUB_KEY_SHIFT)
#define MSE_SECURE_BOOT_PUB_KEY(v)             (MSE_SECURE_BOOT_PUB_KEY_MASK & (v << MSE_SECURE_BOOT_PUB_KEY_SHIFT))

/* Slot Locked */
#define MSE_SLOT_LOCKED(v)                     ((0x01 << v) & 0xFFFFu)

/* Chip Options */
#define MSE_CHIP_OPT_POST_EN_SHIFT             (0)
#define MSE_CHIP_OPT_POST_EN_MASK              (0x01u << MSE_CHIP_OPT_POST_EN_SHIFT)
#define MSE_CHIP_OPT_IO_PROT_EN_SHIFT          (1)
#define MSE_CHIP_OPT_IO_PROT_EN_MASK           (0x01u << MSE_CHIP_OPT_IO_PROT_EN_SHIFT)
#define MSE_CHIP_OPT_KDF_AES_EN_SHIFT          (2)
#define MSE_CHIP_OPT_KDF_AES_EN_MASK           (0x01u << MSE_CHIP_OPT_KDF_AES_EN_SHIFT)
#define MSE_CHIP_OPT_ECDH_PROT_SHIFT           (8)
#define MSE_CHIP_OPT_ECDH_PROT_MASK            (0x03u << MSE_CHIP_OPT_ECDH_PROT_SHIFT)
#define MSE_CHIP_OPT_ECDH_PROT(v)              (MSE_CHIP_OPT_ECDH_PROT_MASK & (v << MSE_CHIP_OPT_ECDH_PROT_SHIFT))
#define MSE_CHIP_OPT_KDF_PROT_SHIFT            (10)
#define MSE_CHIP_OPT_KDF_PROT_MASK             (0x03u << MSE_CHIP_OPT_KDF_PROT_SHIFT)
#define MSE_CHIP_OPT_KDF_PROT(v)               (MSE_CHIP_OPT_KDF_PROT_MASK & (v << MSE_CHIP_OPT_KDF_PROT_SHIFT))
#define MSE_CHIP_OPT_IO_PROT_KEY_SHIFT         (12)
#define MSE_CHIP_OPT_IO_PROT_KEY_MASK          (0x0Fu << MSE_CHIP_OPT_IO_PROT_KEY_SHIFT)
#define MSE_CHIP_OPT_IO_PROT_KEY(v)            (MSE_CHIP_OPT_IO_PROT_KEY_MASK & (v << MSE_CHIP_OPT_IO_PROT_KEY_SHIFT))

/* Key Config */
#define MSE_KEY_CONFIG_OFFSET(x)               (96UL + (x) * 2)
#define MSE_KEY_CONFIG_PRIVATE_SHIFT           (0)
#define MSE_KEY_CONFIG_PRIVATE_MASK            (0x01u << MSE_KEY_CONFIG_PRIVATE_SHIFT)
#define MSE_KEY_CONFIG_PUB_INFO_SHIFT          (1)
#define MSE_KEY_CONFIG_PUB_INFO_MASK           (0x01u << MSE_KEY_CONFIG_PUB_INFO_SHIFT)
#define MSE_KEY_CONFIG_KEY_TYPE_SHIFT          (2)
#define MSE_KEY_CONFIG_KEY_TYPE_MASK           (0x07u << MSE_KEY_CONFIG_KEY_TYPE_SHIFT)
#define MSE_KEY_CONFIG_KEY_TYPE(v)             (MSE_KEY_CONFIG_KEY_TYPE_MASK & (v << MSE_KEY_CONFIG_KEY_TYPE_SHIFT))
#define MSE_KEY_CONFIG_LOCKABLE_SHIFT          (5)
#define MSE_KEY_CONFIG_LOCKABLE_MASK           (0x01u << MSE_KEY_CONFIG_LOCKABLE_SHIFT)
#define MSE_KEY_CONFIG_REQ_RANDOM_SHIFT        (6)
#define MSE_KEY_CONFIG_REQ_RANDOM_MASK         (0x01u << MSE_KEY_CONFIG_REQ_RANDOM_SHIFT)
#define MSE_KEY_CONFIG_REQ_AUTH_SHIFT          (7)
#define MSE_KEY_CONFIG_REQ_AUTH_MASK           (0x01u << MSE_KEY_CONFIG_REQ_AUTH_SHIFT)
#define MSE_KEY_CONFIG_AUTH_KEY_SHIFT          (8)
#define MSE_KEY_CONFIG_AUTH_KEY_MASK           (0x0Fu << MSE_KEY_CONFIG_AUTH_KEY_SHIFT)
#define MSE_KEY_CONFIG_AUTH_KEY(v)             (MSE_KEY_CONFIG_AUTH_KEY_MASK & (v << MSE_KEY_CONFIG_AUTH_KEY_SHIFT))
#define MSE_KEY_CONFIG_PERSIST_DISABLE_SHIFT   (12)
#define MSE_KEY_CONFIG_PERSIST_DISABLE_MASK    (0x01u << MSE_KEY_CONFIG_PERSIST_DISABLE_SHIFT)
#define MSE_KEY_CONFIG_RFU_SHIFT               (13)
#define MSE_KEY_CONFIG_RFU_MASK                (0x01u << MSE_KEY_CONFIG_RFU_SHIFT)
#define MSE_KEY_CONFIG_X509_ID_SHIFT           (14)
#define MSE_KEY_CONFIG_X509_ID_MASK            (0x03u << MSE_KEY_CONFIG_X509_ID_SHIFT)
#define MSE_KEY_CONFIG_X509_ID(v)              (MSE_KEY_CONFIG_X509_ID_MASK & (v << MSE_KEY_CONFIG_X509_ID_SHIFT))
/** @} */
/*lint -flb*/
#endif

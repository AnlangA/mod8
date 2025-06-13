
#include "cryptoauthlib.h"
#include "mse_iface.h"
#include "mse_device.h"
#include "ecc_i2c.h"
#include "usart.h"
#include "main.h"
#include "host/mse_host.h"

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
#define LED_Pin LL_GPIO_PIN_15
#define LED_GPIO_Port GPIOB
#define KEY_Pin LL_GPIO_PIN_15
#define KEY_GPIO_Port GPIOA

#define KIT_NAME_HEADER "MOD8 Demo(STM32)"
#define BOARD_APPLICATION_VERSION "1.5.0"
#define STRING_EOL "\r"
#define STRING_HEADER                                                                                                  \
    "\r-- " KIT_NAME_HEADER " --\r\n"                                                                                  \
    "-- Compiled: "__DATE__                                                                                            \
    " "__TIME__                                                                                                        \
    " v" BOARD_APPLICATION_VERSION " --\r\n"                                                                           \
    "-- Console log (115200-8-N-1) --\r\n" STRING_EOL
/* USER CODE END PTD */

MSEIfaceCfg cfg_mod8_i2c = {.iface_type = MSE_I2C_IFACE,
                            .devtype = MOD8,
                            {
                                .i2c.address = 0xC0,
                                .i2c.bus = 0,
                                .i2c.baud = 100000,
                            },
                            .wake_delay = 2500,
                            .rx_retries = 1};

// 测试密钥
const uint8_t io_protection_key[] = {
    0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x6D, 0x6F, 0x64, 0x73,
    0x65, 0x6D, 0x69, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x73, 0x68, 0x6F, 0x77, 0x73, 0x2F, 0x37, 0x2F,
};
const uint8_t secure_boot_public_key[] = {
    0x99, 0x70, 0x8D, 0xE6, 0xA8, 0x98, 0x54, 0x09, 0xA9, 0xA5, 0x7F, 0x45, 0x95, 0xE6, 0x9A, 0xCA,
    0x41, 0xCE, 0xF4, 0xEB, 0xAD, 0xF1, 0xC6, 0x67, 0x30, 0xCC, 0x1A, 0xBA, 0x80, 0x0C, 0x5A, 0x8F,
    0x93, 0xF8, 0x89, 0x51, 0xF1, 0x7E, 0x1D, 0x3D, 0x4D, 0xA0, 0x81, 0x5F, 0x59, 0x38, 0xD8, 0x17,
    0xE3, 0xC6, 0xA0, 0xFC, 0x82, 0x8B, 0x02, 0x6D, 0x6C, 0x60, 0xF0, 0x23, 0x1A, 0x47, 0x1A, 0xBC,
};

/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void)
{
    LL_FLASH_SetLatency(LL_FLASH_LATENCY_1);
    while (LL_FLASH_GetLatency() != LL_FLASH_LATENCY_1)
    {
    }
    LL_RCC_HSE_Enable();

    /* Wait till HSE is ready */
    while (LL_RCC_HSE_IsReady() != 1)
    {
    }
    LL_RCC_LSI_Enable();

    /* Wait till LSI is ready */
    while (LL_RCC_LSI_IsReady() != 1)
    {
    }
    LL_PWR_EnableBkUpAccess();
    if (LL_RCC_GetRTCClockSource() != LL_RCC_RTC_CLKSOURCE_LSI)
    {
        LL_RCC_ForceBackupDomainReset();
        LL_RCC_ReleaseBackupDomainReset();
        LL_RCC_SetRTCClockSource(LL_RCC_RTC_CLKSOURCE_LSI);
    }
    LL_RCC_EnableRTC();
    LL_RCC_PLL_ConfigDomain_SYS(LL_RCC_PLLSOURCE_HSE_DIV_1, LL_RCC_PLL_MUL_5);
    LL_RCC_PLL_Enable();

    /* Wait till PLL is ready */
    while (LL_RCC_PLL_IsReady() != 1)
    {
    }
    LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);
    LL_RCC_SetAPB1Prescaler(
        LL_RCC_APB1_DIV_2); // FPCLK1应当是10 MHz的整数倍，这样可以正确地产生400KHz的快速时钟。36MHz max
    LL_RCC_SetAPB2Prescaler(LL_RCC_APB2_DIV_1);
    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_PLL);

    /* Wait till System clock is ready */
    while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_PLL)
    {
    }
    LL_SetSystemCoreClock(40000000);

    /* Update the time base */
    if (HAL_InitTick(TICK_INT_PRIORITY) != HAL_OK)
    {
        Error_Handler();
    }
    LL_RCC_SetUSBClockSource(LL_RCC_USB_CLKSOURCE_PLL);
}

/** Configure pins as
 * Analog
 * Input
 * Output
 * EVENT_OUT
 * EXTI
 */
void MX_GPIO_Init(void)
{

    LL_GPIO_InitTypeDef GPIO_InitStruct = {0};

    /* GPIO Ports Clock Enable */
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_GPIOC);
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_GPIOD);
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_GPIOA);
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_GPIOB);

    /**/
    LL_GPIO_SetOutputPin(LED_GPIO_Port, LED_Pin);

    /**/
    GPIO_InitStruct.Pin = LED_Pin;
    GPIO_InitStruct.Mode = LL_GPIO_MODE_OUTPUT;
    GPIO_InitStruct.Speed = LL_GPIO_SPEED_FREQ_MEDIUM;
    GPIO_InitStruct.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    LL_GPIO_Init(LED_GPIO_Port, &GPIO_InitStruct);

    /**/
    GPIO_InitStruct.Pin = KEY_Pin;
    GPIO_InitStruct.Mode = LL_GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = LL_GPIO_PULL_UP;
    LL_GPIO_Init(KEY_GPIO_Port, &GPIO_InitStruct);
}

/**
 * @brief  写入配置数据
 * @note   配置区锁定仅能执行一次，不可逆；执行各种应用前必须先锁定配置区；一般在产品出厂前完成。
 * @retval
 */
MSE_STATUS app_load_configuration(void)
{
    MSE_STATUS status;
    bool is_locked = false;
    const uint8_t mod8_configdata[MSE_ECC_CONFIG_SIZE] = {
        0x01, 0x23, 0xFF, 0xFF, 0x00, 0x00, 0x60, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xEE, 0x01, 0x01, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x85, 0x00, 0x82, 0x00, 0x85, 0x20, 0x85, 0x20, 0x85, 0x20, 0x8F, 0x46,
        0x8F, 0x0F, 0x8F, 0x9F, 0x0F, 0x0F, 0x8F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
        0x0D, 0x1F, 0x8F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xF7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0xFF, 0xFF, 0x0E, 0x60, 0x00, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x53, 0x00, 0x73, 0x00, 0x73, 0x00, 0x73, 0x00, 0x38, 0x00, 0x7C, 0x00, 0x1C, 0x00,
        0x3C, 0x00, 0x1A, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x12, 0x00, 0x30, 0x00,
    };
    uint8_t config[200] = {0x00};
    uint8_t i = 0;
    do
    {
        /* 检查配置区当前锁定状态  */
        if ((status = mse_is_locked(LOCK_ZONE_CONFIG, &is_locked)) != MSE_SUCCESS)
        {
            printf(" mse_is_locked failed with %02x \r\n", status);
            break;
        }
        /*Write configuration if it is not already locked */
        if (!is_locked)
        {
            /*Trigger Configuration write... ignore first 16 bytes*/
            if ((status = mse_write_bytes_zone(MSE_ZONE_CONFIG, 0, 16, &mod8_configdata[16],
                                               (sizeof(mod8_configdata) - 16))) != MSE_SUCCESS)
            {
                printf(" Write configuration failed with %02x \r\n", status);
                break;
            }
            /*Lock Configuration Zone on completing configuration*/
            if ((status = mse_lock(LOCK_ZONE_NO_CRC | LOCK_ZONE_CONFIG, 0)) != MSE_SUCCESS)
            {
                printf(" Lock Configuration Zone failed with %02x \r\n", status);
                break;
            }
        }
        /*Read Configuration Zone on completing configuration*/
        status = mse_read_config_zone(config);
        if (status != MSE_SUCCESS)
        {
            printf(" mse_read_config_zone() failed: %02x\r\n", status);
            break;
        }
        printf(" [1] Configuration Zone: \r\n");
        for (i = 0; i < MSE_ECC_CONFIG_SIZE; i++)
        {
            if (i % 16 == 0)
            {
                printf("\r\n");
            }
            else if (i % 8 == 0)
            {
                printf("  ");
            }
            else
            {
                printf(" ");
            }
            printf("%02X", (int)config[i]);
        }
        printf("\r\n");
    } while (0);
    return status;
}

/**
 * @brief  写入各应用密钥
 * @note
 * 数据（密钥）区锁定仅能执行一次，不可逆；执行各种应用前必须先锁定数据区；一般在产品出厂前完成；部分密钥可单独锁定，锁定操作不可逆。
 * @retval
 */
MSE_STATUS app_write_key(void)
{
    MSE_STATUS status;
    bool is_locked = false;
    uint16_t io_protection_key_id = 0x0006; // 对应io_protection_key
    uint16_t secure_boot_public_key_id;
    do
    {
        /*Check current status of Public Key Slot lock status */
        if ((status = mse_read_bytes_zone(MSE_ZONE_CONFIG, 0, SECUREBOOTCONFIG_OFFSET + 1,
                                          (uint8_t *)(&secure_boot_public_key_id),
                                          sizeof(secure_boot_public_key_id))) != MSE_SUCCESS)
        {
            printf(" failed ! mse_read_zone returned %02x \r\n", status);
            break;
        }
        secure_boot_public_key_id = (secure_boot_public_key_id & 0x00F0) >> 4;
        // printf(" sboot_public_key_slot: %02x \r\n", secure_boot_public_key_id);

        /* 如果要写入的slot已经单独锁定，则无法再次写入 */
        if ((status = mse_is_slot_locked(io_protection_key_id, &is_locked)) != MSE_SUCCESS)
        {
            printf(" failed ! mse_is_slot_locked 1 returned %02x \r\n", status);
            break;
        }
        if (is_locked)
        {
            printf(" io protection key is locked \r\n");
            status = MSE_SUCCESS;
            break;
        }

        is_locked = false;
        if ((status = mse_is_slot_locked(secure_boot_public_key_id, &is_locked)) != MSE_SUCCESS)
        {
            printf(" failed ! mse_is_slot_locked 2 returned %02x \r\n", status);
            break;
        }

        if (is_locked)
        {
            printf(" secure boot public key is locked \r\n");
            status = MSE_SUCCESS;
            break;
        }

        is_locked = false;
        /* Check current status of Data zone lock status  */
        if ((status = mse_is_locked(LOCK_ZONE_DATA, &is_locked)) != MSE_SUCCESS)
        {
            printf(" mse_is_locked failed with %02x \r\n", status);
            break;
        }

        /*Write Data if it is not already locked */
        if (!is_locked)
        {
            /*Write Key*/
            // Slot 6 对应io_protection_key
            status = mse_write_zone(MSE_ZONE_DATA, io_protection_key_id, 0, 0, io_protection_key, 32);
            if (status != MSE_SUCCESS)
            {
                printf(" Write Slot %0d failed with ret=0x%08X \r\n", io_protection_key_id, status);
                break;
            }

            // Slot 15 对应 secure_boot_public_key
            // Write public key to slot
            status = mse_write_pubkey(secure_boot_public_key_id, secure_boot_public_key);
            if (status != MSE_SUCCESS)
            {
                printf(" Write Slot %0d failed with ret=0x%08X \r\n", secure_boot_public_key_id, status);
                break;
            }

            /*Lock Data Zone if it is not*/
            if ((status = mse_lock(LOCK_ZONE_NO_CRC | LOCK_ZONE_DATA, 0)) != MSE_SUCCESS)
            {
                printf(" Lock Data Zone failed with %02x \r\n", status);
                break;
            }
            /* 以下单独永久锁定密钥slot的操作可在正式发行版本中执行，在原型开发阶段可不执行，操作不可逆。 */
            /*Lock slot 15 */
            // if ((status = mse_lock_data_slot(secure_boot_public_key_id)) != MSE_SUCCESS)
            // {
            //     printf(" failed ! 2 mse_lock_data_slot returned %02x \r\n", status);
            //     break;
            // }
            /*Lock slot 6 */
            // if ((status = mse_lock_data_slot(io_protection_key_id)) != MSE_SUCCESS)
            // {
            //     printf(" failed ! 2 mse_lock_data_slot returned %02x \r\n", status);
            //     break;
            // }
            printf(" [2] Write Key Success\r\n");
            break;
        }
        else
        {
            printf(" [2] Data Zone is locked\r\n");
            status = MSE_SUCCESS;
            break;
        }

    } while (0);
    return status;
}

/**
 * @brief  ECC签名、验签
 * @note
 * @retval
 */
MSE_STATUS app_sign_verify(void)
{
    MSE_STATUS status;
    bool is_verified = false;
    bool is_locked = false;
    uint16_t private_key_id = 2;
    uint16_t public_key_id = 13;
    uint8_t digest[MSE_SHA256_DIGEST_SIZE]; // 消息摘要数据，如果用MOD8来计算消息的摘要可调用mse_sha接口
    uint8_t signature[MSE_ECCP256_SIG_SIZE];
    uint8_t public_key[MSE_ECCP256_PUBKEY_SIZE];
    uint8_t i = 0;
    do
    {
        /* Check current status of Data zone lock status  */
        if ((status = mse_is_locked(LOCK_ZONE_DATA, &is_locked)) != MSE_SUCCESS)
        {
            printf(" mse_is_locked failed with %02x \r\n", status);
            break;
        }
        if (!is_locked)
        {
            printf(" Data Zone need locked \r\n");
            status = MSE_NOT_LOCKED;
            break;
        }
        // Generate new key pair(MOD8内部随机生成密钥对，用于演示，私钥存在slot2中，不可读)
        status = mse_genkey(private_key_id, public_key);
        if (status != MSE_SUCCESS)
        {
            printf(" Generate key pair failed with ret=0x%08X \r\n", status);
            break;
        }

        // Write public key to slot
        status = mse_write_pubkey(public_key_id, public_key);
        if (status != MSE_SUCCESS)
        {
            printf(" Write public key failed with ret=0x%08X \r\n", status);
            break;
        }

        // Generate random digest to be signed
        /* 正常情况下使用SHA256等算法计算要签名消息的摘要(digest)，此处为了演示直接使用安全芯片产生的随机数当摘要数据 */
        status = mse_random(digest);
        if (status != MSE_SUCCESS)
        {
            printf(" Generate random message failed with ret=0x%08X \r\n", status);
            break;
        }

        // Sign the digest
        status = mse_sign(private_key_id, digest, signature);
        if (status != MSE_SUCCESS)
        {
            printf(" Sign failed with ret=0x%08X \r\n", status);
            break;
        }

        // Verify the signature
        is_verified = false;
        status = mse_verify_stored(digest, signature, public_key_id, &is_verified);
        if (status != MSE_SUCCESS)
        {
            printf(" Verify failed with ret=0x%08X \r\n", status);
            break;
        }
        if (is_verified)
        {
            printf(" [3] Verify Success\r\n");
            status = MSE_SUCCESS;
            printf(" Public key: \n");
            for (i = 0; i < sizeof(public_key); i++)
            {
                if (i % 16 == 0)
                {
                    printf("\r\n");
                }
                else if (i % 8 == 0)
                {
                    printf("  ");
                }
                else
                {
                    printf(" ");
                }
                printf("%02X", (int)public_key[i]);
            }
            printf("\r\n");
            printf(" Message's digest: \n");
            for (i = 0; i < sizeof(digest); i++)
            {
                if (i % 16 == 0)
                {
                    printf("\r\n");
                }
                else if (i % 8 == 0)
                {
                    printf("  ");
                }
                else
                {
                    printf(" ");
                }
                printf("%02X", (int)digest[i]);
            }
            printf("\r\n");
            printf(" Signature: \n");
            for (i = 0; i < sizeof(signature); i++)
            {
                if (i % 16 == 0)
                {
                    printf("\r\n");
                }
                else if (i % 8 == 0)
                {
                    printf("  ");
                }
                else
                {
                    printf(" ");
                }
                printf("%02X", (int)signature[i]);
            }
            printf("\r\n");
            break;
        }
        else
        {
            printf(" Verify failed \r\n");
            break;
        }
    } while (0);
    return status;
}

/**
 * @brief  HMAC 和 SHA256应用
 * @note
 * @retval
 */
MSE_STATUS app_hmac(void)
{
    MSE_STATUS status;
    bool is_locked = false;
    uint8_t data_input[] = {
        0x71, 0x88, 0x2B, 0x71, 0x0C, 0xB4, 0x8E, 0x00, 0x9D, 0x55, 0x2F, 0x17, 0xBD, 0xBB, 0xB2, 0xF3,
        0xEF, 0xB9, 0x23, 0x29, 0xE7, 0xDE, 0xF6, 0x74, 0xDE, 0x70, 0x51, 0x4D, 0x58, 0xF7, 0x2D, 0xAC,
        0x48, 0x5B, 0xA5, 0xD1, 0x8C, 0x95, 0x44, 0x00, 0x71, 0x14, 0xA8, 0x4B, 0x01, 0xED, 0x56, 0xE4,
        0x3A, 0x7A, 0xD2, 0x01, 0xB6, 0xDB, 0x8A, 0xC5, 0x0E, 0x4B, 0x31, 0x3A, 0xB9, 0xB6, 0x8D, 0xDB,
    };
    const uint8_t hmac_ref[MSE_SHA256_DIGEST_SIZE] = {
        0x38, 0x37, 0x2D, 0xDC, 0xF8, 0x80, 0x62, 0xEF, 0x1D, 0xA1, 0x1F, 0x88, 0x58, 0xDC, 0x1E, 0xB7,
        0x44, 0x9D, 0x50, 0xA0, 0x99, 0x05, 0x40, 0x32, 0xFA, 0xE9, 0xE2, 0x4E, 0xC7, 0x4E, 0x80, 0xC2,
    };
    uint16_t key_id = 0x0006; // 对应io_protection_key
    uint8_t hmac[MSE_SHA256_DIGEST_SIZE];
    // sha256
    uint8_t message[32];
    uint8_t digest[MSE_SHA256_DIGEST_SIZE];
    uint8_t i = 0;
    uint8_t hmac_digest_host[32];
    do
    {
        /* Check current status of Data zone lock status  */
        if ((status = mse_is_locked(LOCK_ZONE_DATA, &is_locked)) != MSE_SUCCESS)
        {
            printf(" mse_is_locked failed with %02x \r\n", status);
            break;
        }
        if (!is_locked)
        {
            printf(" Data Zone need locked \r\n");
            status = MSE_NOT_LOCKED;
            break;
        }
        // Calculating HMAC using the key in slot6
        memset(hmac, 0x00, sizeof(hmac));
        status = mse_sha_hmac(data_input, sizeof(data_input), key_id, hmac, SHA_MODE_TARGET_TEMPKEY);
        if (status != MSE_SUCCESS)
        {
            printf(" mse_sha_hmac failed with ret=0x%08X \r\n", status);
            break;
        }

        // Calculating HMAC-SHA2 in the Host (注意 Host启用本地软HMAC会增大RAM使用空间)
        memset(hmac_digest_host, 0x00, sizeof(hmac_digest_host));
        status = mcac_sw_sha256_hmac(data_input, sizeof(data_input), io_protection_key, 32, hmac_digest_host);
        if (status != MSE_SUCCESS)
        {
            printf(" mseh_hmac failed with ret=0x%08X \r\n", status);
            break;
        }

        // Compare
        if (memcmp(hmac_ref, hmac, MSE_SHA256_DIGEST_SIZE))
        {
            printf(" HMAC Compare failed \r\n");
            break;
        }
        else
        {
            printf(" [4-1] HMAC Success\r\n");
            printf(" Key: \n");
            for (i = 0; i < sizeof(io_protection_key); i++)
            {
                if (i % 16 == 0)
                {
                    printf("\r\n");
                }
                else if (i % 8 == 0)
                {
                    printf("  ");
                }
                else
                {
                    printf(" ");
                }
                printf("%02X", (int)io_protection_key[i]);
            }
            printf("\r\n");
            printf(" HMAC digest: \n");
            for (i = 0; i < sizeof(hmac); i++)
            {
                if (i % 16 == 0)
                {
                    printf("\r\n");
                }
                else if (i % 8 == 0)
                {
                    printf("  ");
                }
                else
                {
                    printf(" ");
                }
                printf("%02X", (int)hmac[i]);
            }
            printf("\r\n");
        }

        // sha256 API(message长度可变，此处利用32字节随机数进行演示)
        status = mse_random(message);
        if (status != MSE_SUCCESS)
        {
            printf(" mse_random failed with ret=0x%08X\r\n", status);
            break;
        }
        status = mse_sha(sizeof(message), message, digest);
        if (status != MSE_SUCCESS)
        {
            printf(" mse_sha failed with ret=0x%08X\r\n", status);
            break;
        }
        printf(" [4-2] SHA Success\r\n");
        status = MSE_SUCCESS;
        printf(" Message: \n");
        for (i = 0; i < sizeof(message); i++)
        {
            if (i % 16 == 0)
            {
                printf("\r\n");
            }
            else if (i % 8 == 0)
            {
                printf("  ");
            }
            else
            {
                printf(" ");
            }
            printf("%02X", (int)message[i]);
        }
        printf("\r\n");
        printf(" Digest: \n");
        for (i = 0; i < sizeof(digest); i++)
        {
            if (i % 16 == 0)
            {
                printf("\r\n");
            }
            else if (i % 8 == 0)
            {
                printf("  ");
            }
            else
            {
                printf(" ");
            }
            printf("%02X", (int)digest[i]);
        }
        printf("\r\n");
    } while (0);
    return status;
}

/**
 * @brief  Secure boot应用
 * @note
 * @retval
 */
MSE_STATUS app_secureboot(void)
{
    MSE_STATUS status;
    bool is_locked = false;
    bool is_verified = false;
    uint16_t secure_boot_config;
    uint8_t buf[2];
    uint8_t randomnum[RANDOM_RSP_SIZE];
    uint8_t digest[] = {
        0xA4, 0xF5, 0x37, 0x97, 0x0F, 0x74, 0x78, 0xBA, 0x10, 0x5A, 0x1C, 0x3A, 0x91, 0xBA, 0x43, 0x60,
        0x91, 0xAA, 0x7D, 0xB9, 0xAE, 0xD0, 0x9F, 0x01, 0x01, 0xAD, 0x21, 0x5D, 0x38, 0xE3, 0xFE, 0x8A,
    };
    uint8_t signature[] = {
        0x5D, 0x9E, 0xCB, 0x1A, 0x4F, 0x4B, 0x03, 0xC3, 0x02, 0x7F, 0xE2, 0x3E, 0x52, 0x0A, 0x73, 0xEB,
        0x82, 0xBB, 0x73, 0xD0, 0x8D, 0x14, 0x10, 0x01, 0x0D, 0x77, 0xD8, 0x03, 0xD9, 0xEE, 0xDA, 0x48,
        0xF3, 0xF9, 0x64, 0x2C, 0x1D, 0xCD, 0x40, 0x73, 0x17, 0x72, 0xB4, 0x79, 0x8E, 0x49, 0x93, 0x4E,
        0x99, 0xE9, 0x00, 0x74, 0x9C, 0x32, 0x73, 0x4F, 0x88, 0xD1, 0x57, 0x86, 0x2F, 0x6D, 0x28, 0xD1,
    };
    /* Secure Boot Process:
     * 0. 需要先创建一个 P256 NIST ECC 固件签名密钥(授权私钥)。
     *    授权私钥将由OEM持有，用于对固件映像进行签名。需要将认证公钥写入secure boot公钥槽并锁定该槽以使其成为永久公钥。
     * 1. 在OEM端，使用SHA256算法创建image文件的摘要(digest)，使用授权私钥对摘要创建签名(signature)。
     * 2. image和签名都存在Flash中。
     * 3. 系统启动时，boot使用相同的SHA256算法计算运行image的摘要，从Flash中读取签名。
     * 4. boot将摘要和签名送给安全芯片。
     * 5. 安全芯片使用出厂前写入的认证公钥对签名进行验签，安全芯片将验签结果传回boot。
     * 6. 如果验证失败，boot可能会提示用户下载新的、真实的image，并返回错误提示。*/
    do
    {
        /* Before doing secure boot it is expected configuration zone is locked  */
        if ((status = mse_is_locked(LOCK_ZONE_CONFIG, &is_locked)) != MSE_SUCCESS)
        {
            printf(" mse_is_locked failed with %02x \r\n", status);
            break;
        }
        if (!is_locked)
        {
            printf(" Configuration Zone need locked \r\n");
            status = MSE_NOT_LOCKED;
            break;
        }

        /* Read Configuration data & verify device configuration settings */
        if ((status = mse_read_bytes_zone(MSE_ZONE_CONFIG, 0, SECUREBOOTCONFIG_OFFSET, buf, 2)) != MSE_SUCCESS)
        {
            printf(" mse_read_bytes_zone failed with %02x \r\n", status);
            break;
        }
        secure_boot_config = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);

        /* Return error status if configuration and device settings doesn't match */
        if ((secure_boot_config & SECUREBOOTCONFIG_MODE_MASK) != 3)
        {
            return MSE_GEN_FAIL;
        }

        /* host产生随机数用于线路保护，这里临时由安全芯片产生，实际应用时必需由host自己产生，且保证每次IO传输数据都不一样
         */
        status = mse_random(randomnum);
        if (status != MSE_SUCCESS)
        {
            printf(" Generate random message failed with ret=0x%08X \r\n", status);
            break;
        }

        /* Verify the secure boot mode full */
        status =
            mse_secureboot_mac(SECUREBOOT_MODE_FULL, digest, signature, randomnum, io_protection_key, &is_verified);
        if (status != MSE_SUCCESS)
        {
            printf(" mse_secureboot failed with 0x%02X \r\n", status);
            break;
        }
        if (!is_verified)
        {
            printf(" Secure boot Verify failed \r\n");
            status = MSE_CHECKMAC_VERIFY_FAILED;
            break;
        }
        printf(" [5] Secure boot success\r\n");
        status = MSE_SUCCESS;
    } while (0);
    return status;
}

// 大小端判断
void IsBigEndian(void)
{
    union temp
    {
        short int a;
        char b;
    } temp;

    temp.a = 0x1234;
    if (temp.b == 0x12) //低字节存的是数据的高字节数据
    {
        //大端模式
        printf("CPU: Big-Endian\r\n");
    }
    else
    {
        //小端模式
        printf("CPU: Little-Endian\r\n");
    }
}

int main(void)
{
    MSE_STATUS status;
    /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
    HAL_Init();

    /* Configure the system clock */
    SystemClock_Config();

    /* Initialize all configured peripherals */
    MX_GPIO_Init();

    /* Demo工程中创建了两个Target，里面分别定义了I2C_HAL和I2C_EMUL，分别表示硬件I2C和软件模拟I2C */
#ifdef I2C_HAL
    MX_I2C1_Init();
#endif

    MX_USART1_UART_Init();
    /* USER CODE BEGIN 2 */
    // 串口输出log：UART-TX
    printf("%s\n", STRING_HEADER);

    /* 大小端判断：注意不同CPU大小端可能不一样，部分主设备端验证用的API可能会计算错误 */
    IsBigEndian();

    /* USER CODE END 2 */

    /* [0] init: I2C通信连接、测试（使用MOD8最关键的一步，I2C驱动移植请参考ecc_i2c.c） */
    status = mse_init(&cfg_mod8_i2c);
    if (status != MSE_SUCCESS)
    {
        printf(" mse_init() failed with ret=0x%08X \r\n", status);
        goto exit;
    }

    printf(" init OK.\r\n");

    /* [1] Load configuration:加载配置并锁定配置区（仅执行一次，注意：锁定后无法解锁） */
    // status = app_load_configuration();
    // if (status != MSE_SUCCESS)
    // {
    //     printf(" APP - Load configuration failed \r\n");
    //     goto exit;
    // }
    // printf(" Load configuration OK.\r\n");

    /* [2] Write Slot Data:生成密钥、写入密钥及应用配套数据，锁定数据区（锁定后无法解锁），前置条件：[1] */
    // status = app_write_key();
    // if (status != MSE_SUCCESS)
    // {
    //     printf(" APP - Write key failed\r\n");
    //     goto exit;
    // }
    // printf(" Write key OK.\r\n");

    /* [3] Sign_Verify: 签名、验签、加解密等应用，前置条件[2] */
    // status = app_sign_verify();
    // if (status != MSE_SUCCESS)
    // {
    //     printf(" APP - Sign_Verify failed\r\n");
    //     goto exit;
    // }
    // printf(" Sign_Verify OK.\r\n");

    /* [4] HMAC: 前置条件[2] */
    // status = app_hmac();
    // if (status != MSE_SUCCESS)
    // {
    //     printf(" APP - HMAC failed\r\n");
    //     goto exit;
    // }
    // printf(" HMAC OK.\r\n");

    /* [5] Secure boot:前置条件[2] */
    // status = app_secureboot();
    // if (status != MSE_SUCCESS)
    // {
    //     printf(" APP - Secure boot failed\r\n");
    //     goto exit;
    // }
    // printf(" Secure boot OK.\r\n");

exit:
    LL_GPIO_TogglePin(LED_GPIO_Port, LED_Pin);
    while (1)
    {
    }
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void)
{
    /* USER CODE BEGIN Error_Handler_Debug */
    /* User can add his own implementation to report the HAL error return state */
    __disable_irq();
    while (1)
    {
    }
    /* USER CODE END Error_Handler_Debug */
}

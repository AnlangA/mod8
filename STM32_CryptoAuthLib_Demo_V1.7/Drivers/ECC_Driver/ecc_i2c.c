/**
 * \file
 * \brief Hardware abstraction layer for STM32 driver.
 *
 *
 * Prerequisite:
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
#include <string.h>
#include <stdio.h>

/* Includes ------------------------------------------------------------------*/
#include "stm32f1xx_hal.h"
#include "mse_hal.h"
#include "main.h"

#ifdef I2C_HAL	// 使用HAL 硬件I2C

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define RX_TIMEOUT_TICKS 400

/* USER CODE BEGIN 1 */

I2C_HandleTypeDef hi2c1;
I2C_HandleTypeDef hi2c2;

#define KIT_I2C hi2c1

#define MAIN_PROCESSOR_RD_CMD                      0x10
#define MAIN_PROCESSOR_RD_CSR                      0x30
#define FAST_CRYPTO_RD_FSR                         0xB0
#define FAST_CRYPTO_RD_FAST_FIRST                  0x90
#define FAST_CRYPTO_RD_FAST_ADDL                   0xD0
#define CMD_MAX_RSP_SIZE                           192



/* I2C1 init function */
void MX_I2C1_Init(void)
{

    /* USER CODE BEGIN I2C1_Init 0 */

    /* USER CODE END I2C1_Init 0 */

    /* USER CODE BEGIN I2C1_Init 1 */

    /* USER CODE END I2C1_Init 1 */
    hi2c1.Instance = I2C1;
    hi2c1.Init.ClockSpeed = 100000;
    hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_16_9;
    hi2c1.Init.OwnAddress1 = 0;
    hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
    hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
    hi2c1.Init.OwnAddress2 = 0;
    hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
    hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
    if (HAL_I2C_Init(&hi2c1) != HAL_OK)
    {
        Error_Handler();
    }
    /* USER CODE BEGIN I2C1_Init 2 */

    /* USER CODE END I2C1_Init 2 */
}


void HAL_I2C_MspInit(I2C_HandleTypeDef *i2cHandle)
{

    GPIO_InitTypeDef GPIO_InitStruct = {0};
    if (i2cHandle->Instance == I2C1)
    {
        /* USER CODE BEGIN I2C1_MspInit 0 */

        /* USER CODE END I2C1_MspInit 0 */

        __HAL_RCC_GPIOB_CLK_ENABLE();
        /**I2C1 GPIO Configuration
        PB6     ------> I2C1_SCL
        PB7     ------> I2C1_SDA
        */
        GPIO_InitStruct.Pin = GPIO_PIN_6 | GPIO_PIN_7;
        GPIO_InitStruct.Mode = GPIO_MODE_AF_OD;
        GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
        HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

        /* I2C1 clock enable */
        __HAL_RCC_I2C1_CLK_ENABLE();
        /* USER CODE BEGIN I2C1_MspInit 1 */

        /* USER CODE END I2C1_MspInit 1 */
    }
    else if (i2cHandle->Instance == I2C2)
    {
        /* USER CODE BEGIN I2C2_MspInit 0 */

        /* USER CODE END I2C2_MspInit 0 */

        __HAL_RCC_GPIOB_CLK_ENABLE();
        /**I2C2 GPIO Configuration
        PB10     ------> I2C2_SCL
        PB11     ------> I2C2_SDA
        */

        GPIO_InitStruct.Pin = GPIO_PIN_10 | GPIO_PIN_11;
        GPIO_InitStruct.Mode = GPIO_MODE_AF_OD;
        GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
        HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

        //		GPIO_InitStruct.Pin = GPIO_PIN_10;
        //    GPIO_InitStruct.Mode = GPIO_MODE_AF_OD;
        //    GPIO_InitStruct.Pull = GPIO_PULLUP; // GPIO_NOPULL;
        //    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
        //    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

        //    GPIO_InitStruct.Pin = GPIO_PIN_11;
        //    GPIO_InitStruct.Mode = GPIO_MODE_AF_OD;
        //    GPIO_InitStruct.Pull = GPIO_PULLUP;
        //    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
        //    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

        /* I2C2 clock enable */
        __HAL_RCC_I2C2_CLK_ENABLE();
        /* USER CODE BEGIN I2C2_MspInit 1 */

        /* USER CODE END I2C2_MspInit 1 */
    }
}

void HAL_I2C_MspDeInit(I2C_HandleTypeDef *i2cHandle)
{

    if (i2cHandle->Instance == I2C1)
    {
        /* USER CODE BEGIN I2C1_MspDeInit 0 */

        /* USER CODE END I2C1_MspDeInit 0 */
        /* Peripheral clock disable */
        __HAL_RCC_I2C1_CLK_DISABLE();

        /**I2C1 GPIO Configuration
        PB6     ------> I2C1_SCL
        PB7     ------> I2C1_SDA
        */
        HAL_GPIO_DeInit(GPIOB, GPIO_PIN_6);

        HAL_GPIO_DeInit(GPIOB, GPIO_PIN_7);

        /* USER CODE BEGIN I2C1_MspDeInit 1 */

        /* USER CODE END I2C1_MspDeInit 1 */
    }
    else if (i2cHandle->Instance == I2C2)
    {
        /* USER CODE BEGIN I2C2_MspDeInit 0 */

        /* USER CODE END I2C2_MspDeInit 0 */
        /* Peripheral clock disable */
        __HAL_RCC_I2C2_CLK_DISABLE();

        /**I2C2 GPIO Configuration
        PB10     ------> I2C2_SCL
        PB11     ------> I2C2_SDA
        */
        HAL_GPIO_DeInit(GPIOB, GPIO_PIN_10);

        HAL_GPIO_DeInit(GPIOB, GPIO_PIN_11);

        /* USER CODE BEGIN I2C2_MspDeInit 1 */

        /* USER CODE END I2C2_MspDeInit 1 */
    }
}

/* USER CODE END 1 */

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

/** \brief
    - this HAL implementation assumes you've included the START Twi libraries in your project, otherwise,
    the HAL layer will not compile because the START TWI drivers are a dependency *
 */

/** \brief hal_i2c_init manages requests to initialize a physical interface.  it manages use counts so when an interface
 * has released the physical layer, it will disable the interface for some other use.
 * You can have multiple MSEIFace instances using the same bus, and you can have multiple MSEIFace instances on
 * multiple i2c buses, so hal_i2c_init manages these things and MSEIFace is abstracted from the physical details.
 */

/** \brief initialize an I2C interface using given config
 * \return None
 */
MSE_STATUS hal_i2c_init(MSEIface iface, MSEIfaceCfg *cfg)
{
    // do nothing
    return MSE_SUCCESS;
}


/** \brief method to change the bus speed of I2C
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */
MSE_STATUS change_i2c_speed(MSEIface iface, uint32_t speed)
{
    /* Make sure I2C is not busy before changing the I2C clock speed */
    while (HAL_I2C_GetState(&KIT_I2C) != HAL_I2C_STATE_READY)
    {
        printf("Waiting to change the I2C clock speek...\r\n");
        mse_delay_ms(2);
    }
    KIT_I2C.Init.ClockSpeed = speed;
    if (HAL_I2C_Init(&KIT_I2C) != HAL_OK)
    {
        Error_Handler();
    }
    return MSE_SUCCESS;
}

/** \brief send wake up token to CryptoAuth device
 * \param[in] device_addr   device I2C address
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_wake(MSEIface iface)
{
    // int retries = 20;
    // uint32_t bdrt = 400000;
    uint8_t data[4];

    data[0] = 0x00;

    // if (bdrt != 100000)   // if not already at 100KHz, change it
    // {
    change_i2c_speed(iface,100000);
    // }

    HAL_I2C_Master_Transmit(&KIT_I2C, 0x00, (uint8_t *)&data[0], 0, RX_TIMEOUT_TICKS);

    // wait tWHI + tWLO which is configured based on device type and configuration structure
    mse_delay_ms(1);

    // if necessary, revert baud rate to what came in.
    // if (bdrt != 100000)
    // {
    // change_i2c_speed(iface,400000);
    // }

    return MSE_SUCCESS;
}

/** \brief send idle command to  CryptoAuth device
 * \param[in] device_addr   device I2C address
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_idle(uint32_t device_addr)
{
    // MSEIfaceCfg* cfg = iogetifacecfg(iface);
    uint8_t data[1];
    HAL_StatusTypeDef hal_status = HAL_ERROR;
    data[0] = 0x02; // idle word address value

    hal_status = HAL_I2C_Master_Transmit(&KIT_I2C, device_addr, (uint8_t *)&data[0], 1, RX_TIMEOUT_TICKS);
    switch (hal_status)
    {
    case HAL_OK:
        return MSE_SUCCESS;
    case HAL_BUSY:
        return MSE_COMM_FAIL;
    case HAL_TIMEOUT:
        return MSE_COMM_FAIL;
    default:
        break;
    }
    return MSE_COMM_FAIL;
}

/** \brief send sleep command to CryptoAuth device
 * \param[in] device_addr   device I2C address
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_sleep(uint32_t device_addr)
{
    uint8_t data[4];
    HAL_StatusTypeDef hal_status = HAL_ERROR;
    data[0] = 0x01; // sleep word address value

    hal_status = HAL_I2C_Master_Transmit(&KIT_I2C, device_addr, (uint8_t *)&data[0], 1, RX_TIMEOUT_TICKS);
    switch (hal_status)
    {
    case HAL_OK:
        return MSE_SUCCESS;
    case HAL_BUSY:
        return MSE_COMM_FAIL;
    case HAL_TIMEOUT:
        return MSE_COMM_FAIL;
    default:
        break;
    }
    return MSE_COMM_FAIL;
}

/** \brief HAL implementation of I2C send over START
 * \param[in] device_addr   device I2C address
 * \param[in] txdata        pointer to space to bytes to send
 * \param[in] txlength      number of bytes to send
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    HAL_StatusTypeDef hal_status = HAL_ERROR;
    hal_status = HAL_I2C_Master_Transmit(&KIT_I2C, word_address, txdata, txlength, RX_TIMEOUT_TICKS);
    switch (hal_status)
    {
    case HAL_OK:
        return MSE_SUCCESS;
    case HAL_BUSY:
        return MSE_COMM_FAIL;
    case HAL_TIMEOUT:
        return MSE_COMM_FAIL;
    default:
        break;
    }
    return MSE_COMM_FAIL;
}

/** \brief HAL implementation of I2C receive function
 * \param[in]    device_addr   device I2C address
 * \param[out]   rxdata        Data received will be returned here.
 * \param[inout] rxlength      As input, the size of the rxdata buffer.
 *                             As output, the number of bytes received.
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_receive_peripheral(uint32_t device_addr, uint8_t *rxdata, uint16_t rxlength)
{
    HAL_StatusTypeDef hal_status = HAL_ERROR;
    hal_status = HAL_I2C_Master_Receive(&KIT_I2C, device_addr, rxdata, rxlength, RX_TIMEOUT_TICKS);
    switch (hal_status)
    {
    case HAL_OK:
        return MSE_SUCCESS;
    case HAL_BUSY:
        return MSE_COMM_FAIL;
    case HAL_TIMEOUT:
        return MSE_COMM_FAIL;
    default:
        break;
    }
    return MSE_COMM_FAIL;
}

/** \brief HAL implementation of I2C receive function for START I2C
 * \param[in]    device_addr   device I2C address
 * \param[out]   rxdata        Data received will be returned here.
 * \param[inout] rxlength      As input, the size of the rxdata buffer.
 *                             As output, the number of bytes received.
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    MSE_STATUS status = MSE_COMM_FAIL;

    if ((NULL == rxlength) || (NULL == rxdata))
    {
        return MSE_BAD_PARAM;
    }

    /* Read given length bytes from device */
    status = hal_i2c_receive_peripheral(word_address, rxdata, *rxlength);


    return status;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return MSE_SUCCESS
 */
MSE_STATUS hal_i2c_post_init(MSEIface iface) { return MSE_SUCCESS; }

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_control(MSEIface iface, uint8_t option, void *param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface && iface->mIfaceCFG)
    {
        if (MSE_HAL_CHANGE_BAUD == option)
        {
            return change_i2c_speed(iface, *(uint32_t *)param);
        }
        else
        {
            return MSE_UNIMPLEMENTED;
        }
    }
    return MSE_BAD_PARAM;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return MSE_SUCCESS on success, otherwise an error code.
 */

MSE_STATUS hal_i2c_release(void *hal_data) { return MSE_SUCCESS; }


#define CPU_FREQUENCY_MHZ 48 // STM32时钟主频，使用条件：系统滴答定时器需要配置和初始化
void hal_delay_us(uint32_t delay)
{
    int last, curr, val;
    int temp;

    while (delay != 0)
    {
        temp = delay > 900 ? 900 : delay;
        last = SysTick->VAL;
        curr = last - CPU_FREQUENCY_MHZ * temp;
        if (curr >= 0)
        {
            do
            {
                val = SysTick->VAL;
            } while ((val < last) && (val >= curr));
        }
        else
        {
            curr += CPU_FREQUENCY_MHZ * 1000;
            do
            {
                val = SysTick->VAL;
            } while ((val <= last) || (val > curr));
        }
        delay -= temp;
    }
}

/** @} */

#endif // I2C_HAL

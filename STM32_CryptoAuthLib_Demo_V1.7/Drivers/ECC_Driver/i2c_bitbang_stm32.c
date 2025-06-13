#include <stdint.h>
#include "stm32f1xx.h"
#include "stm32f1xx_ll_gpio.h"
#include "i2c_bitbang_stm32.h"

#ifdef I2C_EMUL // 使用GPIO模拟I2C

#define DEFAULT_I2C_BUS 0

// TODO: 定义I2C总线数组，用于绑定对应每条I2C总线的引脚位置
// *INDENT-OFF* - Preserve alignment from the code formatter
I2CBuses i2c_buses_default = {{I2C1_SDA_Pin, I2C1_SDA_Pin},
                              {I2C1_SCL_Pin, I2C1_SCL_Pin},
                              {I2C1_SDA_GPIO_Port, I2C1_SDA_GPIO_Port},
                              {I2C1_SCL_GPIO_Port, I2C1_SCL_GPIO_Port}};
// *INDENT-ON*

uint32_t pin_sda, pin_scl;
GPIO_TypeDef *port_sda;
GPIO_TypeDef *port_scl;
/*
void hal_delay_us(uint32_t us)
{
    uint32_t dwCurCounter = 0;             // 当前时间计数值
    uint32_t dwPreTickVal = SysTick->VAL;  // 之前 SYSTICK 计数值
    uint32_t dwCurTickVal;                 // 当前 SYSTICK 计数值
    us = us * (SystemCoreClock / 1000000); // 需延时时间，共多少时间节拍

    while (1)
    {
        dwCurTickVal = SysTick->VAL;

        if (dwCurTickVal < dwPreTickVal)
        {
            dwCurCounter = dwCurCounter + dwPreTickVal - dwCurTickVal;
        }
        else
        {
            dwCurCounter = dwCurCounter + dwPreTickVal + SysTick->LOAD - dwCurTickVal;
        }

        dwPreTickVal = dwCurTickVal;

        if (dwCurCounter >= us)
        {
            break;
        }
    }
}
*/
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

void i2c_set_pin(uint32_t sda, uint32_t scl)
{
    pin_sda = sda;
    pin_scl = scl;
}

void i2c_enable(void)
{
    I2C_ENABLE();
    I2C_DATA_HIGH();
    I2C_CLOCK_HIGH();
}

void i2c_send_start(void)
{
    //! Set clock high in case we re-start.
    I2C_CLOCK_HIGH();
    I2C_SET_OUTPUT_HIGH();
    I2C_DATA_LOW();
    I2C_HOLD_DELAY();
    I2C_CLOCK_LOW();
}

void i2c_send_ack(uint8_t ack)
{
    uint32_t i = 0;
    if (ack)
    {
        I2C_SET_OUTPUT_LOW(); //!< Low data line indicates an ACK.

        while (I2C_DATA_IN())
        {
            I2C_CLOCK_DELAY_SEND_ACK();
            if (i++ > 1000)
                break;
        }
    }
    else
    {
        I2C_SET_OUTPUT_HIGH(); //!< High data line indicates a NACK.

        while (!I2C_DATA_IN())
        {
            I2C_CLOCK_DELAY_SEND_ACK();
            if (i++ > 1000)
                break;
        }
    }

    //! Clock out acknowledgment.
    I2C_CLOCK_HIGH();
    I2C_CLOCK_DELAY_SEND_ACK();
    I2C_CLOCK_LOW();
}

void i2c_send_stop(void)
{
    I2C_SET_OUTPUT_LOW();
    // I2C_CLOCK_DELAY_WRITE_LOW();
    I2C_HOLD_DELAY();

    I2C_CLOCK_HIGH();
    I2C_HOLD_DELAY();

    I2C_DATA_HIGH();
}

MSE_STATUS i2c_send_byte(uint8_t i2c_byte)
{
    MSE_STATUS status = MSE_TX_TIMEOUT;

    uint8_t i;

    DISABLE_INTERRUPT();

    // 延展-判断SCL是否被拉低-发之前：速率大于100K时，等待7us或对SCL进行判断(从设备未准备好会拉低SCL)
    I2C_CLOCK_DELAY_STRETCHING();

    //! This avoids spikes but adds an if condition.
    //! We could parametrize the call to I2C_SET_OUTPUT
    //! and translate the msb to OUTSET or OUTCLR,
    //! but then the code would become target specific.
    if (i2c_byte & 0x80)
    {
        I2C_SET_OUTPUT_HIGH();
    }
    else
    {
        I2C_SET_OUTPUT_LOW();
    }

    //! Send 8 bits of data.
    for (i = 0; i < 8; i++)
    {
        I2C_CLOCK_LOW();

        if (i2c_byte & 0x80)
        {
            I2C_DATA_HIGH();
        }
        else
        {
            I2C_DATA_LOW();
        }

        I2C_CLOCK_DELAY_WRITE_LOW();

        //! Clock out the data bit.
        I2C_CLOCK_HIGH();

        //! Shifting while clock is high compensates for the time it
        //! takes to evaluate the bit while clock is low.
        //! That way, the low and high time of the clock pin is
        //! almost equal.
        i2c_byte <<= 1;
        I2C_CLOCK_DELAY_WRITE_HIGH();
    }

    //! Clock in last data bit.
    I2C_CLOCK_LOW();

    //! Set data line to be an input.
    I2C_SET_INPUT();

    I2C_CLOCK_DELAY_READ_LOW();
    //! Wait for the ack.
    I2C_CLOCK_HIGH();

    for (i = 0; i < I2C_ACK_TIMEOUT; i++)
    {
        if (!I2C_DATA_IN())
        {
            status = MSE_SUCCESS;
            I2C_CLOCK_DELAY_READ_HIGH();
            break;
        }
    }

    I2C_CLOCK_LOW();

    ENABLE_INTERRUPT();

    return status;
}

MSE_STATUS i2c_send_bytes(uint8_t count, uint8_t *data)
{
    MSE_STATUS status = MSE_TX_TIMEOUT;

    uint8_t i;

    for (i = 0; i < count; i++)
    {
        status = i2c_send_byte(data[i]);

        if (status != MSE_SUCCESS)
        {
            if (i > 0)
            {
                status = MSE_TX_FAIL;
            }

            break;
        }
    }

    return status;
}

uint8_t i2c_receive_one_byte(uint8_t ack)
{
    uint8_t i2c_byte;
    uint8_t i;

    DISABLE_INTERRUPT();

    I2C_SET_INPUT();

    // 延展-判断SCL是否被拉低-接收前：速率大于100K时，等待7us或对SCL进行判断(从设备未准备好会拉低SCL)
    I2C_CLOCK_DELAY_STRETCHING();

    for (i = 0x80, i2c_byte = 0; i; i >>= 1)
    {
        I2C_CLOCK_HIGH();
        I2C_CLOCK_DELAY_READ_HIGH();

        if (I2C_DATA_IN())
        {
            i2c_byte |= i;
        }

        I2C_CLOCK_LOW();

        if (i > 1)
        {
            //! We don't need to delay after the last bit because
            //! it takes time to switch the pin to output for acknowledging.
            I2C_CLOCK_DELAY_READ_LOW();
        }
    }

    i2c_send_ack(ack);

    ENABLE_INTERRUPT();

    return i2c_byte;
}

void i2c_receive_bytes(uint8_t count, uint8_t *data)
{
    while (--count)
    {
        *data++ = i2c_receive_one_byte(1);
    }

    *data = i2c_receive_one_byte(0);

    i2c_send_stop();
}

#endif

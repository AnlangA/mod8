#ifndef I2C_BITBANG_STM32_H_
#define I2C_BITBANG_STM32_H_

#include "mse_status.h"

//#warning "请注意设置最大的I2C总线数 MAX_I2C_BUSES"
#define MAX_I2C_BUSES 2 // The MAX_I2C_BUSES is the number of free pins in STM32
#define I2C1_SCL_Pin LL_GPIO_PIN_6
#define I2C1_SCL_GPIO_Port GPIOB
#define I2C1_SDA_Pin LL_GPIO_PIN_7
#define I2C1_SDA_GPIO_Port GPIOB

typedef struct
{
    uint32_t pin_sda[MAX_I2C_BUSES];
    uint32_t pin_scl[MAX_I2C_BUSES];
    GPIO_TypeDef *port_sda[MAX_I2C_BUSES];
    GPIO_TypeDef *port_scl[MAX_I2C_BUSES];
} I2CBuses;

extern I2CBuses i2c_buses_default;

extern uint32_t pin_sda;
extern uint32_t pin_scl;
extern GPIO_TypeDef *port_sda;
extern GPIO_TypeDef *port_scl;

#define I2C_ENABLE()                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        LL_GPIO_SetPinMode(port_sda, pin_sda, LL_GPIO_MODE_OUTPUT);                                                    \
        LL_GPIO_SetPinMode(port_scl, pin_scl, LL_GPIO_MODE_OUTPUT);                                                    \
    } while (0)

#define I2C_DISABLE()                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        LL_GPIO_SetPinMode(port_sda, pin_sda, LL_GPIO_MODE_INPUT);                                                     \
        LL_GPIO_SetPinMode(port_scl, pin_scl, LL_GPIO_MODE_INPUT);                                                     \
    } while (0)

#define I2C_CLOCK_LOW() LL_GPIO_ResetOutputPin(port_scl, pin_scl)
#define I2C_CLOCK_HIGH() LL_GPIO_SetOutputPin(port_scl, pin_scl)
#define I2C_DATA_LOW() LL_GPIO_ResetOutputPin(port_sda, pin_sda)
#define I2C_DATA_HIGH() LL_GPIO_SetOutputPin(port_sda, pin_sda)

#define I2C_DATA_IN() LL_GPIO_IsInputPinSet(port_sda, pin_sda)

#define I2C_SET_OUTPUT() LL_GPIO_SetPinMode(port_sda, pin_sda, LL_GPIO_MODE_OUTPUT)
#define I2C_SET_OUTPUT_HIGH()                                                                                          \
    {                                                                                                                  \
        I2C_SET_OUTPUT();                                                                                              \
        I2C_DATA_HIGH();                                                                                               \
    }
#define I2C_SET_OUTPUT_LOW()                                                                                           \
    {                                                                                                                  \
        I2C_SET_OUTPUT();                                                                                              \
        I2C_DATA_LOW();                                                                                                \
    }
#define I2C_SET_INPUT() LL_GPIO_SetPinMode(port_sda, pin_sda, LL_GPIO_MODE_INPUT)

#define DISABLE_INTERRUPT() __disable_irq()
#define ENABLE_INTERRUPT() __enable_irq()

#define I2C_CLOCK_DELAY_WRITE_LOW() hal_delay_us(2)
#define I2C_CLOCK_DELAY_WRITE_HIGH() hal_delay_us(2)
#define I2C_CLOCK_DELAY_READ_LOW() hal_delay_us(2)
#define I2C_CLOCK_DELAY_READ_HIGH() hal_delay_us(2)
#define I2C_CLOCK_DELAY_SEND_ACK() hal_delay_us(2)
#define I2C_CLOCK_DELAY_STRETCHING() hal_delay_us(7)    // >7us
//! This delay is inserted to make the Start and Stop hold time at least 250 ns.
#define I2C_HOLD_DELAY() hal_delay_us(4)	// >3us

//! loop count when waiting for an acknowledgment
#define I2C_ACK_TIMEOUT (8)

/**
 * \brief Set I2C data and clock pin.
 *        Other functions will use these pins.
 *
 * \param[in] sda  definition of GPIO pin to be used as data pin
 * \param[in] scl  definition of GPIO pin to be used as clock pin
 */
void i2c_set_pin(uint32_t sda, uint32_t scl);

/**
 * \brief Configure GPIO pins for I2C clock and data as output.
 */
void i2c_enable(void);

/**
 * \brief Configure GPIO pins for I2C clock and data as input.
 */
void i2c_disable(void);

/**
 * \brief Send a START condition.
 */
void i2c_send_start(void);

/**
 * \brief Send an ACK or NACK (after receive).
 *
 * \param[in] ack  0: NACK, else: ACK
 */
void i2c_send_ack(uint8_t ack);

/**
 * \brief Send a STOP condition.
 */
void i2c_send_stop(void);

/**
 * \brief Send one byte.
 *
 * \param[in] i2c_byte  byte to write
 *
 * \return MSE_STATUS
 */
MSE_STATUS i2c_send_byte(uint8_t i2c_byte);

/**
 * \brief Send a number of bytes.
 *
 * \param[in] count  number of bytes to send
 * \param[in] data   pointer to buffer containing bytes to send
 *
 * \return MSE_STATUS
 */
MSE_STATUS i2c_send_bytes(uint8_t count, uint8_t *data);

/**
 * \brief Receive one byte (MSB first).
 *
 * \param[in] ack  0:NACK, else:ACK
 *
 * \return Number of bytes received
 */
uint8_t i2c_receive_one_byte(uint8_t ack);

/**
 * \brief Receive a number of bytes.
 *
 * \param[out] data   pointer to receive buffer
 * \param[in]  count  number of bytes to receive
 */
void i2c_receive_bytes(uint8_t count, uint8_t *data);

#endif /* I2C_BITBANG_STM32_H_ */

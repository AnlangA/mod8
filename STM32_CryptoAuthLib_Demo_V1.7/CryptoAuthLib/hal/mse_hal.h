/**
 * \file
 * \brief low-level HAL - methods used to setup indirection to physical layer interface
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


#ifndef MSE_HAL_H_
#define MSE_HAL_H_

#include <stdlib.h>

#include "mse_config.h"

#include "mse_status.h"
#include "mse_iface.h"


/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

typedef struct
{
    MSE_STATUS (*send)(void* ctx, uint8_t* txdata, uint16_t txlen);        /**< Must be a blocking send */
    MSE_STATUS (*recv)(void* ctx, uint8_t* rxdata, uint16_t* rxlen);       /**< Must be a blocking receive */
    void* (*packet_alloc)(size_t bytes);                                    /**< Allocate a phy packet */
    void (*packet_free)(void* packet);                                      /**< Free a phy packet */
    void* hal_data;                                                         /**< Physical layer context */
} mse_hal_kit_phy_t;

#ifdef __cplusplus
extern "C" {
#endif

MSE_STATUS hal_iface_init(MSEIfaceCfg *, MSEHAL_t** hal, MSEHAL_t** phy);
MSE_STATUS hal_iface_release(MSEIfaceType, void* hal_data);

MSE_STATUS hal_check_wake(const uint8_t* response, int response_size);

#ifdef MSE_HAL_I2C
MSE_STATUS hal_i2c_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_i2c_post_init(MSEIface iface);
MSE_STATUS hal_i2c_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS hal_i2c_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS hal_i2c_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef MSE_LEGACY_HAL
MSE_STATUS hal_i2c_wake(MSEIface iface);
MSE_STATUS hal_i2c_idle(MSEIface iface);
MSE_STATUS hal_i2c_sleep(MSEIface iface);
#endif
MSE_STATUS hal_i2c_release(void *hal_data);
#endif

#ifdef MSE_HAL_SWI_UART
MSE_STATUS hal_swi_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_swi_post_init(MSEIface iface);
MSE_STATUS hal_swi_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS hal_swi_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS hal_swi_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef MSE_LEGACY_HAL
MSE_STATUS hal_swi_wake(MSEIface iface);
MSE_STATUS hal_swi_idle(MSEIface iface);
MSE_STATUS hal_swi_sleep(MSEIface iface);
#endif
MSE_STATUS hal_swi_release(void *hal_data);
#endif

#if defined(MSE_HAL_SWI_GPIO) || defined(MSE_HAL_SWI_BB)
MSE_STATUS hal_swi_gpio_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_swi_gpio_post_init(MSEIface iface);
MSE_STATUS hal_swi_gpio_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS hal_swi_gpio_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS hal_swi_gpio_release(void *hal_data);
MSE_STATUS hal_swi_gpio_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#endif

#if defined(MSE_HAL_GPIO) || defined(MSE_HAL_BB)
MSE_STATUS hal_gpio_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_gpio_post_init(MSEIface iface);
MSE_STATUS hal_gpio_send(MSEIface iface, uint8_t word_address, uint8_t* pin_state, int unused_param);
MSE_STATUS hal_gpio_receive(MSEIface iface, uint8_t word_address, uint8_t* pin_state, uint16_t* unused_param);
MSE_STATUS hal_gpio_release(void *hal_data);
MSE_STATUS hal_gpio_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#endif

#if defined(MSE_HAL_SWI_UART) || defined(MSE_HAL_KIT_UART) || defined(MSE_HAL_UART)
MSE_STATUS hal_uart_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_uart_post_init(MSEIface iface);
MSE_STATUS hal_uart_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS hal_uart_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS hal_uart_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef MSE_LEGACY_HAL
MSE_STATUS hal_uart_wake(MSEIface iface);
MSE_STATUS hal_uart_idle(MSEIface iface);
MSE_STATUS hal_uart_sleep(MSEIface iface);
#endif
MSE_STATUS hal_uart_release(void *hal_data);
#endif

#ifdef MSE_HAL_SPI
MSE_STATUS hal_spi_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_spi_post_init(MSEIface iface);
MSE_STATUS hal_spi_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS hal_spi_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS hal_spi_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#ifdef MSE_LEGACY_HAL
MSE_STATUS hal_spi_wake(MSEIface iface);
MSE_STATUS hal_spi_idle(MSEIface iface);
MSE_STATUS hal_spi_sleep(MSEIface iface);
#endif
MSE_STATUS hal_spi_release(void *hal_data);
#endif

#ifdef MSE_HAL_KIT_HID
MSE_STATUS hal_kit_hid_init(MSEIface iface, MSEIfaceCfg *cfg);
MSE_STATUS hal_kit_hid_post_init(MSEIface iface);
MSE_STATUS hal_kit_hid_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS hal_kit_hid_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS hal_kit_hid_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
MSE_STATUS hal_kit_hid_release(void *hal_data);
#endif

#ifdef MSE_HAL_KIT_BRIDGE
MSE_STATUS hal_kit_init(MSEIface iface, MSEIfaceCfg* cfg);
MSE_STATUS hal_kit_post_init(MSEIface iface);
MSE_STATUS hal_kit_send(MSEIface iface, uint8_t word_address, uint8_t* txdata, int txlength);
MSE_STATUS hal_kit_receive(MSEIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength);
MSE_STATUS hal_kit_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
MSE_STATUS hal_kit_release(void* hal_data);
#endif

#ifdef MSE_HAL_CUSTOM
MSE_STATUS hal_custom_control(MSEIface iface, uint8_t option, void* param, size_t paramlen);
#endif

/* Polling defaults if not overwritten by the configuration */
#ifndef MSE_POLLING_INIT_TIME_MSEC
#define MSE_POLLING_INIT_TIME_MSEC       5
#endif

#ifndef MSE_POLLING_FREQUENCY_TIME_MSEC
#define MSE_POLLING_FREQUENCY_TIME_MSEC  2
#endif

#ifndef MSE_POLLING_MAX_TIME_MSEC
#define MSE_POLLING_MAX_TIME_MSEC        2500
#endif

/*  */
typedef enum
{
    MSE_HAL_CONTROL_WAKE = 0,
    MSE_HAL_CONTROL_IDLE = 1,
    MSE_HAL_CONTROL_SLEEP = 2,
    MSE_HAL_CONTROL_RESET = 3,
    MSE_HAL_CONTROL_SELECT = 4,
    MSE_HAL_CONTROL_DESELECT = 5,
    MSE_HAL_CHANGE_BAUD = 6,
    MSE_HAL_FLUSH_BUFFER = 7,
    MSE_HAL_CONTROL_DIRECTION = 8
} MSE_HAL_CONTROL;

/** \brief Timer API for legacy implementations */
#ifndef mse_delay_ms
void mse_delay_ms(uint32_t ms);
#endif

#ifndef mse_delay_us
void mse_delay_us(uint32_t us);
#endif

/** \brief Timer API implemented at the HAL level */
void hal_rtos_delay_ms(uint32_t ms);
void hal_delay_ms(uint32_t ms);
void hal_delay_us(uint32_t us);

/** \brief Optional hal interfaces */
MSE_STATUS hal_create_mutex(void ** ppMutex, char* pName);
MSE_STATUS hal_destroy_mutex(void * pMutex);
MSE_STATUS hal_lock_mutex(void * pMutex);
MSE_STATUS hal_unlock_mutex(void * pMutex);

#ifndef MSE_NO_HEAP
#ifdef MSE_TESTS_ENABLED
void hal_test_set_memory_f(void* (*malloc_func)(size_t), void (*free_func)(void*));
#endif

#if defined(MSE_TESTS_ENABLED) || !defined(MSE_PLATFORM_MALLOC)
void*   hal_malloc(size_t size);
void    hal_free(void* ptr);
#else
#define hal_malloc      MSE_PLATFORM_MALLOC
#define hal_free        MSE_PLATFORM_FREE
#endif
#endif

#ifdef memset_s
#define hal_memset_s    memset_s
#else
#define hal_memset_s    mse_memset_s
#endif


MSE_STATUS hal_iface_register_hal(MSEIfaceType iface_type, MSEHAL_t *hal, MSEHAL_t **old_hal, MSEHAL_t* phy, MSEHAL_t** old_phy);
uint8_t hal_is_command_word(uint8_t word_address);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* MSE_HAL_H_ */

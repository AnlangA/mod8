/**
 * \file
 * \brief low-level HAL - methods used to setup indirection to physical layer interface.
 * this level does the dirty work of abstracting the higher level MSEIFace methods from the
 * low-level physical interfaces.  Its main goal is to keep low-level details from bleeding into
 * the logical interface implemetation.
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


/* when incorporating MSE HAL into your application, you need to adjust the #defines in mse_hal.h to include
 * and exclude appropriate interfaces - this optimizes memory use when not using a specific iface implementation in your application */

#include "cryptoauthlib.h"
#include "mse_hal.h"

#ifndef MSE_MAX_HAL_CACHE
#define MSE_MAX_HAL_CACHE
#endif

#ifdef MSE_HAL_I2C
static MSEHAL_t hal_i2c = {
    hal_i2c_init,
    hal_i2c_post_init,
    hal_i2c_send,
    hal_i2c_receive,
    hal_i2c_control,
    hal_i2c_release
};
#endif

#ifdef MSE_HAL_SWI_UART
static MSEHAL_t hal_swi_uart = {
    hal_swi_init,
    hal_swi_post_init,
    hal_swi_send,
    hal_swi_receive,
    hal_swi_control,
    hal_swi_release
};
#endif

#if defined(MSE_HAL_SWI_GPIO) || defined(MSE_HAL_SWI_BB)
static MSEHAL_t hal_swi_gpio = {
    hal_swi_gpio_init,
    hal_swi_gpio_post_init,
    hal_swi_gpio_send,
    hal_swi_gpio_receive,
    hal_swi_gpio_control,
    hal_swi_gpio_release
};
#endif

#if defined(MSE_HAL_UART) || defined(MSE_HAL_SWI_UART) || defined(MSE_HAL_KIT_UART)
static MSEHAL_t hal_uart = {
    hal_uart_init,
    hal_uart_post_init,
    hal_uart_send,
    hal_uart_receive,
    hal_uart_control,
    hal_uart_release
};
#endif

#ifdef MSE_HAL_SPI
static MSEHAL_t hal_spi = {
    hal_spi_init,
    hal_spi_post_init,
    hal_spi_send,
    hal_spi_receive,
    hal_spi_control,
    hal_spi_release
};
#endif

#if defined(MSE_HAL_GPIO) || defined(MSE_HAL_BB)
static MSEHAL_t hal_gpio = {
    hal_gpio_init,
    hal_gpio_post_init,
    hal_gpio_send,          /* Set IO State */
    hal_gpio_receive,       /* Read IO State */
    hal_gpio_control,
    hal_gpio_release
};
#endif

#ifdef MSE_HAL_KIT_HID
static MSEHAL_t hal_hid = {
    hal_kit_hid_init,
    hal_kit_hid_post_init,
    hal_kit_hid_send,
    hal_kit_hid_receive,
    hal_kit_hid_control,
    hal_kit_hid_release
};
#endif

#if defined(MSE_HAL_KIT_HID) || defined(MSE_HAL_KIT_UART)
#include "kit_protocol.h"
static MSEHAL_t hal_kit_v1 = {
    kit_init,
    kit_post_init,
    kit_send,
    kit_receive,
    kit_control,
    kit_release
};
#endif

#ifdef MSE_HAL_KIT_BRIDGE
static MSEHAL_t hal_kit_bridge = {
    hal_kit_init,
    hal_kit_post_init,
    hal_kit_send,
    hal_kit_receive,
    hal_kit_control,
    hal_kit_release
};
#endif

#ifdef MSE_HAL_CUSTOM
static MSEHAL_t hal_custom;
#endif

/** \brief Structure that holds the hal/phy maping for different interface types
 */
typedef struct
{
    uint8_t    iface_type;          /**<  */
    MSEHAL_t* hal;                 /**<  */
    MSEHAL_t* phy;                 /**< Physical interface for the specific HAL*/
} mse_hal_list_entry_t;


static mse_hal_list_entry_t mse_registered_hal_list[MSE_MAX_HAL_CACHE] = {
#ifdef MSE_HAL_I2C
    { MSE_I2C_IFACE,      &hal_i2c,             NULL             },
#endif
#ifdef MSE_HAL_SWI_UART
    { MSE_SWI_IFACE,      &hal_swi_uart,        &hal_uart        },
#endif
#ifdef MSE_HAL_KIT_UART
    { MSE_UART_IFACE,     &hal_kit_v1,          &hal_uart        },
#elif defined(MSE_HAL_UART)
    { MSE_UART_IFACE,     &hal_uart,            NULL             },
#endif
#ifdef MSE_HAL_SPI
    { MSE_SPI_IFACE,      &hal_spi,             NULL             },
#endif
#ifdef MSE_HAL_KIT_HID
    { MSE_HID_IFACE,      &hal_kit_v1,          &hal_hid         },
#endif
#ifdef MSE_HAL_KIT_BRIDGE
    { MSE_KIT_IFACE,      &hal_kit_bridge,      NULL             },
#endif
#if defined(MSE_HAL_SWI_GPIO) || defined(MSE_HAL_SWI_BB)
    { MSE_SWI_GPIO_IFACE, &hal_swi_gpio,        &hal_gpio                    },
#endif
};

static const size_t mse_registered_hal_list_size = sizeof(mse_registered_hal_list) / sizeof(mse_hal_list_entry_t);


/** \brief Internal function to get a value from the hal cache
 * \param[in] iface_type - the type of physical interface to register
 * \param[out] hal pointer to the existing MSEHAL_t structure
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
static MSE_STATUS hal_iface_get_registered(MSEIfaceType iface_type, MSEHAL_t** hal, MSEHAL_t **phy)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (hal && phy)
    {
        size_t i;
        for (i = 0; i < mse_registered_hal_list_size; i++)
        {
            if (iface_type == mse_registered_hal_list[i].iface_type)
            {
                break;
            }
        }

        if (i < mse_registered_hal_list_size)
        {
            *hal = mse_registered_hal_list[i].hal;
            *phy = mse_registered_hal_list[i].phy;
            status = MSE_SUCCESS;
        }
        else
        {
            status = MSE_GEN_FAIL;
        }
    }

    return status;
}

/** \brief Internal function to set a value in the hal cache
 * \param[in] iface_type - the type of physical interface to register
 * \param[in] hal pointer to the existing MSEHAL_t structure
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
static MSE_STATUS hal_iface_set_registered(MSEIfaceType iface_type, MSEHAL_t* hal, MSEHAL_t* phy)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (hal)
    {
        size_t i;
        size_t empty = mse_registered_hal_list_size;
        for (i = 0; i < mse_registered_hal_list_size; i++)
        {
            if (iface_type == mse_registered_hal_list[i].iface_type)
            {
                break;
            }
            else if (empty == mse_registered_hal_list_size)
            {
                if (!mse_registered_hal_list[i].hal && !mse_registered_hal_list[i].phy)
                {
                    empty = i;
                }
            }
        }

        if (i < mse_registered_hal_list_size)
        {
            mse_registered_hal_list[i].hal = hal;
            mse_registered_hal_list[i].phy = phy;
            status = MSE_SUCCESS;
        }
        else if (empty < mse_registered_hal_list_size)
        {
            mse_registered_hal_list[empty].hal = hal;
            mse_registered_hal_list[empty].hal = phy;
            status = MSE_SUCCESS;
        }
        else
        {
            status = MSE_ALLOC_FAILURE;
        }

    }

    return status;
}

/** \brief Register/Replace a HAL with a
 * \param[in] iface_type - the type of physical interface to register
 * \param[in] hal pointer to the new MSEHAL_t structure to register
 * \param[out] old pointer to the existing MSEHAL_t structure
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_iface_register_hal(MSEIfaceType iface_type, MSEHAL_t *hal, MSEHAL_t **old_hal, MSEHAL_t* phy, MSEHAL_t** old_phy)
{
    MSE_STATUS status;

    status = (old_hal && old_phy) ? hal_iface_get_registered(iface_type, old_hal, old_phy) : MSE_SUCCESS;

    if (MSE_SUCCESS == status)
    {
        status = hal_iface_set_registered(iface_type, hal, phy);
    }

    return MSE_SUCCESS;
}

/** \brief Standard HAL API for MSE to initialize a physical interface
 * \param[in] cfg pointer to MSEIfaceCfg object
 * \param[in] hal pointer to MSEHAL_t intermediate data structure
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_iface_init(MSEIfaceCfg *cfg, MSEHAL_t **hal, MSEHAL_t **phy)
{
    MSE_STATUS status = MSE_BAD_PARAM;

    if (cfg && hal)
    {
        status = hal_iface_get_registered(cfg->iface_type, hal, phy);

#ifdef MSE_HAL_CUSTOM
        if (MSE_CUSTOM_IFACE == cfg->iface_type)
        {
            *hal = hal_malloc(sizeof(MSEHAL_t));
            if (*hal)
            {
                (*hal)->halinit = cfg->mcacustom.halinit;
                (*hal)->halpostinit = cfg->mcacustom.halpostinit;
                (*hal)->halreceive = cfg->mcacustom.halreceive;
                (*hal)->halsend = cfg->mcacustom.halsend;
                (*hal)->halcontrol = hal_custom_control;
                (*hal)->halrelease = cfg->mcacustom.halrelease;
                status = MSE_SUCCESS;
            }
            else
            {
                status = MSE_ALLOC_FAILURE;
            }
        }
#endif
    }

    return status;
}

/** \brief releases a physical interface, HAL knows how to interpret hal_data
 * \param[in] iface_type - the type of physical interface to release
 * \param[in] hal_data - pointer to opaque hal data maintained by HAL implementation for this interface type
 *  \return MSE_SUCCESS on success, otherwise an error code.
 */

MSE_STATUS hal_iface_release(MSEIfaceType iface_type, void *hal_data)
{
    MSE_STATUS status;
    MSEHAL_t * hal;
    MSEHAL_t* phy;

    status = hal_iface_get_registered(iface_type, &hal, &phy);

    if (MSE_SUCCESS == status)
    {
        if (hal && hal->halrelease)
        {
            status = hal->halrelease(hal_data);
        }

        if (phy && phy->halrelease)
        {
            MSE_STATUS phy_status = phy->halrelease(hal_data);

            if (MSE_SUCCESS == status)
            {
                status = phy_status;
            }
        }
    }

    return status;
}

/** \brief Utility function for hal_wake to check the reply.
 * \param[in] response       Wake response to be checked.
 * \param[in] response_size  Size of the response to check.
 * \return MSE_SUCCESS for expected wake, MSE_STATUS_SELFTEST_ERROR if the
 *         power on self test failed, MSE_WAKE_FAILED for other failures.
 */
MSE_STATUS hal_check_wake(const uint8_t* response, int response_size)
{
    const uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };
    const uint8_t selftest_fail_resp[4] = { 0x04, 0x07, 0xC4, 0x40 };

    if (response_size != 4)
    {
        return MSE_WAKE_FAILED;
    }
    if (memcmp(response, expected_response, 4) == 0)
    {
        return MSE_SUCCESS;
    }
    if (memcmp(response, selftest_fail_resp, 4) == 0)
    {
        return MSE_STATUS_SELFTEST_ERROR;
    }
    return MSE_WAKE_FAILED;
}

/** \brief Utility function for hal_wake to check the reply.
 * \param[in] word_address      Command to check
 * \return true if the word_address is considered a command
 */
uint8_t hal_is_command_word(uint8_t word_address)
{
    return 0xFF == word_address || 0x03 == word_address || 0x10 == word_address;
}


#if !defined(MSE_NO_HEAP) && defined(MSE_TESTS_ENABLED) && defined(MSE_PLATFORM_MALLOC)

void* (*g_hal_malloc_f)(size_t) = MSE_PLATFORM_MALLOC;
void (*g_hal_free_f)(void*) = MSE_PLATFORM_FREE;

void* hal_malloc(size_t size)
{
    return g_hal_malloc_f(size);
}

void hal_free(void* ptr)
{
    g_hal_free_f(ptr);
}

void hal_test_set_memory_f(void* (*malloc_func)(size_t), void (*free_func)(void*))
{
    g_hal_malloc_f = malloc_func;
    g_hal_free_f = free_func;
}

#endif

#if defined(MSE_HAL_LEGACY_API) && defined(MSE_HAL_I2C)
MSE_STATUS hal_i2c_control(MSEIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    switch (option)
    {
    case MSE_HAL_CONTROL_WAKE:
        return hal_i2c_wake(iface);
    case MSE_HAL_CONTROL_IDLE:
        return hal_i2c_idle(iface);
    case MSE_HAL_CONTROL_SLEEP:
        return hal_i2c_sleep(iface);
    case MSE_HAL_CONTROL_SELECT:
    /* fallthrough */
    case MSE_HAL_CONTROL_DESELECT:
        return MSE_SUCCESS;
    default:
        return MSE_BAD_PARAM;
    }
}
#endif

#if defined(MSE_HAL_LEGACY_API) && defined(MSE_HAL_SWI)
MSE_STATUS hal_swi_control(MSEIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    switch (option)
    {
    case MSE_HAL_CONTROL_WAKE:
        return hal_swi_wake(iface);
    case MSE_HAL_CONTROL_IDLE:
        return hal_swi_idle(iface);
    case MSE_HAL_CONTROL_SLEEP:
        return hal_swi_sleep(iface);
    case MSE_HAL_CONTROL_SELECT:
    /* fallthrough */
    case MSE_HAL_CONTROL_DESELECT:
        return MSE_SUCCESS;
    default:
        return MSE_BAD_PARAM;
    }
}
#endif

#if defined(MSE_HAL_LEGACY_API) && defined(MSE_HAL_UART)
MSE_STATUS hal_uart_control(MSEIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    switch (option)
    {
    case MSE_HAL_CONTROL_WAKE:
        return hal_uart_wake(iface);
    case MSE_HAL_CONTROL_IDLE:
        return hal_uart_idle(iface);
    case MSE_HAL_CONTROL_SLEEP:
        return hal_uart_sleep(iface);
    case MSE_HAL_CONTROL_SELECT:
    /* fallthrough */
    case MSE_HAL_CONTROL_DESELECT:
        return MSE_SUCCESS;
    default:
        return MSE_BAD_PARAM;
    }
}
#endif

#if defined(MSE_HAL_LEGACY_API) && defined(MSE_HAL_SPI)
MSE_STATUS hal_spi_control(MSEIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface)
    {
        switch (option)
        {
        case MSE_HAL_CONTROL_WAKE:
            return hal_spi_wake(iface);
        case MSE_HAL_CONTROL_IDLE:
            return hal_spi_idle(iface);
        case MSE_HAL_CONTROL_SLEEP:
            return hal_spi_sleep(iface);
        case MSE_HAL_CONTROL_SELECT:
        /* fallthrough */
        case MSE_HAL_CONTROL_DESELECT:
            return MSE_SUCCESS;
        default:
            break;
        }
    }
    return MSE_BAD_PARAM;
}
#endif

#if defined(MSE_HAL_CUSTOM)
MSE_STATUS hal_custom_control(MSEIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface && iface->mIfaceCFG)
    {
        switch (option)
        {
        case MSE_HAL_CONTROL_WAKE:
            return iface->mIfaceCFG->mcacustom.halwake(iface);
        case MSE_HAL_CONTROL_IDLE:
            return iface->mIfaceCFG->mcacustom.halidle(iface);
        case MSE_HAL_CONTROL_SLEEP:
            return iface->mIfaceCFG->mcacustom.halsleep(iface);
        case MSE_HAL_CONTROL_SELECT:
        /* fallthrough */
        case MSE_HAL_CONTROL_DESELECT:
            return MSE_SUCCESS;
        default:
            break;
        }
    }
    return MSE_BAD_PARAM;
}
#endif

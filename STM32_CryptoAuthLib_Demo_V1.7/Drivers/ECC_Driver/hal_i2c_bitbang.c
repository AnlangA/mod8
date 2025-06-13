#include <string.h>
#include <stdio.h>
#include "mse_hal.h"
#include "mse_device.h"
#include "hal_i2c_bitbang.h"

#ifdef I2C_EMUL

/**
 * \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief These methods define the hardware abstraction layer for
 *        communicating with a CryptoAuth device using I2C bit banging.
 */

/**
 * \brief Logical to physical bus mapping structure.
 */
static MSEI2CMaster_t i2c_hal_data[MAX_I2C_BUSES]; //!< map logical, 0-based bus number to index

/**
 * \brief This function creates a Start condition and sends the I2C
 *        address.
 *
 * \param[in] iface  interface of the logical device to send data to
 * \param[in] RorW   I2C_READ for reading, I2C_WRITE for writing.
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
static MSE_STATUS hal_i2c_send_slave_address(uint8_t address, uint8_t RorW)
{
    // MSEIfaceCfg *cfg = iogetifacecfg(iface);

    MSE_STATUS status = MSE_TX_TIMEOUT;

    uint8_t sla = address | RorW;

    i2c_send_start();

    status = i2c_send_byte(sla);

    if (status != MSE_SUCCESS)
    {
        i2c_send_stop();
    }

    return status;
}

/**
 * \brief hal_i2c_init manages requests to initialize a physical
 *        interface. It manages use counts so when an interface has
 *        released the physical layer, it will disable the interface for
 *        some other use. You can have multiple MSEIFace instances using
 *        the same bus, and you can have multiple MSEIFace instances on
 *        multiple i2c buses, so hal_i2c_init manages these things and
 *        MSEIFace is abstracted from the physical details.
 */

/**
 * \brief Initialize an I2C interface using given config.
 *
 * \param[in] iface  opaque pointer to HAL data
 * \param[in] cfg  interface configuration
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_init(MSEIface iface, MSEIfaceCfg *cfg)
{
    if (!iface || !cfg)
    {
        return MSE_BAD_PARAM;
    }
    if (cfg->i2c.bus >= MAX_I2C_BUSES)
    {
        return MSE_COMM_FAIL;
    }

    MSEI2CMaster_t *data = &i2c_hal_data[cfg->i2c.bus];

    if (data->ref_ct <= 0)
    {
        // Bus isn't being used, enable it
        //  设置当前需要进行通讯的 I2C 总线为第几条:MSEIfaceCfg cfg_mod8_i2c
        // cfg_mod8_i2c.i2c.bus = ;

        // 映射 SDA 和 SCL 的 PORT
        port_sda = i2c_buses_default.port_sda[cfg->i2c.bus]; // I2C1_SDA_GPIO_Port
        port_scl = i2c_buses_default.port_scl[cfg->i2c.bus]; // I2C1_SCL_GPIO_Port
        // assign GPIO pins
        i2c_hal_data[cfg->i2c.bus].pin_sda = i2c_buses_default.pin_sda[cfg->i2c.bus];
        i2c_hal_data[cfg->i2c.bus].pin_scl = i2c_buses_default.pin_scl[cfg->i2c.bus];

        i2c_set_pin(i2c_hal_data[cfg->i2c.bus].pin_sda, i2c_hal_data[cfg->i2c.bus].pin_scl);
        i2c_enable();

        // store this for use during the release phase
        data->bus_index = cfg->i2c.bus;
        // buses are shared, this is the first instance
        data->ref_ct = 1;
    }
    else
    {
        // Bus is already is use, increment reference counter
        data->ref_ct++;
    }

    iface->hal_data = data;

    return MSE_SUCCESS;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return MSE_STATUS
 */
MSE_STATUS hal_i2c_post_init(MSEIface iface) { return MSE_SUCCESS; }

/**
 * \brief HAL implementation of Send byte(s) via I2C.
 *
 * \param[in] iface     interface of the logical device to send data to
 * \param[in] txdata    pointer to bytes to send
 * \param[in] txlength  number of bytes to send
 *
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_send(MSEIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    MSEIfaceCfg *cfg = iogetifacecfg(iface);

    MSE_STATUS status = MSE_TX_TIMEOUT;

    int bus = cfg->i2c.bus;

    //! Set I2C pins
    i2c_set_pin(i2c_hal_data[bus].pin_sda, i2c_hal_data[bus].pin_scl);

    //! Address the device and indicate that bytes are to be written
    status = hal_i2c_send_slave_address(word_address, I2C_WRITE);

    if (status != MSE_SUCCESS)
    {
        return status;
    }

    //! Send the remaining bytes
    if (txlength)
        status = i2c_send_bytes(txlength, txdata);

    //! Send STOP regardless of i2c_status
    i2c_send_stop();

    return status;
}

/**
 * \brief HAL implementation of receive bytes via I2C bit-banged.
 * \param[in]    iface     Device to interact with.
 * \param[out]   rxdata    Data received will be returned here.
 * \param[inout] rxlength  As input, the size of the rxdata buffer.
 *                         As output, the number of bytes received.
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_receive(MSEIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    MSEIfaceCfg *cfg = iogetifacecfg(iface);
    MSE_STATUS status = MSE_RX_FAIL;
    int bus = cfg->i2c.bus;
    int retries = cfg->rx_retries;

    // Set I2C pins
    i2c_set_pin(i2c_hal_data[bus].pin_sda, i2c_hal_data[bus].pin_scl);

    while (retries-- > 0 && status != MSE_SUCCESS)
    {
        // Address the device and indicate that bytes are to be read
        status = hal_i2c_send_slave_address(word_address, I2C_READ);

        if (status == MSE_SUCCESS)
        {
            // Receive count byte
            i2c_receive_bytes(*rxlength, rxdata);
        }
    }

    return status;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data  opaque pointer to hal data structure - known only to the HAL implementation
 * \return MSE_SUCCESS on success, otherwise an error code.
 */
MSE_STATUS hal_i2c_release(void *hal_data)
{
    MSEI2CMaster_t *hal = (MSEI2CMaster_t *)hal_data;

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0)
    {
        i2c_set_pin(i2c_hal_data[hal->bus_index].pin_sda, i2c_hal_data[hal->bus_index].pin_scl);
        hal->ref_ct = 0;
    }

    return MSE_SUCCESS;
}

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
            // return change_i2c_speed(iface, *(uint32_t *)param);
            return MSE_SUCCESS;
        }
        else
        {
            return MSE_UNIMPLEMENTED;
        }
    }
    return MSE_BAD_PARAM;
}

#endif

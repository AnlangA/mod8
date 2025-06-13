/**
 * \file
 *
 * \brief  ModSemi Crypto Auth hardware interface object
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

#ifndef MSE_IFACE_H
#define MSE_IFACE_H
/*lint +flb */

/** \defgroup interface MSEIface (mse_)
 *  \brief Abstract interface to all CryptoAuth device types.  This interface
 *  connects to the HAL implementation and abstracts the physical details of the
 *  device communication from all the upper layers of CryptoAuthLib
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#include "mse_config.h"
#include "mse_devtypes.h"
#include "mse_status.h"


typedef enum
{
    MSE_I2C_IFACE = 0,         /**< Native I2C Driver */
    MSE_SWI_IFACE = 1,         /**< SWI or 1-Wire over UART/USART */
    MSE_UART_IFACE = 2,        /**< Kit v1 over UART/USART */
    MSE_SPI_IFACE = 3,         /**< Native SPI Driver */
    MSE_HID_IFACE = 4,         /**< Kit v1 over HID */
    MSE_KIT_IFACE = 5,         /**< Kit v2 (Binary/Bridging) */
    MSE_CUSTOM_IFACE = 6,      /**< Custom HAL functions provided during interface init */
    MSE_I2C_GPIO_IFACE = 7,    /**< I2C "Bitbang" Driver */
    MSE_SWI_GPIO_IFACE = 8,    /**< SWI or 1-Wire using a GPIO */
    MSE_SPI_GPIO_IFACE = 9,    /**< SWI or 1-Wire using a GPIO */

    // additional physical interface types here
    MSE_UNKNOWN_IFACE = 0xFE
} MSEIfaceType;


/*The types are used within the kit protocol to identify the correct interface*/
typedef enum
{   MSE_KIT_AUTO_IFACE,        //Selects the first device if the Kit interface is not defined
    MSE_KIT_I2C_IFACE,
    MSE_KIT_SWI_IFACE,
    MSE_KIT_SPI_IFACE,
    MSE_KIT_UNKNOWN_IFACE
} MSEKitType;


/* MSEIfaceCfg is the configuration object for a device
 */

typedef struct
{

    MSEIfaceType  iface_type;      // active iface - how to interpret the union below
    MSEDeviceType devtype;         // explicit device type

    union                           // each instance of an iface cfg defines a single type of interface
    {
        struct
        {
#ifdef MSE_ENABLE_DEPRECATED
            uint8_t slave_address;  // 8-bit slave address
#else
            uint8_t address;        /**< Device address - the upper 7 bits are the I2c address bits */
#endif
            uint8_t  bus;           // logical i2c bus number, 0-based - HAL will map this to a pin pair for SDA SCL
            uint32_t baud;          // typically 400000
        } i2c;

        struct
        {
            uint8_t address;        // 7-bit device address
            uint8_t bus;            // logical SWI bus - HAL will map this to a pin	or uart port
        } mcaswi;

        struct
        {
            uint8_t  bus;           // logical i2c bus number, 0-based - HAL will map this to a spi pheripheral
            uint8_t  select_pin;    // CS pin line typically 0
            uint32_t baud;          // typically 16000000
        } mcaspi;

        struct
        {
            MSEKitType dev_interface; // Kit interface type
            uint8_t     dev_identity;  // I2C address for the I2C interface device or the bus number for the SWI interface device.
            uint8_t     port;          // Port numbers where supported - otherwise accept the device through config data
            uint32_t    baud;          // typically 115200
            uint8_t     wordsize;      // usually 8
            uint8_t     parity;        // 0 == even, 1 == odd, 2 == none
            uint8_t     stopbits;      // 0,1,2
        } mcauart;

        struct
        {
            int         idx;           // HID enumeration index
            MSEKitType dev_interface; // Kit interface type
            uint8_t     dev_identity;  // I2C address for the I2C interface device or the bus number for the SWI interface device.
            uint32_t    vid;           // Vendor ID of kit (0x03EB for CK101)
            uint32_t    pid;           // Product ID of kit (0x2312 for CK101)
            uint32_t    packetsize;    // Size of the USB packet
        } mcahid;

        struct
        {
            MSEKitType dev_interface; // Target Bus Type
            uint8_t     dev_identity;  // Target device identity
            uint32_t    flags;
        } mcakit;

        struct
        {
            MSE_STATUS (*halinit)(void *hal, void *cfg);
            MSE_STATUS (*halpostinit)(void *iface);
            MSE_STATUS (*halsend)(void *iface, uint8_t word_address, uint8_t *txdata, int txlength);
            MSE_STATUS (*halreceive)(void *iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength);
            MSE_STATUS (*halwake)(void *iface);
            MSE_STATUS (*halidle)(void *iface);
            MSE_STATUS (*halsleep)(void *iface);
            MSE_STATUS (*halrelease)(void* hal_data);
        } mcacustom;

    };

    uint16_t wake_delay;    // microseconds of tWHI + tWLO which varies based on chip type
    int      rx_retries;    // the number of retries to attempt for receiving bytes
    void *   cfg_data;      // opaque data used by HAL in device discovery
} MSEIfaceCfg;



typedef struct mse_iface * MSEIface;

/** \brief HAL Driver Structure
 */
typedef struct
{
    MSE_STATUS (*halinit)(MSEIface iface, MSEIfaceCfg* cfg);
    MSE_STATUS (*halpostinit)(MSEIface iface);
    MSE_STATUS (*halsend)(MSEIface iface, uint8_t word_address, uint8_t* txdata, int txlength);
    MSE_STATUS (*halreceive)(MSEIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength);
    MSE_STATUS (*halcontrol)(MSEIface iface, uint8_t option, void* param, size_t paramlen);
    MSE_STATUS (*halrelease)(void* hal_data);
} MSEHAL_t;

/** \brief mse_iface is the context structure for a configured interface
 */
typedef struct mse_iface
{
    MSEIfaceCfg* mIfaceCFG;    /**< Points to previous defined/given Cfg object, the caller manages this */
    MSEHAL_t*    hal;          /**< The configured HAL for the interface */
    MSEHAL_t*    phy;          /**< When a HAL is not a "native" hal it needs a physical layer to be associated with it */
    void*         hal_data;     /**< Pointer to HAL specific context/data */
} mse_iface_t;

MSE_STATUS initMSEIface(MSEIfaceCfg *cfg, MSEIface ca_iface);
MSEIface newMSEIface(MSEIfaceCfg *cfg);
MSE_STATUS releaseMSEIface(MSEIface ca_iface);
void deleteMSEIface(MSEIface *ca_iface);

// IFace methods
MSE_STATUS ioinit(MSEIface ca_iface);
MSE_STATUS iosend(MSEIface ca_iface, uint8_t word_address, uint8_t *txdata, int txlength);
MSE_STATUS ioreceive(MSEIface ca_iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength);
MSE_STATUS iocontrol(MSEIface ca_iface, uint8_t option, void* param, size_t paramlen);
MSE_STATUS iowake(MSEIface ca_iface);
MSE_STATUS ioidle(MSEIface ca_iface);
MSE_STATUS iosleep(MSEIface ca_iface);

// accessors
MSEIfaceCfg * iogetifacecfg(MSEIface ca_iface);
void* iogetifacehaldat(MSEIface ca_iface);

/* Utilities */
bool mse_iface_is_kit(MSEIface ca_iface);
bool mse_iface_is_swi(MSEIface ca_iface);
int mse_iface_get_retries(MSEIface ca_iface);
uint16_t mse_iface_get_wake_delay(MSEIface ca_iface);

#ifdef __cplusplus
}
#endif
/*lint -flb*/
/** @} */
#endif

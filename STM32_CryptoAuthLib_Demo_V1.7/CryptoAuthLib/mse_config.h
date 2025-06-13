/* Auto-generated config file mse_config.h */
#ifndef MSE_CONFIG_H
#define MSE_CONFIG_H

/* Included HALS */
#if defined(USE_HAL_DRIVER)
#include "stm32f1xx_hal.h"
#endif /* USE_HAL_DRIVER   */                                                                                            \

#define MSE_HAL_I2C



/** Define to enable compatibility with legacy HALs
   (HALs with embedded device logic)*/


/* Included device support */


/** Device Override - Library Assumes MOD8A support in checks */
#define MSE_MOD8A_SUPPORT



/* \brief How long to wait after an initial wake failure for the POST to
 *         complete.
 * If Power-on self test (POST) is enabled, the self test will run on waking
 * from sleep or during power-on, which delays the wake reply.
 */
#ifndef MSE_POST_DELAY_MSEC
#define MSE_POST_DELAY_MSEC 25
#endif

/***************** Diagnostic & Test Configuration Section *****************/

/** Enable debug messages */
// #cmakedefine MSE_PRINTF

/** Enable to build in test hooks */
// #cmakedefine MSE_TESTS_ENABLED

/******************** Features Configuration Section ***********************/


/** Additional Runtime Configuration */
// #cmakedefine MSE_LIBRARY_CONF  "@MSE_LIBRARY_CONF@"

/** Define to build mse_ functions rather that defining them as macros */
// #cmakedefine MSE_USE_MSE_FUNCTIONS

/** Define to enable older API forms that have been replaced */
// #cmakedefine MSE_ENABLE_DEPRECATED


/******************** Platform Configuration Section ***********************/

/** Define if the library is not to use malloc/free */
#define MSE_NO_HEAP

/** Define platform malloc/free */
// #cmakedefine MSE_PLATFORM_MALLOC    @MSE_PLATFORM_MALLOC@
// #cmakedefine MSE_PLATFORM_FREE      @MSE_PLATFORM_FREE@

#define mse_delay_ms   HAL_Delay
#define mse_delay_us   hal_delay_us

#endif // MSE_CONFIG_H

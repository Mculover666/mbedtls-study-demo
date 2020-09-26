/**
 * @brief   Minimal configuration for GCM Function
 * @author  mculover666
 * @date    2020/09/26
*/

#ifndef _MBEDTLS_CONFIG_GCM_H_
#define _MBEDTLS_CONFIG_GCM_H_

/* System support */
#define MBEDTLS_HAVE_ASM
//#define MBEDTLS_HAVE_TIME

/* mbed feature support */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* mbed modules */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C

#include "mbedtls/check_config.h"

#endif /* _MBEDTLS_CONFIG_GCM_H_ */

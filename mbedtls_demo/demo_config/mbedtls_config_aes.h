/**
 * @brief   Minimal configuration for AES Function
 * @author  mculover666
 * @date    2020/09/23
*/

#ifndef _MBEDTLS_CONFIG_AES_H_
#define _MBEDTLS_CONFIG_AES_H_

/* System support */
#define MBEDTLS_HAVE_ASM
//#define MBEDTLS_HAVE_TIME

/* mbed feature support */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* mbed modules */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
//#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_C

#include "mbedtls/check_config.h"

#endif /* _MBEDTLS_CONFIG_CTR_DRBG_H_ */

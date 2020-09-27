/**
 * @brief   Minimal configuration for RSA Function
 * @author  mculover666
 * @date    2020/09/27
*/

#ifndef _MBEDTLS_CONFIG_RSA_H_
#define _MBEDTLS_CONFIG_RSA_H_

/* System support */
#define MBEDTLS_HAVE_ASM
//#define MBEDTLS_HAVE_TIME

/* mbed feature support */
#define MBEDTLS_ENTROPY_HARDWARE_ALT
//#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* mbed modules */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_GENPRIME
#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V21

#include "mbedtls/check_config.h"

#endif /* _MBEDTLS_CONFIG_RSA_H_ */

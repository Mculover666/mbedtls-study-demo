/**
 * @brief   Minimal configuration for SHAX Function
 * @author  mculover666
 * @date    2020/09/22
*/

#ifndef _MBEDTLS_CONFIG_SHA_X_H_
#define _MBEDTLS_CONFIG_SHA_X_H_

/* System support */
#define MBEDTLS_HAVE_ASM
//#define MBEDTLS_HAVE_TIME

/* mbed feature support */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* mbed modules */
//#define MBEDTLS_MD2_C
//#define MBEDTLS_MD4_C
//#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
//#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
//#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C

/* enable generic message digest wrappers */
#define MBEDTLS_MD_C

#include "mbedtls/check_config.h"

#endif /* _MBEDTLS_CONFIG_SHA_X_H_ */

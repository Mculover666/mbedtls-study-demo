/**
 * @brief   Minimal configuration for X509 Function
 * @author  mculover666
 * @date    2020/10/04
*/

#ifndef _MBEDTLS_CONFIG_X509_H_
#define _MBEDTLS_CONFIG_X509_H_

/* System support */
#define MBEDTLS_HAVE_ASM
//#define MBEDTLS_HAVE_TIME

/* mbed feature support */
#define MBEDTLS_ENTROPY_HARDWARE_ALT
//#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* mbed modules */
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_X509_CRT_PARSE_C

#include "mbedtls/check_config.h"

#endif /* _MBEDTLS_CONFIG_X509_H_ */

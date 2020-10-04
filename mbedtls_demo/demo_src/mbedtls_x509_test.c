/**
 * @brief   X509 Function demo
 * @author  mculover666
 * @date    2020/10/04
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/x509_crt.h"
#include "baidu_certs.h"

char buf[4096];

int mbedtls_x509_test(void)
{
    int ret;
   
    mbedtls_x509_crt cert, cacert;

    /* 1. init structure */
    mbedtls_x509_crt_init(&cert);
    mbedtls_x509_crt_init(&cacert);

    /* 2. Parser cacert */
    printf( "\n  . Parse cacert..." );
    
    ret = mbedtls_x509_crt_parse(&cacert, (unsigned char *)baidu_ca_cert, sizeof(baidu_ca_cert));
     if(ret != 0) {
        printf( " failed\n  ! mbedtls_x509_crt_parse cacert returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* 2. Cacert parser result */
    printf( "\n  . Cacert parser result..." );
    
    ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", &cacert);
    if (ret < 0) {
        printf("fail! mbedtls_x509_crt_info return %d(-0x%04x)\n", ret, -ret);
        goto exit;
    } else {
        buf[ret] = '\0';
        printf("ok!\r\n");
        printf("crt info has %d chars\r\n", strlen(buf));    
        printf("%s\r\n", buf);
    }
    
    exit:  
    /* 3. release structure */
    mbedtls_x509_crt_free(&cert);
    mbedtls_x509_crt_free(&cacert);
    
    return ret;
}

#endif /* MBEDTLS_RSA_C */

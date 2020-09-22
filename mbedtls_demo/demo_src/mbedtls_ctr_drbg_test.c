/**
 * @brief   CTR_DRBG Function demo
 * @author  mculover666
 * @date    2020/09/22
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CTR_DRBG_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

int mbedtls_ctr_drbg_test(void)
{
    int ret;
    uint8_t data_buf[10];
   
    const char *pers = "crbg_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* 1. init entropy structure */
    mbedtls_entropy_init(&entropy);
    
    /* 2. init ctr drbg structure */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    /* 3. update seed with we own interface ported */
    printf( "\n  . Seeding the random number generator..." );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }

    printf( " ok\n" );

    /* 4. generate random data */
    printf( "\n  . generate random data..." );
    
    
    if ( ( ret = mbedtls_ctr_drbg_random(&ctr_drbg, data_buf, sizeof(data_buf) ) ) != 0) {
        printf( " failed\n  ! mbedtls_ctr_drbg_random returned %d\n", ret );
        goto exit;
    }
    printf( " ok\n" );
    
    printf("random data:[");
    for (int i = 0; i < sizeof(data_buf); i++) {
        printf("%02x ", data_buf[i]);
    }
    printf("]\r\n");
    
    exit:
    
    /* 5. release ctr drbg structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    
    /* 6. release entropy structure*/
    mbedtls_entropy_free(&entropy);
    
    return ret;
}

#endif /* MBEDTLS_CTR_DRBG_C */

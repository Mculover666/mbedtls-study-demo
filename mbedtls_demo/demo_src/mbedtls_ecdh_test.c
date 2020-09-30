/**
 * @brief   EDCH Function demo
 * @author  mculover666
 * @date    2020/09/30
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDH_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

#define GENERATOR   "2"
#define T_P          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695" \
                     "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"\
                     "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
                     "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"\
                     "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"\
                     "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
                     "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"\
                     "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"

uint8_t buf[65];

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;
    
    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ", 
                           buf[i], 
                           i == len - 1 ? "\r\n" : "");
    }
}

int mbedtls_ecdh_test(void)
{
    int ret;
    size_t olen;
   
    const char *pers = "ecdh_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_point client_pub, server_pub;
    mbedtls_ecp_group grp;
    mbedtls_mpi client_secret, server_secret;
    mbedtls_mpi client_pri, server_pri;
        
    /* 1. init structure */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&client_secret);
    mbedtls_mpi_init(&server_secret);
    mbedtls_mpi_init(&client_pri);
    mbedtls_mpi_init(&server_pri);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&client_pub);
    mbedtls_ecp_point_init(&server_pub);
    
    /* 2. update seed with we own interface ported */
    printf( "\n  . Seeding the random number generator..." );
    
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );

    /* 3.  select ecp group SECP256R1 */
    printf("\n  . Select ecp group SECP256R1...");
    
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecp_group_load returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    
    printf("ok\r\n");
    
    /* 4. Client generate public parameter */
    printf("\n  . Client Generate public parameter...");
    
    ret = mbedtls_ecdh_gen_public(&grp, &client_pri, &client_pub, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show public parameter */
    mbedtls_ecp_point_write_binary(&grp, &client_pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, sizeof(buf));
    dump_buf(buf, olen);
    
    /* 5. Client generate public parameter */
    printf("\n  . Server Generate public parameter...");
    
    ret = mbedtls_ecdh_gen_public(&grp, &server_pri, &server_pub, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show public parameter */
    mbedtls_ecp_point_write_binary(&grp, &server_pub, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, sizeof(buf));
    dump_buf(buf, olen);
    
    /* 6. Calc shared secret */
    printf("\n  . Client Calc shared secret...");
    
    ret = mbedtls_ecdh_compute_shared(&grp, &client_secret, &server_pub, &client_pri, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show public parameter */
    mbedtls_mpi_write_binary(&client_secret, buf, sizeof(buf));
    dump_buf(buf, olen);
    
    /* 7. Server Calc shared secret */
    printf("\n  . Server Calc shared secret...");
    
    ret = mbedtls_ecdh_compute_shared(&grp, &server_secret, &client_pub, &server_pri, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show public parameter */
    mbedtls_mpi_write_binary(&server_secret, buf, sizeof(buf));
    dump_buf(buf, olen);
    
    /* 8. mpi compare */
    ret = mbedtls_mpi_cmp_mpi(&server_secret, &client_secret);
    printf("compare result: %d\r\n", ret);
    
    exit:
    
    /* 10. release structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&client_secret);
    mbedtls_mpi_free(&server_secret);
    mbedtls_mpi_free(&client_pri);
    mbedtls_mpi_free(&server_pri);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&client_pub);
    mbedtls_ecp_point_free(&server_pub);
    
    return ret;
}

#endif /* MBEDTLS_DHM_C */

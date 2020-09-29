/**
 * @brief   DHM Function demo
 * @author  mculover666
 * @date    2020/09/28
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DHM_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/dhm.h"

#define GENERATOR   "2"
#define T_P          "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695" \
                     "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"\
                     "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"\
                     "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"\
                     "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"\
                     "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"\
                     "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"\
                     "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"

uint8_t server_pub[256];
uint8_t client_pub[256];
uint8_t server_secret[256];
uint8_t client_secret[256];

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;
    
    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ", 
                           buf[i], 
                           i == len - 1 ? "\r\n" : "");
    }
}

int mbedtls_dhm_test(void)
{
    int ret;
    size_t olen;
   
    const char *pers = "dhm_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_dhm_context dhm_server, dhm_client;

    /* 1. init structure */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_dhm_init(&dhm_server);
    mbedtls_dhm_init(&dhm_client);
    
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

    /* 3. genetate 2048 bit prime(G, P) */
    printf("\n  . Genetate 2048 bit prime(G, P)...");
    
    mbedtls_mpi_read_string(&dhm_server.P, 16, T_P);
    mbedtls_mpi_read_string(&dhm_server.G, 10, GENERATOR);
    dhm_server.len = mbedtls_mpi_size(&dhm_server.P);
    
    mbedtls_mpi_read_string(&dhm_client.P, 16, T_P);
    mbedtls_mpi_read_string(&dhm_client.G, 10, GENERATOR);
    dhm_client.len = mbedtls_mpi_size(&dhm_client.P);
    
    printf("ok\r\n");
    
    /* 4. Server create a DHM key pair */
    printf("\n  . Server creates a DHM key pair...");
    
    ret = mbedtls_dhm_make_public(&dhm_server, 256, server_pub, sizeof(server_pub), mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_dhm_make_public returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    dump_buf(server_pub, sizeof(server_pub));
    
    /* 5. Client creates a DHM key pair */
    printf("\n  . Client create a DHM key pair...");
    
    ret = mbedtls_dhm_make_public(&dhm_client, 256, client_pub, sizeof(client_pub), mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_dhm_make_public returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    dump_buf(client_pub, sizeof(client_pub));
    
    /* 6. Server Read public key pair */
    printf("\n  . Server Read public key pair...");
    
    ret = mbedtls_dhm_read_public(&dhm_server, client_pub, sizeof(client_pub));
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_dhm_read_public returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* 7. Client Read public key pair */
    printf("\n  . Client Read public key pair...");
    
    ret = mbedtls_dhm_read_public(&dhm_client, server_pub, sizeof(server_pub));
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_dhm_read_public returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" ); 
    
    /* 8. calc the shared secret */
    printf("\n  . Server calc the shared secret...");
    
    ret = mbedtls_dhm_calc_secret(&dhm_server, server_secret, sizeof(server_secret), &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_dhm_calc_secret returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" ); 
    dump_buf(server_secret, sizeof(server_secret));
    
    /* 9. calc the shared secret */
    printf("\n  . Client calc the shared secret...");
    
    ret = mbedtls_dhm_calc_secret(&dhm_client, client_secret, sizeof(client_secret), &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_dhm_calc_secret returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" ); 
    dump_buf(client_secret, sizeof(client_secret));
    
    exit:
    
    /* 10. release structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_dhm_free(&dhm_server);
    mbedtls_dhm_free(&dhm_client);
    
    return ret;
}

#endif /* MBEDTLS_DHM_C */

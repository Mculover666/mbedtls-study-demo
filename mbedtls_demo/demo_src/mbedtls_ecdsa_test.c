/**
 * @brief   ECDSA Function demo
 * @author  mculover666
 * @date    2020/10/03
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECDSA_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"

uint8_t buf[97];

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;
    
    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ", 
                           buf[i], 
                           i == len - 1 ? "\r\n" : "");
    }
}

int mbedtls_ecdsa_test(void)
{
    int ret;
    size_t qlen, dlen;
    size_t rlen, slen;
    uint8_t hash[32];
   
    const char *msg  = "HelloWorld";
    const char *pers = "ecdsa_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi r, s;
    mbedtls_ecdsa_context ctx;
    mbedtls_md_context_t md_ctx;
        
    /* 1. init structure */
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    
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
    
    /* 3. hash message */
    printf( "\n  . Hash message..." );
    
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (uint8_t *)msg, strlen(msg), hash);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_md returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show hash */
    dump_buf(hash, sizeof(hash));
    
    /* 4. generate keypair */
    printf( "\n  . Generate ecdsa keypair..." );
    
    ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdsa_genkey returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show keypair */
    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &qlen, buf, sizeof(buf));
    dlen = mbedtls_mpi_size(&ctx.d);
    mbedtls_mpi_write_binary(&ctx.d, buf + qlen, dlen);
    dump_buf(buf, qlen + dlen);
    
    /* 5. ecdsa sign */
    printf( "\n  . ECDSA sign..." );
    
    ret = mbedtls_ecdsa_sign(&ctx.grp, &r, &s, &ctx.d, hash, sizeof(hash), mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdsa_sign returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );
    
    /* show sign */
    rlen = mbedtls_mpi_size(&r);
    slen = mbedtls_mpi_size(&s);
    mbedtls_mpi_write_binary(&r, buf, rlen);
    mbedtls_mpi_write_binary(&s, buf + rlen, slen);
    dump_buf(buf, rlen + slen);
    
    /* 6. ecdsa verify */
    printf( "\n  . ECDSA verify..." );
    
    ret = mbedtls_ecdsa_verify(&ctx.grp, hash, sizeof(hash), &ctx.Q, &r, &s);
    if(ret != 0) {
        printf( " failed\n  ! mbedtls_ecdsa_verify returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf( " ok\n" );

    exit:
    
    /* 7. release structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_md_free(&md_ctx);
    mbedtls_ecdsa_free(&ctx);
    
    return ret;
}

#endif /* MBEDTLS_DHM_C */

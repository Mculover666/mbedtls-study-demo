/**
 * @brief   GCM Function demo
 * @author  mculover666
 * @date    2020/09/26
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_GCM_C)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "mbedtls/cipher.h"

/* source context */
static const char input[16] = {
    0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7, 
    0x3d, 0x9a, 0x5c, 0xd4, 0x32, 0x10, 0x30, 0x69
};
/* Private Key */
static uint8_t key[16] = {
    0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37,
    0xde, 0x6a, 0xe0, 0xe1, 0xcb, 0x7c, 0x42, 0x3c
};

/* Intialization Vector */
static uint8_t iv[12] = {
    0xb3, 0xd8, 0xcc, 0x01, 
    0x7c, 0xbb, 0x89, 0xb3,
    0x9e, 0x0f, 0x67, 0xe2
};

/* The additional data to authenticate */
uint8_t add[16] = {
    0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84, 
    0xe0, 0x09, 0x2d, 0x3e, 0x44, 0x8e, 0xda, 0x5f
};

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;
    
    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ", 
                           buf[i], 
                           i == len - 1 ? "\r\n" : "");
    }
}

int gcm_test(mbedtls_cipher_type_t cipher_type)
{
    int ret;
    size_t len;
    int olen = 0;
    uint8_t output_buf[16];
    uint8_t tag_buf[16];
    uint8_t decrypt_out_buf[16];
    
    
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info;
    
    /* 1. init cipher structuer */
    mbedtls_cipher_init(&ctx);
    
    /* 2. get info structuer from type */
    info = mbedtls_cipher_info_from_type(cipher_type);
    
    /* 3. setup cipher structuer */
    ret = mbedtls_cipher_setup(&ctx, info);
    if (ret != 0) {
        goto exit;
    }
    
    /* 4. set encrypt key */
    ret = mbedtls_cipher_setkey(&ctx, key, sizeof(key) * 8, MBEDTLS_ENCRYPT);
    if (ret != 0) {
        goto exit;
    }
    
    /* 5. auth encrypt */
    ret = mbedtls_cipher_auth_encrypt(&ctx, 
                                      iv, sizeof(iv), add, sizeof(add), 
                                      (unsigned char *)input, sizeof(input), 
                                      output_buf, &len, tag_buf, sizeof(tag_buf));
    if (ret != 0) {
        goto exit;
    }
    olen += len;
    
    /* show */
    printf("cipher name:%s block size is:%d\r\n", mbedtls_cipher_get_name(&ctx), mbedtls_cipher_get_block_size(&ctx));
    printf("\r\noutput_buf:\r\n");
    dump_buf((uint8_t *)output_buf, olen);
    printf("\r\ntag_buf:\r\n");
    dump_buf(tag_buf, sizeof(tag_buf));
    
    /* 6. set decrypt key */
    ret = mbedtls_cipher_setkey(&ctx, key, sizeof(key) * 8, MBEDTLS_DECRYPT);
    if (ret != 0) {
        goto exit;
    }
    
    /* 7. auth decrypt */
    olen = 0;
    len  = 0;
    ret = mbedtls_cipher_auth_decrypt(&ctx, 
                                      iv, sizeof(iv), add, sizeof(add), 
                                      (unsigned char *)output_buf, sizeof(output_buf), 
                                      decrypt_out_buf, &len, tag_buf, sizeof(tag_buf));
    if (ret != 0) {
        goto exit;
    }
    olen += len;
    
    /* show */
    printf("cipher name:%s block size is:%d\r\n", mbedtls_cipher_get_name(&ctx), mbedtls_cipher_get_block_size(&ctx));
    printf("\r\ndecrypt_out_buf:\r\n");
    dump_buf((uint8_t *)decrypt_out_buf, olen);
    printf("\r\ntag_buf:\r\n");
    dump_buf(tag_buf, sizeof(tag_buf));
    
    exit:
    /* 8. free cipher structure */
    mbedtls_cipher_free(&ctx);
    
    return ret;
}

#endif /* MBEDTLS_CIPHER_C */

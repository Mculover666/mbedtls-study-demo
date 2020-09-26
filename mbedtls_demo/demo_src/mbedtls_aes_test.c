/**
 * @brief   AES Function demo
 * @author  mculover666
 * @date    2020/09/23
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CIPHER_C)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "mbedtls/cipher.h"

/* Private Key */
uint8_t key[16] = {
    0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
    0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06
};

/* Intialization Vector */
uint8_t iv[16] = {
    0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
    0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41
};

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;
    
    printf("buf:");
    
    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ", 
                           buf[i], 
                           i == len - 1 ? "\r\n" : "");
    }
}

int aes_test(mbedtls_cipher_type_t cipher_type)
{
    int ret;
    size_t len;
    int olen = 0;
    uint8_t output_buf[64];
    const char input[] = "mculover666 is learning";
    //const char input[] = {'m', 'c', 'u', 'l', 'o', 'v', 'e', 'r', '6', '6', '6', ' ', 'i', 's'};
    
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
    
    /* 4. set key */
    ret = mbedtls_cipher_setkey(&ctx, key, sizeof(key) * 8, MBEDTLS_ENCRYPT);
    if (ret != 0) {
        goto exit;
    }
    
    /* 5. set iv */
    ret = mbedtls_cipher_set_iv(&ctx, iv, sizeof(iv));
    if (ret != 0) {
        goto exit;
    }
    
    /* 6. update cipher */
    ret = mbedtls_cipher_update(&ctx, (unsigned char *)input, strlen(input), output_buf, &len);
    if (ret != 0) {
        goto exit;
    }
    olen += len;
    
    /* 7. finish cipher */
    ret = mbedtls_cipher_finish(&ctx, output_buf, &len);
    if (ret != 0) {
        goto exit;
    }
    olen += len;
    
    /* show */
    printf("\r\nsource_context:%s\r\n", input);
    dump_buf((uint8_t *)input, strlen(input));
    printf("cipher name:%s block size is:%d\r\n", mbedtls_cipher_get_name(&ctx), mbedtls_cipher_get_block_size(&ctx));
    dump_buf(output_buf, olen);
    
    exit:
    /* 8. free cipher structure */
    mbedtls_cipher_free(&ctx);
    
    return ret;
}

#endif /* MBEDTLS_CIPHER_C */

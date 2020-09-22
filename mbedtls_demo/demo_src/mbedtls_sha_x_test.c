/**
 * @brief   SHAX Function demo
 * @author  mculover666
 * @date    2020/09/22
*/

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/md.h"

int mbedtls_shax_test(mbedtls_md_type_t md_type)
{
    int len, i;
    int ret;
    const char *message = "mculover666";
    unsigned char digest[32];
    
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;

    printf("message is:%s\r\n", message);

    /* 1. init mbedtls_md_context_t structure */
    mbedtls_md_init(&ctx);
    
    /* 2. get md info structure pointer */
    info = mbedtls_md_info_from_type(md_type);
    
    /* 3. setup md info structure */
    ret = mbedtls_md_setup(&ctx, info, 0);
    if (ret != 0) {
        goto exit;
    }
    
    /* 4. start */
    ret = mbedtls_md_starts(&ctx);
     if (ret != 0) {
        goto exit;
    }
     
    /* 5. update */
    ret = mbedtls_md_update(&ctx, (unsigned char *)message, strlen(message));
    if (ret != 0) {
        goto exit;
    }
     
    /* 6. finish */
    ret = mbedtls_md_finish(&ctx, digest);
    if (ret != 0) {
        goto exit;
    }
    
    /* show */
    printf("%s digest context is:[", mbedtls_md_get_name(info));
    len= mbedtls_md_get_size(info);
    for (i = 0; i < len; i++) {
      printf("%02x", digest[i]);
    }
    printf("]\r\n");

    exit:
    /* 7. free */
    mbedtls_md_free(&ctx);
    
    return ret;
}

#endif /* MBEDTLS_MD_C */

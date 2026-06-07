#include <openssl/cmac.h>
#include <openssl/hmac.h>

void test_legacy_mac() {
    HMAC_CTX* hctx = NULL;
    HMAC_CTX* hctx2 = NULL;
    CMAC_CTX* cctx = NULL;
    unsigned char key[32];
    unsigned char data[64];
    unsigned char out[32];
    unsigned int outlen = 0;
    size_t outlen2 = 0;

    HMAC_CTX_new();
    HMAC_CTX_reset(hctx);
    HMAC_CTX_copy(hctx, hctx2);
    HMAC_Init_ex(hctx, key, 32, NULL, NULL);
    HMAC_Init(hctx, key, 32, NULL);
    HMAC_Update(hctx, data, 64);
    HMAC_Final(hctx, out, &outlen);
    HMAC(NULL, key, 32, data, 64, out, &outlen);

    CMAC_CTX_new();
    CMAC_Init(cctx, key, 32, NULL, NULL);
    CMAC_Update(cctx, data, 64);
    CMAC_Final(cctx, out, &outlen2);
    CMAC_resume(cctx);
}

#include <sodium.h>

void example() {
    unsigned char out[64];
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char ciphertext[128];
    unsigned char ad[16];

    crypto_generichash(out, 64, (const unsigned char *)"data", 4, NULL, 0);
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, NULL, (const unsigned char *)"plaintext", 9, ad, 16, NULL, nonce, key);
}

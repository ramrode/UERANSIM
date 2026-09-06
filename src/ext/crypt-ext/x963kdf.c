/* X963kdf.c -- X9.63 Key Derivation Function
2023-03-22 : Stephane G. : Public domain */

#include "x963kdf.h"

#include <string.h>

void x963kdf_ex(unsigned char *output, const unsigned char *sharedSecret, size_t sharedSecretLen,
                const unsigned char *sharedInfo, size_t sharedInfoLen, size_t keySize)
{
    size_t maxCount = (keySize + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    size_t count;

    for (count = 1; count <= maxCount; count++)
    {
        sha256_t ss;
        uint8_t hash[SHA256_DIGEST_SIZE];
        uint8_t counterBuf[4];
        size_t offset = (count - 1) * SHA256_DIGEST_SIZE;
        size_t remaining = keySize - offset;
        size_t toCopy = remaining < SHA256_DIGEST_SIZE ? remaining : SHA256_DIGEST_SIZE;

        counterBuf[0] = (uint8_t)((count >> 24) & 0xff);
        counterBuf[1] = (uint8_t)((count >> 16) & 0xff);
        counterBuf[2] = (uint8_t)((count >> 8) & 0xff);
        counterBuf[3] = (uint8_t)(count & 0xff);

        sha256_init(&ss);
        sha256_update(&ss, sharedSecret, sharedSecretLen);
        sha256_update(&ss, counterBuf, 4);
        sha256_update(&ss, sharedInfo, sharedInfoLen);
        sha256_final(&ss, hash);

        memcpy(output + offset, hash, toCopy);
    }
}

void x963kdf(unsigned char *output, const unsigned char *sharedSecret, const unsigned char *sharedInfo,
             size_t keySize)
{
    x963kdf_ex(output, sharedSecret, SHA256_DIGEST_SIZE, sharedInfo, SHA256_DIGEST_SIZE, keySize);
}

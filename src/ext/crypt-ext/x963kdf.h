/* X963kdf.h -- X9.63 Key Derivation Function
2023-03-22 : Stephane G. : Public domain */

#pragma once

#include "sha256.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ANSI-X9.63 KDF with SHA-256, for callers that need a shared info other than 32 bytes.
       SUCI Profile B passes the 33 byte compressed ephemeral public key. */
    void x963kdf_ex(unsigned char *output, const unsigned char *sharedSecret, size_t sharedSecretLen,
                    const unsigned char *sharedInfo, size_t sharedInfoLen, size_t keySize);

    /* Shorthand for the 32 byte shared secret and shared info that SUCI Profile A uses. */
    void x963kdf(unsigned char *output, const unsigned char *sharedSecret, const unsigned char *sharedInfo,
                 size_t keySize);

#ifdef __cplusplus
}
#endif

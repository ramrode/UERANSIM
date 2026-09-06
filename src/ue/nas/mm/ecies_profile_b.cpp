//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "ecies_profile_b.hpp"

#include <cmath>
#include <cstring>
#include <utils/octet_string.hpp>

extern "C"
{
#include <ext/crypt-ext/aes.h>
#include <ext/crypt-ext/hmac-sha256.h>
#include <ext/crypt-ext/sha256.h>
#include <ext/micro-ecc/uECC.h>
}

// ANSI-X9.63 KDF with variable-length sharedInfo (the vendored x963kdf hardcodes 32).
static void x963kdf_profileB(uint8_t *output, const uint8_t *sharedSecret, size_t sharedSecretLen,
                             const uint8_t *sharedInfo, size_t sharedInfoLen, size_t keySize)
{
    size_t maxCount = static_cast<size_t>(std::ceil(static_cast<double>(keySize) / SHA256_DIGEST_SIZE));
    uint8_t counterBuf[4];

    for (size_t count = 1; count <= maxCount; count++)
    {
        sha256_t ss;
        uint8_t hash[SHA256_DIGEST_SIZE];

        sha256_init(&ss);
        sha256_update(&ss, sharedSecret, sharedSecretLen);
        counterBuf[0] = static_cast<uint8_t>((count >> 24) & 0xff);
        counterBuf[1] = static_cast<uint8_t>((count >> 16) & 0xff);
        counterBuf[2] = static_cast<uint8_t>((count >> 8) & 0xff);
        counterBuf[3] = static_cast<uint8_t>((count) & 0xff);
        sha256_update(&ss, counterBuf, 4);
        sha256_update(&ss, sharedInfo, sharedInfoLen);
        sha256_final(&ss, hash);

        size_t offset = (count - 1) * SHA256_DIGEST_SIZE;
        size_t toCopy = (offset + SHA256_DIGEST_SIZE <= keySize) ? SHA256_DIGEST_SIZE : (keySize - offset);
        std::memcpy(output + offset, hash, toCopy);
    }
}

// Order of the secp256r1 group (big-endian).
static const uint8_t SECP256R1_ORDER[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
                                            0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

bool isValidProfileBPrivateKey(const OctetString &privKey)
{
    if (privKey.length() != 32)
        return false;

    // Both operands are big-endian, so memcmp is an unsigned numeric comparison.
    if (std::memcmp(privKey.data(), SECP256R1_ORDER, 32) >= 0)
        return false;

    for (int i = 0; i < 32; i++)
    {
        if (privKey.data()[i] != 0)
            return true;
    }
    return false;
}

std::string eciesProfileB(const OctetString &plaintextMsin, const OctetString &hnPublicKey,
                          const OctetString &ephemeralPrivKey)
{
    uECC_Curve curve = uECC_secp256r1();

    // --- 1. Normalize hnPublicKey to 64-byte native (X||Y) ---
    uint8_t hnNative64[64];
    int hnLen = hnPublicKey.length();

    if (hnLen == 33)
    {
        uint8_t prefix = hnPublicKey.data()[0];
        if (prefix != 0x02 && prefix != 0x03)
            return {};
        uECC_decompress(hnPublicKey.data(), hnNative64, curve);
    }
    else if (hnLen == 65)
    {
        if (hnPublicKey.data()[0] != 0x04)
            return {};
        std::memcpy(hnNative64, hnPublicKey.data() + 1, 64);
    }
    else if (hnLen == 64)
    {
        std::memcpy(hnNative64, hnPublicKey.data(), 64);
    }
    else
    {
        return {};
    }

    // uECC_shared_secret does not validate the peer point, and uECC_decompress returns garbage
    // for an x that is not on the curve. Validate every input form here, otherwise a mistyped
    // key would yield a well-formed SUCI that the home network cannot decrypt.
    if (!uECC_valid_public_key(hnNative64, curve))
        return {};

    // --- 2. Derive ephemeral PUBLIC key ---
    if (ephemeralPrivKey.length() != 32)
        return {};

    uint8_t ephPub64[64];
    if (!uECC_compute_public_key(ephemeralPrivKey.data(), ephPub64, curve))
        return {};

    uint8_t compressedEphPub[33];
    uECC_compress(ephPub64, compressedEphPub, curve);

    // --- 3. ECDH ---
    uint8_t sharedX[32];
    if (!uECC_shared_secret(hnNative64, ephemeralPrivKey.data(), sharedX, curve))
        return {};

    // --- 4. KDF: X9.63 KDF with sharedInfo = compressedEphPub (33 bytes) ---
    uint8_t derivedKey[64];
    x963kdf_profileB(derivedKey, sharedX, 32, compressedEphPub, 33, 64);

    uint8_t *aesKey = derivedKey;      // [0, 16)
    uint8_t *iv = derivedKey + 16;     // [16, 32)
    uint8_t *macKey = derivedKey + 32; // [32, 64)

    // --- 5. Cipher: AES-128-CTR ---
    int msinLen = plaintextMsin.length();
    std::vector<uint8_t> ciphertext(plaintextMsin.data(), plaintextMsin.data() + msinLen);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, aesKey);
    AES_ctx_set_iv(&ctx, iv);
    AES_CTR_xcrypt_buffer(&ctx, ciphertext.data(), static_cast<uint32_t>(msinLen));

    // --- 6. MAC: HMAC-SHA256 over ciphertext, truncate to 8 bytes ---
    uint8_t fullMac[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(fullMac, ciphertext.data(), static_cast<size_t>(msinLen), macKey, 32);
    uint8_t macTag[8];
    std::memcpy(macTag, fullMac, 8);

    // --- 7. Assemble compressedEphPub(33) || ciphertext || macTag(8) → hex ---
    OctetString output;
    output.append(OctetString::FromArray(compressedEphPub, 33));
    output.append(OctetString::FromArray(ciphertext.data(), static_cast<size_t>(msinLen)));
    output.append(OctetString::FromArray(macTag, 8));

    return output.toHexString();
}

//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALI GUNGOR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "test_util.hpp"

#include <cstdint>
#include <random>
#include <ue/nas/mm/ecies_profile_b.hpp>

void run_ecies_profile_b_structural_test()
{
    // Same home network public key as the C.4 vector (uncompressed, 65 bytes)
    OctetString hnPubKey = OctetString::FromHex("0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1"
                                                "5A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4");

    // Plaintext MSIN (BCD encoded, 5 bytes), the same length as the C.4 vector
    OctetString plaintextMsin = OctetString::FromHex("0000000010");
    const int expectedHexLen = (33 + 5 + 8) * 2;

    // Fixed seeds rather than srand(time(nullptr)). The point of this test is that any ephemeral
    // key produces a well formed scheme output, and a failure has to be reproducible to be useful.
    for (uint32_t seed : {0x5EEDu, 0xC0FFEEu, 0x1234ABCDu})
    {
        std::mt19937 rng{seed};
        uint8_t privKey[32];
        for (uint8_t &b : privKey)
            b = static_cast<uint8_t>(rng() & 0xFF);

        OctetString ephPrivKey = OctetString::FromArray(privKey, sizeof(privKey));
        TEST_ASSERT(isValidProfileBPrivateKey(ephPrivKey), "structural: ephemeral key is in [1, n-1]");

        std::string result = eciesProfileB(plaintextMsin, hnPubKey, ephPrivKey);

        TEST_ASSERT(!result.empty(), "structural: eciesProfileB produces output");
        TEST_ASSERT_EQ(static_cast<int>(result.size()), expectedHexLen);

        std::string prefix = result.substr(0, 2);
        TEST_ASSERT(prefix == "02" || prefix == "03", "structural: ephemeral pubkey prefix is 02 or 03");
    }
}

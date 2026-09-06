//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALI GUNGOR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "test_util.hpp"
#include <ue/nas/mm/ecies_profile_b.hpp>

// secp256r1 group order n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
// A private key is usable only when it lies in [1, n-1].
void run_priv_key_range_tests()
{
    // Smallest valid scalar
    TEST_ASSERT(isValidProfileBPrivateKey(
                    OctetString::FromHex("0000000000000000000000000000000000000000000000000000000000000001")),
                "priv key range: 1 is valid");

    // Largest valid scalar, n-1
    TEST_ASSERT(isValidProfileBPrivateKey(
                    OctetString::FromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550")),
                "priv key range: n-1 is valid");

    // The TS 33.501 C.4 ephemeral private key
    TEST_ASSERT(isValidProfileBPrivateKey(
                    OctetString::FromHex("99798858A1DC6A2C68637149A4B1DBFD1FDFF5ADDD62A2142F06699ED7602529")),
                "priv key range: C.4 ephemeral key is valid");

    // Zero is not a valid scalar
    TEST_ASSERT(!isValidProfileBPrivateKey(
                    OctetString::FromHex("0000000000000000000000000000000000000000000000000000000000000000")),
                "priv key range: zero is rejected");

    // n itself is out of range
    TEST_ASSERT(!isValidProfileBPrivateKey(
                    OctetString::FromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")),
                "priv key range: n is rejected");

    // n+1 is out of range
    TEST_ASSERT(!isValidProfileBPrivateKey(
                    OctetString::FromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552")),
                "priv key range: n+1 is rejected");

    // All-ones is far above n
    TEST_ASSERT(!isValidProfileBPrivateKey(
                    OctetString::FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
                "priv key range: all-ones is rejected");

    // Wrong lengths are rejected regardless of value
    TEST_ASSERT(!isValidProfileBPrivateKey(
                    OctetString::FromHex("00000000000000000000000000000000000000000000000000000000000001")),
                "priv key range: 31-byte key is rejected");
    TEST_ASSERT(!isValidProfileBPrivateKey(
                    OctetString::FromHex("000000000000000000000000000000000000000000000000000000000000000101")),
                "priv key range: 33-byte key is rejected");
}

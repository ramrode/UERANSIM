//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "test_util.hpp"

extern void run_micro_ecc_tests();
extern void run_x963kdf_tests();
extern void run_ecies_profile_b_vector_test();
extern void run_ecies_profile_b_structural_test();
extern void run_ecies_soft_fail_tests();
extern void run_suci_encoding_tests();
extern void run_priv_key_range_tests();

int main()
{
    TEST_ASSERT_EQ(1 + 1, 2);
    TEST_ASSERT(true, "trivial assertion");

    run_micro_ecc_tests();
    run_x963kdf_tests();
    run_ecies_profile_b_vector_test();
    run_ecies_profile_b_structural_test();
    run_ecies_soft_fail_tests();
    run_suci_encoding_tests();
    run_priv_key_range_tests();

    return test_summary();
}

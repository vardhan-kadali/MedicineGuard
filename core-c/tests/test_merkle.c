#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "sha256.h"
#include "merkle.h"

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        g_tests_failed++; \
        printf("  [FAIL] %s (Line %d)\n", msg, __LINE__); \
    } \
} while (0)

/* Helper to generate mock medicine records */
static medicine_record_t *create_mock_batch(const char *batch_id,
                                            const char *medicine_name,
                                            size_t count) {
    medicine_record_t *records = (medicine_record_t *)malloc(count * sizeof(medicine_record_t));
    if (!records) return NULL;

    for (size_t i = 0; i < count; i++) {
        records[i].batch_id = strdup(batch_id);

        char unit_buf[32];
        snprintf(unit_buf, sizeof(unit_buf), "MED%05zu", i + 1);
        records[i].unit_id = strdup(unit_buf);

        records[i].medicine_name = strdup(medicine_name);
        records[i].manufacturing_date = strdup("2026-11-13");
        records[i].expiry_date = strdup("2028-11-13");
    }
    return records;
}

static void free_mock_batch(medicine_record_t *records, size_t count) {
    if (!records) return;
    for (size_t i = 0; i < count; i++) {
        free(records[i].batch_id);
        free(records[i].unit_id);
        free(records[i].medicine_name);
        free(records[i].manufacturing_date);
        free(records[i].expiry_date);
    }
    free(records);
}

/* 1. Test Deterministic Serialization Format */
static void test_serialization(void) {
    printf("\n--- Test Suite 1: Deterministic Serialization ---\n");

    medicine_record_t rec = {
        .batch_id = "BATCH101",
        .unit_id = "MED00001",
        .medicine_name = "Paracetamol 500mg",
        .manufacturing_date = "2026-11-13",
        .expiry_date = "2028-11-13"
    };

    uint8_t *bytes = NULL;
    size_t len = 0;
    merkle_error_t err = merkle_serialize_record(&rec, &bytes, &len);

    TEST_ASSERT(err == MERKLE_SUCCESS, "Serialization succeeded");
    TEST_ASSERT(bytes != NULL, "Output buffer is non-null");

    /* Check magic header: 'M', 'G', '0', '1' */
    TEST_ASSERT(bytes[0] == 'M' && bytes[1] == 'G' && bytes[2] == '0' && bytes[3] == '1',
                "Magic header is 'MG01'");

    /* Check first field length (batch_id = "BATCH101" -> 8 bytes in big-endian) */
    uint32_t b_len = ((uint32_t)bytes[4] << 24) | ((uint32_t)bytes[5] << 16) |
                     ((uint32_t)bytes[6] << 8)  | (uint32_t)bytes[7];
    TEST_ASSERT(b_len == 8, "First field length correctly encoded as 8");
    TEST_ASSERT(memcmp(bytes + 8, "BATCH101", 8) == 0, "First field content matches 'BATCH101'");

    /* Serialization must be deterministic: repeat and compare */
    uint8_t *bytes2 = NULL;
    size_t len2 = 0;
    merkle_serialize_record(&rec, &bytes2, &len2);
    TEST_ASSERT(len == len2 && memcmp(bytes, bytes2, len) == 0,
                "Serialization is 100% deterministic across multiple invocations");

    free(bytes);
    free(bytes2);
}

/* 2. Test Domain Separation */
static void test_domain_separation(void) {
    printf("\n--- Test Suite 2: Domain Separation Security ---\n");

    medicine_record_t rec = {
        .batch_id = "BATCH101",
        .unit_id = "MED00001",
        .medicine_name = "Aspirin",
        .manufacturing_date = "2026-11-13",
        .expiry_date = "2028-11-13"
    };

    uint8_t leaf_hash[32];
    merkle_compute_leaf_hash(&rec, leaf_hash);

    /* Compute standard SHA-256 of raw serialized record WITHOUT domain prefix */
    uint8_t *raw_bytes = NULL;
    size_t raw_len = 0;
    merkle_serialize_record(&rec, &raw_bytes, &raw_len);

    uint8_t raw_hash[32];
    sha256_hash(raw_bytes, raw_len, raw_hash);

    TEST_ASSERT(crypto_memcmp(leaf_hash, raw_hash, 32) != 0,
                "Domain-separated leaf hash differs from raw SHA-256 (leaf prefix 0x00 enforced)");

    /* Verify parent prefix 0x01 */
    uint8_t parent_hash[32];
    merkle_compute_parent_hash(leaf_hash, raw_hash, parent_hash);

    uint8_t naive_concat[64];
    memcpy(naive_concat, leaf_hash, 32);
    memcpy(naive_concat + 32, raw_hash, 32);
    uint8_t naive_parent[32];
    sha256_hash(naive_concat, 64, naive_parent);

    TEST_ASSERT(crypto_memcmp(parent_hash, naive_parent, 32) != 0,
                "Domain-separated parent hash differs from naive concatenation (prefix 0x01 enforced)");

    free(raw_bytes);
}

/* 3. Test Merkle Tree Construction and Verification Across Various Leaf Counts */
static void test_tree_construction_and_proofs(size_t leaf_count) {
    char label[128];
    snprintf(label, sizeof(label), "Tree Construction & Proofs (N = %zu leaves)", leaf_count);
    printf("\n--- Test Suite: %s ---\n", label);

    medicine_record_t *records = create_mock_batch("BATCH_TEST", "Paracetamol", leaf_count);
    TEST_ASSERT(records != NULL, "Mock batch created");

    merkle_tree_t *tree = NULL;
    merkle_error_t err = merkle_tree_build(records, leaf_count, &tree);
    TEST_ASSERT(err == MERKLE_SUCCESS && tree != NULL, "Tree built successfully");

    uint8_t root[32];
    merkle_tree_get_root(tree, root);
    char root_hex[65];
    sha256_to_hex(root, root_hex);
    printf("    Root [%zu leaves]: %s (Height: %zu)\n", leaf_count, root_hex, tree->height);

    /* Verify all leaves in this batch */
    bool all_verified = true;
    for (size_t i = 0; i < leaf_count; i++) {
        merkle_proof_t proof;
        merkle_error_t perr = merkle_proof_generate(tree, i, &proof);
        if (perr != MERKLE_SUCCESS) {
            all_verified = false;
            break;
        }

        merkle_error_t verr = merkle_proof_verify(&records[i], &proof, root);
        if (verr != MERKLE_SUCCESS) {
            all_verified = false;
            break;
        }
    }

    snprintf(label, sizeof(label), "All %zu proofs verified correctly against batch root", leaf_count);
    TEST_ASSERT(all_verified, label);

    merkle_tree_free(tree);
    free_mock_batch(records, leaf_count);
}

/* 4. Test 5-Leaf Odd Node Promotion Specific Structure */
static void test_five_leaf_structure(void) {
    printf("\n--- Test Suite: 5-Leaf Tree Promotion Invariance ---\n");

    medicine_record_t *records = create_mock_batch("BATCH_FIVE", "Amoxicillin", 5);
    merkle_tree_t *tree = NULL;
    merkle_tree_build(records, 5, &tree);

    /* Height for 5 leaves:
     * Level 0: 5 nodes (leaves L0, L1, L2, L3, L4)
     * Level 1: 3 nodes (P0 = H(L0,L1), P1 = H(L2,L3), L4 promoted)
     * Level 2: 2 nodes (P2 = H(P0,P1), L4 promoted)
     * Level 3: 1 node  (ROOT = H(P2,L4))
     * Total height = 4 levels */
    TEST_ASSERT(tree->height == 4, "5-leaf tree has height 4");
    TEST_ASSERT(tree->levels[0].count == 5, "Level 0 has 5 nodes");
    TEST_ASSERT(tree->levels[1].count == 3, "Level 1 has 3 nodes");
    TEST_ASSERT(tree->levels[2].count == 2, "Level 2 has 2 nodes");
    TEST_ASSERT(tree->levels[3].count == 1, "Level 3 has 1 node");

    /* Confirm L4 is promoted unchanged into Level 1 index 2 and Level 2 index 1 */
    TEST_ASSERT(memcmp(tree->levels[0].hashes[4], tree->levels[1].hashes[2], 32) == 0,
                "L4 promoted unchanged to Level 1");
    TEST_ASSERT(memcmp(tree->levels[1].hashes[2], tree->levels[2].hashes[1], 32) == 0,
                "L4 promoted unchanged to Level 2");

    /* Check proof for L4: should have exactly 1 step (P2 on the left) */
    merkle_proof_t proof4;
    merkle_proof_generate(tree, 4, &proof4);
    TEST_ASSERT(proof4.step_count == 1, "L4 proof has exactly 1 step (bypassing promoted levels)");
    TEST_ASSERT(proof4.steps[0].direction == SIBLING_LEFT, "L4 sibling is P2 on LEFT");
    TEST_ASSERT(memcmp(proof4.steps[0].hash, tree->levels[2].hashes[0], 32) == 0,
                "L4 sibling hash matches Level 2 P2 node");

    uint8_t root[32];
    merkle_tree_get_root(tree, root);
    TEST_ASSERT(merkle_proof_verify(&records[4], &proof4, root) == MERKLE_SUCCESS,
                "L4 proof verifies successfully");

    merkle_tree_free(tree);
    free_mock_batch(records, 5);
}

/* 5. Comprehensive Negative Tests */
static void test_negative_cases(void) {
    printf("\n--- Test Suite: Negative Security & Tampering Tests ---\n");

    const size_t count = 8;
    medicine_record_t *records = create_mock_batch("BATCH_NEG", "Metformin", count);
    merkle_tree_t *tree = NULL;
    merkle_tree_build(records, count, &tree);

    uint8_t root[32];
    merkle_tree_get_root(tree, root);

    merkle_proof_t valid_proof;
    merkle_proof_generate(tree, 0, &valid_proof);

    /* 1. Tamper Medicine Name */
    medicine_record_t tampered_rec = records[0];
    tampered_rec.medicine_name = "Metformin Fake";
    TEST_ASSERT(merkle_proof_verify(&tampered_rec, &valid_proof, root) == MERKLE_ERR_ROOT_MISMATCH,
                "Tampered medicine name rejected");

    /* 2. Tamper Unit ID */
    tampered_rec = records[0];
    tampered_rec.unit_id = "MED99999";
    TEST_ASSERT(merkle_proof_verify(&tampered_rec, &valid_proof, root) == MERKLE_ERR_ROOT_MISMATCH,
                "Tampered unit ID rejected");

    /* 3. Tamper Batch ID */
    tampered_rec = records[0];
    tampered_rec.batch_id = "BATCH_EVIL";
    TEST_ASSERT(merkle_proof_verify(&tampered_rec, &valid_proof, root) == MERKLE_ERR_ROOT_MISMATCH,
                "Tampered batch ID rejected");

    /* 4. Tamper Expiry Date */
    tampered_rec = records[0];
    tampered_rec.expiry_date = "2030-01-01";
    TEST_ASSERT(merkle_proof_verify(&tampered_rec, &valid_proof, root) == MERKLE_ERR_ROOT_MISMATCH,
                "Tampered expiry date rejected");

    /* 5. Tamper Sibling Hash in Proof */
    merkle_proof_t bad_proof = valid_proof;
    bad_proof.steps[0].hash[0] ^= 0xFF;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_ROOT_MISMATCH,
                "Tampered sibling hash rejected");

    /* 6. Reverse Sibling Direction */
    bad_proof = valid_proof;
    bad_proof.steps[0].direction = (bad_proof.steps[0].direction == SIBLING_LEFT) ? SIBLING_RIGHT : SIBLING_LEFT;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_INVALID_PROOF,
                "Reversed sibling direction rejected");

    /* 7. Tamper Leaf Index in Proof */
    bad_proof = valid_proof;
    bad_proof.leaf_index = 1;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_INVALID_PROOF,
                "Tampered leaf index in proof rejected");

    /* 8. Tamper Total Leaves count in Proof (e.g. 8 -> 4, step count mismatch) */
    bad_proof = valid_proof;
    bad_proof.total_leaves = 4;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_INVALID_PROOF,
                "Tampered total leaves count (8 -> 4) rejected with MERKLE_ERR_INVALID_PROOF");

    bad_proof.total_leaves = 0;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_INVALID_PROOF,
                "Tampered total leaves count (0) rejected with MERKLE_ERR_INVALID_PROOF");

    /* 9. Proof from another batch */
    medicine_record_t *other_batch = create_mock_batch("BATCH_OTHER", "Metformin", count);
    merkle_tree_t *other_tree = NULL;
    merkle_tree_build(other_batch, count, &other_tree);
    uint8_t other_root[32];
    merkle_tree_get_root(other_tree, other_root);

    TEST_ASSERT(merkle_proof_verify(&records[0], &valid_proof, other_root) == MERKLE_ERR_ROOT_MISMATCH,
                "Proof verified against foreign batch root rejected");

    /* 10. Missing proof step (truncate step count) */
    bad_proof = valid_proof;
    bad_proof.step_count -= 1;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_INVALID_PROOF,
                "Proof with missing step rejected");

    /* 11. Extra proof step appended */
    bad_proof = valid_proof;
    bad_proof.steps[bad_proof.step_count] = valid_proof.steps[0];
    bad_proof.step_count += 1;
    TEST_ASSERT(merkle_proof_verify(&records[0], &bad_proof, root) == MERKLE_ERR_INVALID_PROOF,
                "Proof with extra trailing step rejected");

    /* 12. Batch validation: Duplicate Unit ID */
    medicine_record_t dup_records[2] = {
        { "B1", "MED01", "MedA", "2026-11-13", "2028-11-13" },
        { "B1", "MED01", "MedA", "2026-11-13", "2028-11-13" }
    };
    merkle_tree_t *dup_tree = NULL;
    TEST_ASSERT(merkle_tree_build(dup_records, 2, &dup_tree) == MERKLE_ERR_DUPLICATE_UNIT,
                "Batch with duplicate unit IDs rejected with MERKLE_ERR_DUPLICATE_UNIT");

    /* 13. Batch validation: Mixed Batch IDs */
    medicine_record_t mixed_records[2] = {
        { "BATCH_A", "MED01", "MedA", "2026-11-13", "2028-11-13" },
        { "BATCH_B", "MED02", "MedA", "2026-11-13", "2028-11-13" }
    };
    merkle_tree_t *mixed_tree = NULL;
    TEST_ASSERT(merkle_tree_build(mixed_records, 2, &mixed_tree) == MERKLE_ERR_MIXED_BATCH,
                "Batch with mixed batch IDs rejected with MERKLE_ERR_MIXED_BATCH");

    /* 14. Empty required fields */
    medicine_record_t empty_rec = { "", "MED01", "MedA", "2026-11-13", "2028-11-13" };
    TEST_ASSERT(merkle_validate_record(&empty_rec) == MERKLE_ERR_INVALID_RECORD,
                "Record with empty batch_id rejected");

    empty_rec.batch_id = "BATCH";
    empty_rec.manufacturing_date = "invalid-date";
    TEST_ASSERT(merkle_validate_record(&empty_rec) == MERKLE_ERR_INVALID_RECORD,
                "Record with invalid date format rejected");

    /* 15. Null pointer handling */
    TEST_ASSERT(merkle_tree_build(NULL, 10, &dup_tree) == MERKLE_ERR_NULL_POINTER,
                "merkle_tree_build handles NULL records safely");
    TEST_ASSERT(merkle_proof_verify(NULL, &valid_proof, root) == MERKLE_ERR_NULL_POINTER,
                "merkle_proof_verify handles NULL record safely");

    merkle_tree_free(other_tree);
    free_mock_batch(other_batch, count);
    merkle_tree_free(tree);
    free_mock_batch(records, count);
}

int main(void) {
    printf("====================================================\n");
    printf(" MedicineGuard - Merkle Tree Engine Test Suite\n");
    printf("====================================================\n");

    test_serialization();
    test_domain_separation();

    /* Test all required leaf counts */
    test_tree_construction_and_proofs(1);     /* 1 leaf */
    test_tree_construction_and_proofs(2);     /* 2 leaves */
    test_tree_construction_and_proofs(3);     /* 3 leaves (odd) */
    test_five_leaf_structure();               /* 5 leaves (detailed structure check) */
    test_tree_construction_and_proofs(7);     /* 7 leaves (odd) */
    test_tree_construction_and_proofs(8);     /* 8 leaves (power of 2) */
    test_tree_construction_and_proofs(100);   /* 100 leaves */
    test_tree_construction_and_proofs(1000);  /* 1,000 leaves */
    test_tree_construction_and_proofs(10000); /* 10,000 leaves - full production batch verification */

    /* Negative tampering and security test suite */
    test_negative_cases();

    printf("\n====================================================\n");
    printf(" Test Summary: %d Run | %d Passed | %d Failed\n",
           g_tests_run, g_tests_passed, g_tests_failed);
    printf("====================================================\n");

    return g_tests_failed ? 1 : 0;
}

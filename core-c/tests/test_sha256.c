#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

static int run_test(const char *test_name, const void *data, size_t len, const char *expected_hex) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    char hex_out[65];

    sha256_hash(data, len, hash);
    sha256_to_hex(hash, hex_out);

    if (strcmp(hex_out, expected_hex) == 0) {
        printf("  [PASS] %s\n", test_name);
        return 0;
    } else {
        printf("  [FAIL] %s\n", test_name);
        printf("    Expected: %s\n", expected_hex);
        printf("    Actual:   %s\n", hex_out);
        return 1;
    }
}

static int test_million_a(void) {
    const char *test_name = "NIST Vector 4: 1,000,000 repetitions of 'a'";
    const char *expected_hex = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    sha256_ctx_t ctx;
    uint8_t hash[SHA256_DIGEST_SIZE];
    char hex_out[65];

    /* Buffer of 1,000 'a' characters; update 1,000 times */
    char chunk[1000];
    memset(chunk, 'a', sizeof(chunk));

    sha256_init(&ctx);
    for (int i = 0; i < 1000; i++) {
        sha256_update(&ctx, chunk, sizeof(chunk));
    }
    sha256_final(&ctx, hash);
    sha256_to_hex(hash, hex_out);

    if (strcmp(hex_out, expected_hex) == 0) {
        printf("  [PASS] %s\n", test_name);
        return 0;
    } else {
        printf("  [FAIL] %s\n", test_name);
        printf("    Expected: %s\n", expected_hex);
        printf("    Actual:   %s\n", hex_out);
        return 1;
    }
}

static int test_incremental_stream(void) {
    const char *test_name = "Incremental Chunking (Byte-by-Byte vs One-Shot)";
    const char *msg = "MedicineGuard: Merkle Tree Traceability";
    uint8_t hash_oneshot[SHA256_DIGEST_SIZE];
    uint8_t hash_stream[SHA256_DIGEST_SIZE];

    sha256_hash(msg, strlen(msg), hash_oneshot);

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    for (size_t i = 0; i < strlen(msg); i++) {
        sha256_update(&ctx, &msg[i], 1);
    }
    sha256_final(&ctx, hash_stream);

    if (crypto_memcmp(hash_oneshot, hash_stream, SHA256_DIGEST_SIZE) == 0) {
        printf("  [PASS] %s\n", test_name);
        return 0;
    } else {
        printf("  [FAIL] %s\n", test_name);
        return 1;
    }
}

static int test_constant_time_memcmp(void) {
    const char *test_name = "Constant-time crypto_memcmp";
    uint8_t a[32] = {0};
    uint8_t b[32] = {0};
    uint8_t c[32] = {0};
    c[31] = 1;

    if (crypto_memcmp(a, b, 32) != 0) {
        printf("  [FAIL] %s: identical buffers reported different\n", test_name);
        return 1;
    }
    if (crypto_memcmp(a, c, 32) == 0) {
        printf("  [FAIL] %s: differing buffers reported identical\n", test_name);
        return 1;
    }
    printf("  [PASS] %s\n", test_name);
    return 0;
}

int main(void) {
    printf("====================================================\n");
    printf(" MedicineGuard - SHA-256 Cryptographic Test Suite\n");
    printf("====================================================\n");

    int failures = 0;

    /* NIST Vector 1: Empty string */
    failures += run_test(
        "NIST Vector 1: Empty String",
        "", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    /* NIST Vector 2: 'abc' */
    failures += run_test(
        "NIST Vector 2: 'abc'",
        "abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    /* NIST Vector 3: 56-byte message */
    failures += run_test(
        "NIST Vector 3: 56-character string",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    /* NIST Vector 4: 1 Million 'a's */
    failures += test_million_a();

    /* Streaming test */
    failures += test_incremental_stream();

    /* Constant time comparison test */
    failures += test_constant_time_memcmp();

    printf("====================================================\n");
    if (failures == 0) {
        printf(" ALL SHA-256 TESTS PASSED SUCCESSFULLY (0 failures)\n");
    } else {
        printf(" SHA-256 TESTS COMPLETED WITH %d FAILURES\n", failures);
    }
    printf("====================================================\n");

    return failures ? 1 : 0;
}

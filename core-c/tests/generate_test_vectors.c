#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "merkle.h"

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
}

static void test_vector_for_n(size_t n) {
    medicine_record_t *records = (medicine_record_t *)malloc(n * sizeof(medicine_record_t));
    char **unit_ids = (char **)malloc(n * sizeof(char *));

    for (size_t i = 0; i < n; i++) {
        unit_ids[i] = (char *)malloc(32);
        snprintf(unit_ids[i], 32, "UNIT-%06zu", i + 1);

        records[i].batch_id = "BATCH-2026-0001";
        records[i].unit_id = unit_ids[i];
        records[i].medicine_name = "Amoxicillin 500mg";
        records[i].manufacturing_date = "2026-01-15";
        records[i].expiry_date = "2028-01-15";
    }

    merkle_tree_t *tree = NULL;
    merkle_error_t err = merkle_tree_build(records, n, &tree);
    if (err != MERKLE_SUCCESS) {
        printf("Error building tree for N=%zu: %d\n", n, err);
        return;
    }

    printf("N=%zu,Height=%zu,Root=", n, tree->height);
    print_hex(tree->root, 32);
    printf("\n");

    merkle_tree_free(tree);
    for (size_t i = 0; i < n; i++) {
        free(unit_ids[i]);
    }
    free(unit_ids);
    free(records);
}

int main(void) {
    size_t sizes[] = { 1, 2, 3, 5, 7, 8, 100, 1000, 10000 };
    size_t count = sizeof(sizes) / sizeof(sizes[0]);

    for (size_t i = 0; i < count; i++) {
        test_vector_for_n(sizes[i]);
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"
#include "merkle.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static double get_time_sec(void) {
    LARGE_INTEGER count, freq;
    QueryPerformanceCounter(&count);
    QueryPerformanceFrequency(&freq);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#include <time.h>
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
#endif

static medicine_record_t *generate_benchmark_batch(size_t n) {
    medicine_record_t *records = (medicine_record_t *)malloc(n * sizeof(medicine_record_t));
    if (!records) return NULL;

    for (size_t i = 0; i < n; i++) {
        records[i].batch_id = strdup("BATCH_BENCH_2026");

        char ubuf[32];
        snprintf(ubuf, sizeof(ubuf), "MED%07zu", i + 1);
        records[i].unit_id = strdup(ubuf);

        records[i].medicine_name = strdup("Paracetamol 500mg IP");
        records[i].manufacturing_date = strdup("2026-11-13");
        records[i].expiry_date = strdup("2028-11-13");
    }
    return records;
}

static void free_benchmark_batch(medicine_record_t *records, size_t n) {
    if (!records) return;
    for (size_t i = 0; i < n; i++) {
        free(records[i].batch_id);
        free(records[i].unit_id);
        free(records[i].medicine_name);
        free(records[i].manufacturing_date);
        free(records[i].expiry_date);
    }
    free(records);
}

typedef struct {
    size_t batch_size;
    size_t total_nodes;
    size_t sha256_build_ops;      /* Leaves + Internal nodes */
    double build_time_ms;
    double proof_gen_total_ms;
    double proof_gen_per_unit_us;
    double verify_total_ms;
    double verify_per_unit_us;
    size_t proof_size_bytes;
    size_t tree_ram_bytes;
} benchmark_result_t;

static int run_benchmark_for_size(size_t n, benchmark_result_t *res) {
    printf(">> Initializing batch of %zu medicine units...\n", n);
    medicine_record_t *records = generate_benchmark_batch(n);
    if (!records) {
        printf("Error: Failed to allocate records for N = %zu\n", n);
        return -1;
    }

    res->batch_size = n;

    /* 1. Measure Record Serialization + Leaf Hashing + Merkle Tree Construction */
    double t_start = get_time_sec();
    merkle_tree_t *tree = NULL;
    merkle_error_t err = merkle_tree_build(records, n, &tree);
    double t_build = get_time_sec() - t_start;

    if (err != MERKLE_SUCCESS || !tree) {
        printf("Error: merkle_tree_build failed with code %d\n", err);
        free_benchmark_batch(records, n);
        return -1;
    }
    res->build_time_ms = t_build * 1000.0;

    /* Calculate total nodes in tree */
    size_t total_nodes = 0;
    for (size_t k = 0; k < tree->height; k++) {
        total_nodes += tree->levels[k].count;
    }
    res->total_nodes = total_nodes;
    /* Leaves are hashed once, internal nodes are hashed once; promoted nodes are not hashed */
    res->sha256_build_ops = total_nodes;
    res->tree_ram_bytes = total_nodes * SHA256_DIGEST_SIZE + tree->height * sizeof(merkle_level_t) + sizeof(merkle_tree_t);

    uint8_t root[SHA256_DIGEST_SIZE];
    merkle_tree_get_root(tree, root);

    /* 2. Measure Proof Generation */
    /* For smaller batches (<= 10,000), generate for all units.
       For N = 100,000, sample 10,000 units to keep benchmark time practical. */
    size_t sample_size = (n <= 10000) ? n : 10000;
    merkle_proof_t *proofs = (merkle_proof_t *)malloc(sample_size * sizeof(merkle_proof_t));
    if (!proofs) {
        printf("Error: Memory allocation failed for proofs\n");
        merkle_tree_free(tree);
        free_benchmark_batch(records, n);
        return -1;
    }

    t_start = get_time_sec();
    for (size_t i = 0; i < sample_size; i++) {
        merkle_proof_generate(tree, i, &proofs[i]);
    }
    double t_gen = get_time_sec() - t_start;
    res->proof_gen_total_ms = (t_gen / (double)sample_size) * (double)n * 1000.0;
    res->proof_gen_per_unit_us = (t_gen / (double)sample_size) * 1e6;
    res->proof_size_bytes = sizeof(uint32_t) * 3 + proofs[0].step_count * sizeof(merkle_proof_step_t);

    /* 3. Measure Proof Verification */
    t_start = get_time_sec();
    for (size_t i = 0; i < sample_size; i++) {
        merkle_error_t verr = merkle_proof_verify(&records[i], &proofs[i], root);
        if (verr != MERKLE_SUCCESS) {
            printf("Error: Verification failed for unit %zu with code %d\n", i, verr);
            free(proofs);
            merkle_tree_free(tree);
            free_benchmark_batch(records, n);
            return -1;
        }
    }
    double t_ver = get_time_sec() - t_start;
    res->verify_total_ms = (t_ver / (double)sample_size) * (double)n * 1000.0;
    res->verify_per_unit_us = (t_ver / (double)sample_size) * 1e6;

    /* Clean up */
    free(proofs);
    merkle_tree_free(tree);
    free_benchmark_batch(records, n);

    return 0;
}

int main(void) {
    printf("========================================================================================\n");
    printf(" MedicineGuard - DAA Empirical Performance Benchmark\n");
    printf(" Language: C (C11) | Hashing: Standalone SHA-256 | Timer: High-Resolution Monotonic\n");
    printf("========================================================================================\n\n");

    const size_t sizes[] = { 100, 1000, 10000, 100000 };
    const size_t num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    benchmark_result_t results[4];

    for (size_t i = 0; i < num_sizes; i++) {
        if (run_benchmark_for_size(sizes[i], &results[i]) != 0) {
            printf("Benchmark failed for N = %zu\n", sizes[i]);
            return 1;
        }
    }

    printf("\n========================================================================================\n");
    printf("                                EMPIRICAL BENCHMARK RESULTS                             \n");
    printf("========================================================================================\n");
    printf("%-8s | %-12s | %-12s | %-14s | %-14s | %-10s | %-10s\n",
           "Units(N)", "Total Nodes", "Build (ms)", "Gen/unit (us)", "Ver/unit (us)", "Proof(B)", "Tree RAM");
    printf("---------+--------------+--------------+----------------+----------------+------------+-----------\n");

    for (size_t i = 0; i < num_sizes; i++) {
        char ram_str[32];
        if (results[i].tree_ram_bytes < 1024 * 1024) {
            snprintf(ram_str, sizeof(ram_str), "%.1f KB", (double)results[i].tree_ram_bytes / 1024.0);
        } else {
            snprintf(ram_str, sizeof(ram_str), "%.2f MB", (double)results[i].tree_ram_bytes / (1024.0 * 1024.0));
        }

        printf("%-8zu | %-12zu | %10.2f ms | %11.2f us | %11.2f us | %7zu B  | %-10s\n",
               results[i].batch_size,
               results[i].total_nodes,
               results[i].build_time_ms,
               results[i].proof_gen_per_unit_us,
               results[i].verify_per_unit_us,
               results[i].proof_size_bytes,
               ram_str);
    }
    printf("========================================================================================\n\n");

    printf("Analysis Summary:\n");
    printf(" - Tree Construction Time scales linearly: Theta(N)\n");
    printf(" - Single Proof Generation Time scales logarithmically: Theta(log N)\n");
    printf(" - Single Proof Verification Time scales logarithmically: Theta(log N)\n");
    printf(" - Space complexity is bounded by 2N nodes in memory: Theta(N)\n");

    return 0;
}

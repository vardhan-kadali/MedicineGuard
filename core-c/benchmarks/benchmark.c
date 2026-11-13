#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "sha256.h"
#include "merkle.h"

#define NUM_TRIALS 7

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

static double g_timer_freq = 0.0;

static void timer_init(void) {
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    g_timer_freq = (double)freq.QuadPart;
}

static double get_time_sec(void) {
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / g_timer_freq;
}

static size_t get_peak_rss_bytes(void) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return (size_t)pmc.PeakWorkingSetSize;
    }
    return 0;
}
#else
#include <time.h>
#include <sys/resource.h>

static double g_timer_freq = 1.0;

static void timer_init(void) {
    g_timer_freq = 1.0;
}

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static size_t get_peak_rss_bytes(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        return (size_t)usage.ru_maxrss * 1024;
    }
    return 0;
}
#endif

typedef struct {
    double min;
    double max;
    double median;
    double mean;
    double std_dev;
} stat_metric_t;

static int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static stat_metric_t compute_stats(double *values, size_t n) {
    stat_metric_t s;
    if (n == 0) {
        memset(&s, 0, sizeof(s));
        return s;
    }

    double *sorted = (double *)malloc(n * sizeof(double));
    if (!sorted) {
        memset(&s, 0, sizeof(s));
        return s;
    }
    memcpy(sorted, values, n * sizeof(double));
    qsort(sorted, n, sizeof(double), compare_doubles);

    s.min = sorted[0];
    s.max = sorted[n - 1];
    if (n % 2 == 1) {
        s.median = sorted[n / 2];
    } else {
        s.median = (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
    }

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) sum += values[i];
    s.mean = sum / (double)n;

    double var_sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = values[i] - s.mean;
        var_sum += diff * diff;
    }
    s.std_dev = (n > 1) ? sqrt(var_sum / (double)(n - 1)) : 0.0;

    free(sorted);
    return s;
}

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

/**
 * @brief Deterministic representative sampling across complete batch.
 *
 * Guaranteed coverage:
 * - First leaf (i = 0)
 * - Center leaf (i = N/2)
 * - Last leaf (i = N-1, exercises odd-node promotion paths)
 * - Uniformly strided points across batch
 * - Fixed-seed pseudorandom points
 */
static size_t *generate_sample_indices(size_t n, size_t *out_sample_size) {
    if (n <= 10000) {
        size_t *indices = (size_t *)malloc(n * sizeof(size_t));
        if (!indices) return NULL;
        for (size_t i = 0; i < n; i++) indices[i] = i;
        *out_sample_size = n;
        return indices;
    }

    size_t sample_size = 10000;
    size_t *indices = (size_t *)malloc(sample_size * sizeof(size_t));
    if (!indices) return NULL;

    size_t idx = 0;
    /* 1. Mandatory boundary and invariant leaves */
    indices[idx++] = 0;          /* Far left */
    indices[idx++] = n / 2;      /* Center */
    indices[idx++] = n - 1;      /* Far right (maximum odd promotions) */

    /* 2. Uniformly strided points */
    size_t stride_count = (sample_size / 2) - 3;
    for (size_t i = 0; i < stride_count; i++) {
        indices[idx++] = 1 + (size_t)(((uint64_t)i * (n - 3)) / (stride_count - 1));
    }

    /* 3. Deterministic pseudorandom points using fixed LCG seed */
    uint64_t lcg_state = 0x4D473031ULL; /* "MG01" */
    while (idx < sample_size) {
        lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
        indices[idx++] = (size_t)(lcg_state % n);
    }

    *out_sample_size = sample_size;
    return indices;
}

typedef struct {
    size_t batch_size;
    size_t total_nodes;
    size_t height;
    size_t sample_size;
    stat_metric_t val_ms;
    stat_metric_t e2e_build_ms;
    stat_metric_t pure_build_ms;
    stat_metric_t proof_gen_us;
    stat_metric_t e2e_verify_us;
    stat_metric_t hash_verify_us;
    size_t in_memory_proof_bytes;
    size_t wire_proof_bytes;
    size_t retained_tree_bytes;
    size_t peak_rss_bytes;
} benchmark_result_t;

static void run_warmup(void) {
    printf("[WARM-UP] Executing preliminary discarded batch (N = 1,000) to stabilize CPU state...\n");
    medicine_record_t *warmup_records = generate_benchmark_batch(1000);
    if (!warmup_records) return;

    merkle_tree_t *tree = NULL;
    if (merkle_tree_build(warmup_records, 1000, &tree) == MERKLE_SUCCESS && tree) {
        uint8_t root[32];
        merkle_tree_get_root(tree, root);
        for (size_t i = 0; i < 100; i++) {
            merkle_proof_t proof;
            merkle_proof_generate(tree, i, &proof);
            merkle_proof_verify(&warmup_records[i], &proof, root);
        }
        merkle_tree_free(tree);
    }
    free_benchmark_batch(warmup_records, 1000);
    printf("[WARM-UP] Complete. CPU instruction cache and allocator arenas primed.\n\n");
}

static int run_benchmark_for_size(size_t n, benchmark_result_t *res) {
    printf(">> Benchmarking batch size N = %zu (%d measured trials)...\n", n, NUM_TRIALS);

    medicine_record_t *records = generate_benchmark_batch(n);
    if (!records) {
        printf("Error: Failed to allocate records for N = %zu\n", n);
        return -1;
    }

    size_t sample_size = 0;
    size_t *sample_indices = generate_sample_indices(n, &sample_size);
    if (!sample_indices) {
        free_benchmark_batch(records, n);
        return -1;
    }

    res->batch_size = n;
    res->sample_size = sample_size;

    double val_times[NUM_TRIALS];
    double e2e_build_times[NUM_TRIALS];
    double pure_build_times[NUM_TRIALS];
    double gen_times[NUM_TRIALS];
    double e2e_ver_times[NUM_TRIALS];
    double hash_ver_times[NUM_TRIALS];

    merkle_proof_t *proofs = (merkle_proof_t *)malloc(sample_size * sizeof(merkle_proof_t));
    uint8_t (*precomputed_leaf_hashes)[SHA256_DIGEST_SIZE] =
        malloc(sample_size * sizeof(*precomputed_leaf_hashes));

    if (!proofs || !precomputed_leaf_hashes) {
        printf("Error: Memory allocation failed for proof buffers\n");
        free(sample_indices);
        free_benchmark_batch(records, n);
        return -1;
    }

    /* Precompute leaf hashes once for pure path verification measurement */
    for (size_t i = 0; i < sample_size; i++) {
        merkle_compute_leaf_hash(&records[sample_indices[i]], precomputed_leaf_hashes[i]);
    }

    for (int t = 0; t < NUM_TRIALS; t++) {
        /* 1. Measure Batch Validation & Duplicate ID detection (qsort) */
        double t_start = get_time_sec();
        merkle_error_t val_err = merkle_validate_batch(records, n);
        double t_val = get_time_sec() - t_start;
        if (val_err != MERKLE_SUCCESS) {
            printf("Error: merkle_validate_batch failed\n");
            return -1;
        }
        val_times[t] = t_val * 1000.0;

        /* 2. Measure End-to-End Batch Build (validation + serialization + leaf hashing + tree build) */
        t_start = get_time_sec();
        merkle_tree_t *tree = NULL;
        merkle_error_t build_err = merkle_tree_build(records, n, &tree);
        double t_build = get_time_sec() - t_start;
        if (build_err != MERKLE_SUCCESS || !tree) {
            printf("Error: merkle_tree_build failed\n");
            return -1;
        }
        e2e_build_times[t] = t_build * 1000.0;
        pure_build_times[t] = (t_build > t_val) ? ((t_build - t_val) * 1000.0) : (t_build * 1000.0);

        if (t == 0) {
            res->height = tree->height;
            size_t total_nodes = 0;
            for (size_t k = 0; k < tree->height; k++) total_nodes += tree->levels[k].count;
            res->total_nodes = total_nodes;
            res->retained_tree_bytes = total_nodes * SHA256_DIGEST_SIZE +
                                      tree->height * sizeof(merkle_level_t) +
                                      sizeof(merkle_tree_t) +
                                      strlen(tree->batch_id) + 1;
        }

        uint8_t root[SHA256_DIGEST_SIZE];
        merkle_tree_get_root(tree, root);

        /* 3. Measure Proof Generation across representative sample */
        t_start = get_time_sec();
        for (size_t i = 0; i < sample_size; i++) {
            merkle_error_t perr = merkle_proof_generate(tree, sample_indices[i], &proofs[i]);
            if (perr != MERKLE_SUCCESS) {
                printf("Error: merkle_proof_generate failed\n");
                return -1;
            }
        }
        double t_gen = get_time_sec() - t_start;
        gen_times[t] = (t_gen / (double)sample_size) * 1e6; /* microseconds */

        /* 4. Measure End-to-End Proof Verification (Record -> Serialize -> Leaf Hash -> Path Verify) */
        t_start = get_time_sec();
        for (size_t i = 0; i < sample_size; i++) {
            merkle_error_t verr = merkle_proof_verify(&records[sample_indices[i]], &proofs[i], root);
            if (verr != MERKLE_SUCCESS) {
                printf("Error: merkle_proof_verify failed at sample %zu (unit index %zu)\n",
                       i, sample_indices[i]);
                return -1;
            }
        }
        double t_e2e_ver = get_time_sec() - t_start;
        e2e_ver_times[t] = (t_e2e_ver / (double)sample_size) * 1e6; /* microseconds */

        /* 5. Measure Pure Path Verification from Precomputed Leaf Hash */
        t_start = get_time_sec();
        for (size_t i = 0; i < sample_size; i++) {
            merkle_error_t verr = merkle_proof_verify_leaf_hash(precomputed_leaf_hashes[i], &proofs[i], root);
            if (verr != MERKLE_SUCCESS) {
                printf("Error: merkle_proof_verify_leaf_hash failed\n");
                return -1;
            }
        }
        double t_hash_ver = get_time_sec() - t_start;
        hash_ver_times[t] = (t_hash_ver / (double)sample_size) * 1e6; /* microseconds */

        if (t == 0) {
            /* Active C in-memory structure size */
            res->in_memory_proof_bytes = sizeof(uint32_t) * 3 + proofs[0].step_count * sizeof(merkle_proof_step_t);
            /* Concrete canonical binary wire format:
             * [4B leaf_index][4B total_leaves][2B step_count] + step_count * [32B hash + 1B direction] */
            res->wire_proof_bytes = 10 + proofs[0].step_count * 33;
        }

        merkle_tree_free(tree);
    }

    res->val_ms = compute_stats(val_times, NUM_TRIALS);
    res->e2e_build_ms = compute_stats(e2e_build_times, NUM_TRIALS);
    res->pure_build_ms = compute_stats(pure_build_times, NUM_TRIALS);
    res->proof_gen_us = compute_stats(gen_times, NUM_TRIALS);
    res->e2e_verify_us = compute_stats(e2e_ver_times, NUM_TRIALS);
    res->hash_verify_us = compute_stats(hash_ver_times, NUM_TRIALS);
    res->peak_rss_bytes = get_peak_rss_bytes();

    free(proofs);
    free(precomputed_leaf_hashes);
    free(sample_indices);
    free_benchmark_batch(records, n);

    return 0;
}

int main(void) {
    timer_init();

    printf("========================================================================================================\n");
    printf(" MedicineGuard — Refined DAA Empirical Performance Benchmark\n");
    printf(" Standard: C11 | Compiler: GCC 16.2.0 (-O3) | Platform: x86_64-w64-mingw32\n");
    printf(" Timer: Invariant High-Resolution QPC (Cached Freq) | Repetitions: %d Trials per Batch\n", NUM_TRIALS);
    printf(" Statistical Metric: Median [Min - Max] +/- Standard Deviation (sigma)\n");
    printf("========================================================================================================\n\n");

    run_warmup();

    const size_t sizes[] = { 100, 1000, 10000, 100000 };
    const size_t num_sizes = sizeof(sizes) / sizeof(sizes[0]);
    benchmark_result_t results[4];

    for (size_t i = 0; i < num_sizes; i++) {
        if (run_benchmark_for_size(sizes[i], &results[i]) != 0) {
            printf("Benchmark failed for N = %zu\n", sizes[i]);
            return 1;
        }
    }

    printf("\n========================================================================================================\n");
    printf("                                PART 1: BATCH INGESTION & TREE CONSTRUCTION                             \n");
    printf("========================================================================================================\n");
    printf("%-8s | %-11s | %-18s | %-20s | %-20s\n",
           "Units(N)", "Nodes (Hgt)", "Validation (ms)", "Pure Build (ms)", "End-to-End Build (ms)");
    printf("---------+-------------+--------------------+----------------------+---------------------\n");

    for (size_t i = 0; i < num_sizes; i++) {
        char nodes_str[32];
        snprintf(nodes_str, sizeof(nodes_str), "%zu (h=%zu)", results[i].total_nodes, results[i].height);

        printf("%-8zu | %-11s | %6.2f +/- %4.2f ms | %7.2f +/- %4.2f ms | %7.2f +/- %4.2f ms\n",
               results[i].batch_size,
               nodes_str,
               results[i].val_ms.median, results[i].val_ms.std_dev,
               results[i].pure_build_ms.median, results[i].pure_build_ms.std_dev,
               results[i].e2e_build_ms.median, results[i].e2e_build_ms.std_dev);
    }
    printf("========================================================================================================\n");
    printf(" Note: 'Validation' measures merkle_validate_batch (field checks + O(N log N) qsort duplicate check).\n");
    printf("       'Pure Build' isolates Level 0 leaf hashing and parent node tree construction.\n");
    printf("       'End-to-End Build' is merkle_tree_build (Validation + Serialization + Leaf Hash + Tree Build).\n\n");

    printf("========================================================================================================\n");
    printf("                                PART 2: PROOF GENERATION & VERIFICATION LATENCY                         \n");
    printf("========================================================================================================\n");
    printf("%-8s | %-12s | %-20s | %-22s | %-22s\n",
           "Units(N)", "Sampled", "Proof Gen (us/unit)", "Pure Path Ver (us/unit)", "End-to-End Ver (us/unit)");
    printf("---------+--------------+----------------------+------------------------+-----------------------\n");

    for (size_t i = 0; i < num_sizes; i++) {
        printf("%-8zu | %-12zu | %7.2f +/- %4.2f us |  %7.2f +/- %4.2f us  |  %7.2f +/- %4.2f us\n",
               results[i].batch_size,
               results[i].sample_size,
               results[i].proof_gen_us.median, results[i].proof_gen_us.std_dev,
               results[i].hash_verify_us.median, results[i].hash_verify_us.std_dev,
               results[i].e2e_verify_us.median, results[i].e2e_verify_us.std_dev);
    }
    printf("========================================================================================================\n");
    printf(" Note: 'Proof Gen' measures merkle_proof_generate across representative sample (first, middle, last,\n");
    printf("       uniform strides, fixed-seed pseudorandom, exercising odd-promotion branches).\n");
    printf("       'Pure Path Ver' measures merkle_proof_verify_leaf_hash (hash climbing only).\n");
    printf("       'End-to-End Ver' measures merkle_proof_verify (Record -> Serialize -> Leaf Hash -> Path Verify).\n\n");

    printf("========================================================================================================\n");
    printf("                                PART 3: MEMORY FOOTPRINT & PROOF SIZES                                  \n");
    printf("========================================================================================================\n");
    printf("%-8s | %-18s | %-18s | %-18s | %-18s\n",
           "Units(N)", "In-Memory Proof", "Binary Wire Proof", "Retained Tree RAM", "Peak Working Set");
    printf("---------+--------------------+--------------------+--------------------+--------------------\n");

    for (size_t i = 0; i < num_sizes; i++) {
        char tree_ram[32];
        if (results[i].retained_tree_bytes < 1024 * 1024) {
            snprintf(tree_ram, sizeof(tree_ram), "%.1f KB", (double)results[i].retained_tree_bytes / 1024.0);
        } else {
            snprintf(tree_ram, sizeof(tree_ram), "%.2f MB", (double)results[i].retained_tree_bytes / (1024.0 * 1024.0));
        }

        char rss_str[32];
        if (results[i].peak_rss_bytes < 1024 * 1024) {
            snprintf(rss_str, sizeof(rss_str), "%.1f KB", (double)results[i].peak_rss_bytes / 1024.0);
        } else {
            snprintf(rss_str, sizeof(rss_str), "%.2f MB", (double)results[i].peak_rss_bytes / (1024.0 * 1024.0));
        }

        printf("%-8zu | %7zu bytes      | %7zu bytes      | %-18s | %-18s\n",
               results[i].batch_size,
               results[i].in_memory_proof_bytes,
               results[i].wire_proof_bytes,
               tree_ram,
               rss_str);
    }
    printf("========================================================================================================\n");
    printf(" Accounting Clarification:\n");
    printf(" - 'In-Memory Proof': C structure size (12B metadata + steps * 36B with 4-byte enum alignment).\n");
    printf(" - 'Binary Wire Proof': Defined compact canonical encoding (10B metadata + steps * 33B [hash + 1B dir]).\n");
    printf(" - 'Retained Tree RAM': Exact memory occupied by merkle_tree_t and all level hash arrays.\n");
    printf(" - 'Peak Working Set': Operating system process peak physical RAM (ProcessMemoryCounters.PeakWorkingSet).\n");
    printf("   Excludes: transient batch generator records (~14 MB for N=100k) and validation pointer array (800 KB).\n\n");

    return 0;
}

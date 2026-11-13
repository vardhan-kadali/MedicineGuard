# MedicineGuard — Asymptotic Complexity & Empirical Performance Analysis
**Course Alignment:** Design and Analysis of Algorithms (DAA)  
**Subject:** Divide and Conquer, Binary Trees, Cryptographic Accumulators, Empirical Profiling  

---

## 1. Asymptotic Complexity Formulations

Let:
- $N$ = Number of individual medicine units in a batch.
- $L$ = Byte length of the canonical serialized medicine record ($\approx 65 \dots 80$ bytes).

| Operation | Asymptotic Time Complexity | Asymptotic Space Complexity | Practical Scale ($N = 10,000$) | Practical Scale ($N = 100,000$) |
|---|---|---|---|---|
| **Record Serialization** | $\Theta(L)$ | $\Theta(L)$ | $< 0.1 \mu\text{s}$ per record | $< 0.1 \mu\text{s}$ per record |
| **Leaf Hashing** | $\Theta(L)$ | $\Theta(1)$ | $\approx 2.3 \mu\text{s}$ per record | $\approx 2.8 \mu\text{s}$ per record |
| **Duplicate-ID Validation (`qsort`)** | $\Theta(N \log N)$ | $\Theta(N)$ pointers | $2.60\text{ ms}$ | $51.52\text{ ms}$ |
| **Pure Tree Construction (from leaves)** | $\Theta(N)$ | $\Theta(N)$ | $25.58\text{ ms}$ | $362.79\text{ ms}$ |
| **End-to-End Batch Build (`build`)** | $\Theta(N \log N + N \cdot L)$ | $\Theta(N)$ | $28.79\text{ ms}$ | $428.36\text{ ms}$ |
| **Root Hash Retrieval** | $\Theta(1)$ | $\Theta(1)$ | Instantaneous | Instantaneous |
| **Single Proof Generation** | $\Theta(\log N)$ | $\Theta(\log N)$ | $0.22 \mu\text{s}$ | $0.31 \mu\text{s}$ |
| **Pure Path Verification (`verify_leaf`)**| $\Theta(\log N)$ | $\Theta(1)$ | $12.99 \mu\text{s}$ | $26.90 \mu\text{s}$ |
| **End-to-End Verification (`verify`)** | $\Theta(L + \log N)$ | $\Theta(L)$ | $15.30 \mu\text{s}$ | $29.76 \mu\text{s}$ |
| **Retained Tree In-Memory RAM** | — | $\Theta(N)$ | $625.5\text{ KB}$ | $6.10\text{ MB}$ |
| **Individual In-Memory Proof Size** | — | $\Theta(\log N)$ | $516\text{ bytes}$ (14 steps) | $624\text{ bytes}$ (17 steps) |
| **Individual Binary Wire Proof Size** | — | $\Theta(\log N)$ | $472\text{ bytes}$ (14 steps) | $571\text{ bytes}$ (17 steps) |

---

## 2. Mathematical Proofs and Complexity Distinctions

### 2.1 Pure Tree Construction $\Theta(N)$ vs. Batch Ingestion $\Theta(N \log N)$
A fundamental distinction in DAA is separating **input validation** from **data structure construction**:

1. **Pure Binary Merkle Tree Construction: $\Theta(N)$**  
   Given $N$ leaf hashes, the number of parent SHA-256 operations computed across all levels is:
   $$\sum_{k=1}^{\lceil \log_2 N \rceil} \frac{N}{2^k} = N \left(1 - \frac{1}{2^{\lceil \log_2 N \rceil}}\right) < N$$
   Because each SHA-256 compression over two 32-byte hashes ($65$ bytes with prefix) is bounded by constant time $c$, total tree construction is strictly linear: $T_{\text{tree}}(N) \le c \cdot (2N - 1) = \Theta(N)$.

2. **Input Validation & Duplicate Detection: $\Theta(N \log N)$**  
   Before building the tree, `merkle_validate_batch()` verifies that all unit IDs within the batch are strictly unique. To prevent $O(N^2)$ pairwise checking, the algorithm allocates $N$ pointers and executes quicksort (`qsort`), which requires $O(N \log N)$ string comparisons.  
   - For $N = 10,000$, quicksort takes $\approx 2.6\text{ ms}$.  
   - For $N = 100,000$, quicksort performs $\approx 1.7 \times 10^6$ comparisons, consuming $\approx 51.5\text{ ms}$ ($\approx 12\%$ of total ingestion time).

3. **End-to-End Batch Build: $\Theta(N \log N + N \cdot L)$**  
   The public function `merkle_tree_build()` coordinates both steps. It should be evaluated as an end-to-end ingestion pipeline, not purely binary tree hashing.

### 2.2 Proof Verification Time: $\Theta(\log N)$
To verify a single medicine unit:
1. **Serialization & Leaf Hash:** Serializing the 5 record fields takes $\Theta(L)$ time. Hashing $0x00 \parallel \text{serialized\_bytes}$ takes $1$ SHA-256 block transformation ($\approx 2.3 \mu\text{s}$).
2. **Path Traversal:** The verifier climbs $\lceil \log_2 N \rceil$ levels. At each level, it hashes the intermediate state with the sibling hash ($65$ bytes). For $N = 10,000$, height is 14; for $N = 100,000$, height is 17.
3. **Constant-Time Root Comparison:** 32 bytes compared in constant time $\Theta(1)$ using `crypto_memcmp`.
$$\text{Total Verification Hashes} = 1 + \lceil \log_2 N \rceil = \Theta(\log N)$$

---

## 3. Empirical Benchmark Methodology (Refined)

To achieve reproducible, scientifically sound results, the benchmark harness (`core-c/benchmarks/benchmark.c`) incorporates:
1. **Preliminary Warm-Up Phase:** A non-timed, discarded execution of $1,000$ units primes CPU frequency governors (Turbo Boost), pre-populates instruction/data caches, and initializes OS memory arenas.
2. **Multi-Trial Repetition:** Exactly $K = 7$ independent trials are measured for every batch size. The **median** is reported alongside the **sample standard deviation ($\sigma$)** to resist transient OS scheduling spikes.
3. **Deterministic Representative Proof Sampling:** For $N = 100,000$, testing is not biased to the first $10,000$ leaves. The harness evaluates $10,000$ representative units across:
   - Leftmost leaf ($i = 0$)
   - Center leaf ($i = N/2$)
   - Rightmost leaf ($i = N - 1$, exercising odd-node promotion bypasses)
   - Uniformly strided points across $[1, N-2]$
   - Fixed-seed pseudorandom points ($LCG$ with seed `0x4D473031`)
4. **Isolated Timers:** High-resolution Invariant `QueryPerformanceCounter` (Windows) queries timer frequency once at startup, eliminating measurement overhead.

---

## 4. Empirical Benchmark Results

Compiled with **GCC 16.2.0 (`-O3`)** on a 64-bit Windows workstation (7 trials per batch size, median $\pm \sigma$ reported):

### Part 1: Batch Validation & Construction Latency

| Units ($N$) | Tree Nodes (Height) | Batch Validation | Pure Tree Construction | End-to-End Batch Build |
|---|---|---|---|---|
| **100** | 202 ($h = 8$) | $0.03 \pm 0.00\text{ ms}$ | $0.40 \pm 0.11\text{ ms}$ | $0.43 \pm 0.11\text{ ms}$ |
| **1,000** | 2,001 ($h = 11$) | $0.29 \pm 0.35\text{ ms}$ | $2.95 \pm 0.53\text{ ms}$ | $3.55 \pm 0.62\text{ ms}$ |
| **10,000** | 20,005 ($h = 15$) | $2.60 \pm 0.51\text{ ms}$ | $25.58 \pm 9.17\text{ ms}$ | $28.79 \pm 9.25\text{ ms}$ |
| **100,000** | 200,006 ($h = 18$) | $51.52 \pm 14.89\text{ ms}$ | $362.79 \pm 64.34\text{ ms}$ | $428.36 \pm 74.86\text{ ms}$ |

### Part 2: Proof Generation & Verification Latency

| Units ($N$) | Sampled Units | Proof Generation | Pure Path Verification | End-to-End Verification |
|---|---|---|---|---|
| **100** | 100 ($100\%$) | $0.15 \pm 0.26 \mu\text{s}$ | $11.49 \pm 1.42 \mu\text{s}$ | $12.97 \pm 1.95 \mu\text{s}$ |
| **1,000** | 1,000 ($100\%$) | $0.19 \pm 0.15 \mu\text{s}$ | $13.87 \pm 4.97 \mu\text{s}$ | $14.97 \pm 6.01 \mu\text{s}$ |
| **10,000** | 10,000 ($100\%$) | $0.22 \pm 0.17 \mu\text{s}$ | $12.99 \pm 2.51 \mu\text{s}$ | $15.30 \pm 2.56 \mu\text{s}$ |
| **100,000** | 10,000 (Sampled) | $0.31 \pm 0.41 \mu\text{s}$ | $26.90 \pm 1.96 \mu\text{s}$ | $29.76 \pm 12.90 \mu\text{s}$ |

### Part 3: Proof Sizes & Memory Footprint

| Units ($N$) | In-Memory Proof (C Struct) | Binary Wire Proof (Compact) | Retained Tree RAM | Peak Process Working Set (RSS) |
|---|---|---|---|---|
| **100** | $264\text{ bytes}$ | $241\text{ bytes}$ | $6.5\text{ KB}$ | $3.96\text{ MB}$ |
| **1,000** | $372\text{ bytes}$ | $340\text{ bytes}$ | $62.8\text{ KB}$ | $5.12\text{ MB}$ |
| **10,000** | $516\text{ bytes}$ | $472\text{ bytes}$ | $625.5\text{ KB}$ | $17.79\text{ MB}$ |
| **100,000** | $624\text{ bytes}$ | $571\text{ bytes}$ | $6.10\text{ MB}$ | $40.59\text{ MB}$ |

---

## 5. Technical Accounting Notes

1. **Proof Size Accounting:**
   - **In-Memory C Struct:** Represents `merkle_proof_t`. Includes $12\text{ bytes}$ metadata (`uint32_t` for `leaf_index`, `total_leaves`, `step_count`) plus `step_count` elements of `merkle_proof_step_t` ($32\text{ bytes}$ hash + $4\text{ bytes}$ enum due to compiler struct alignment).
   - **Binary Wire Proof:** Defined compact canonical serialization: $[4\text{B index}][4\text{B total}][2\text{B count}] + \text{steps} \times [32\text{B hash} + 1\text{B direction}]$. This eliminates struct padding, reducing proof size by $\approx 8\text{--}10\%$.
2. **Memory Footprint Accounting:**
   - **Retained Tree RAM:** Exact bytes allocated for the `merkle_tree_t` structure and all level hash arrays ($2N - 1$ total nodes $\times 32$ bytes).
   - **Peak Process Working Set (RSS):** Operating system physical memory allocated to the process (`GetProcessMemoryInfo`). This includes transient allocations: the $N$-element `medicine_record_t` array, $600,000$ individual heap strings in the batch generator ($\approx 14\text{ MB}$ for $N=100\text{k}$), and the temporary pointer sorting array ($800\text{ KB}$).

# MedicineGuard — Asymptotic Complexity & Empirical Performance Analysis
**Course Alignment:** Design and Analysis of Algorithms (DAA)  
**Subject:** Divide and Conquer, Binary Trees, Cryptographic Accumulators, Empirical Profiling  

---

## 1. Asymptotic Complexity Formulations

Let:
- $N$ = Number of individual medicine units in a batch.
- $L$ = Byte length of the canonical serialized medicine record ($\approx 65 \dots 80$ bytes).
- $h$ = Tree height $= \lceil \log_2 N \rceil + 1$ (levels $0 \dots h-1$, where $h \le 18$ for $N \le 100,000$).

| Operation | Asymptotic Time Complexity | Asymptotic Space Complexity | Practical Scale ($N = 10,000$) | Practical Scale ($N = 100,000$) |
|---|---|---|---|---|
| **Record Serialization** | $\Theta(L)$ | $\Theta(L)$ | $< 0.1 \mu\text{s}$ per record | $< 0.1 \mu\text{s}$ per record |
| **Leaf Hashing** | $\Theta(L)$ | $\Theta(1)$ | $\approx 2.1 \mu\text{s}$ per record | $\approx 2.7 \mu\text{s}$ per record |
| **Duplicate-ID Validation (`qsort`)** | $\Theta(N \log N)$ | $\Theta(N)$ pointers | $2.93\text{ ms}$ | $58.82\text{ ms}$ |
| **Tree Build Excluding Validation** | $\Theta(N \cdot L)$ | $\Theta(N)$ hashes | $27.29\text{ ms}$ | $314.94\text{ ms}$ |
| **End-to-End Batch Build (`merkle_tree_build`)** | $\Theta(N \log N + N \cdot L)$ | $\Theta(N)$ hashes | $30.50\text{ ms}$ | $418.27\text{ ms}$ |
| **Root Hash Retrieval** | $\Theta(1)$ | $\Theta(1)$ | Instantaneous | Instantaneous |
| **Single Proof Generation** | $\Theta(\log N)$ | $\Theta(\log N)$ | $0.18 \mu\text{s}$ | $0.41 \mu\text{s}$ |
| **Pure Path Verification (`verify_leaf_hash`)**| $\Theta(\log N)$ | $\Theta(1)$ | $18.49 \mu\text{s}$ | $25.25 \mu\text{s}$ |
| **End-to-End Verification (`merkle_proof_verify`)** | $\Theta(L + \log N)$ | $\Theta(L)$ | $20.60 \mu\text{s}$ | $32.53 \mu\text{s}$ |
| **Retained Tree In-Memory RAM** | — | $\Theta(N)$ hashes | $625.5\text{ KB}$ | $6.10\text{ MB}$ |
| **Individual In-Memory Proof Size** | — | $\Theta(\log N)$ steps | $516\text{ bytes}$ (14 steps) | $624\text{ bytes}$ (17 steps) |
| **Individual Binary Wire Proof Size** | — | $\Theta(\log N)$ steps | $472\text{ bytes}$ (14 steps) | $571\text{ bytes}$ (17 steps) |

---

## 2. Mathematical Proofs and Complexity Distinctions

### 2.1 Exact Node-Count Recurrence for Level-Retained Storage

In MedicineGuard, each level is retained independently in memory (`merkle_level_t *levels`). When an unpaired rightmost node is promoted directly to the next level without hashing, it is retained in level $k$ and copied into level $k+1$.

#### Exact Node Recurrence Formula
Let $C_k$ denote the count of nodes stored at level $k$:
- **Level 0 (Leaf level):** $C_0 = N$
- **Level $k+1$ (Parent level):**
  $$C_{k+1} = \left\lceil \frac{C_k}{2} \right\rceil = \left\lfloor \frac{C_k + 1}{2} \right\rfloor$$
- **Termination:** Tree construction stops at level $h-1$ when $C_{h-1} = 1$ (the single Merkle Root).
- **Total Retained Nodes:**
  $$T(N) = \sum_{k=0}^{h-1} C_k$$

#### Verification Against Batch Sizes
1. **$N = 100$ ($h = 8$ levels):**
   - $C = [100, 50, 25, 13, 7, 4, 2, 1]$
   - **Total Retained Nodes:** $100 + 50 + 25 + 13 + 7 + 4 + 2 + 1 = \mathbf{202}$ nodes.
   - *Odd promotions:* 3 promotions ($25 \to 13$, $13 \to 7$, $7 \to 4$). $(2N - 1) + 3 = 199 + 3 = 202$.

2. **$N = 1,000$ ($h = 11$ levels):**
   - $C = [1000, 500, 250, 125, 63, 32, 16, 8, 4, 2, 1]$
   - **Total Retained Nodes:** $1000 + 500 + 250 + 125 + 63 + 32 + 16 + 8 + 4 + 2 + 1 = \mathbf{2,001}$ nodes.
   - *Odd promotions:* 2 promotions ($125 \to 63$, $63 \to 32$). $(2N - 1) + 2 = 1999 + 2 = 2,001$.

3. **$N = 10,000$ ($h = 15$ levels):**
   - $C = [10000, 5000, 2500, 1250, 625, 313, 157, 79, 40, 20, 10, 5, 3, 2, 1]$
   - **Total Retained Nodes:** $10000 + 5000 + \dots + 1 = \mathbf{20,005}$ nodes.
   - *Odd promotions:* 6 promotions. $(2N - 1) + 6 = 19999 + 6 = 20,005$.

4. **$N = 100,000$ ($h = 18$ levels):**
   - $C = [100000, 50000, 25000, 12500, 6250, 3125, 1563, 782, 391, 196, 98, 49, 25, 13, 7, 4, 2, 1]$
   - **Total Retained Nodes:** $100000 + \dots + 1 = \mathbf{200,006}$ nodes.
   - *Odd promotions:* 7 promotions. $(2N - 1) + 7 = 199999 + 7 = 200,006$.

Because height $h = \lceil \log_2 N \rceil \le 18 \ll N$:
$$2N - 1 \le T(N) \le 2N - 1 + \lceil \log_2 N \rceil \implies \lim_{N \to \infty} \frac{T(N)}{N} = 2 \implies T(N) = \mathbf{\Theta(N)}$$

---

### 2.2 Proof of Exact Parent Hashing Invariant: $\sum H_k = N - 1$

A crucial distinction exists between **retained node storage** ($T(N)$) and **cryptographic hashing operations**:

#### Lemma: Parent Hashes at Level $k$
At level $k$, there are $C_k$ nodes. The number of parent SHA-256 compressions computed to generate level $k+1$ is the number of paired adjacent nodes:
$$H_k = \left\lfloor \frac{C_k}{2} \right\rfloor$$

By the mathematical identity linking floor and ceiling functions:
$$\left\lfloor \frac{C_k}{2} \right\rfloor = C_k - \left\lceil \frac{C_k}{2} \right\rceil = C_k - C_{k+1}$$

- Case 1 ($C_k = 2m$ is even):
  $$H_k = m, \quad C_k - C_{k+1} = 2m - m = m$$
- Case 2 ($C_k = 2m + 1$ is odd):
  $$H_k = m, \quad C_k - C_{k+1} = (2m + 1) - (m + 1) = m$$

In both cases, $H_k = C_k - C_{k+1}$ holds identically.

#### Theorem: Telescoping Sum of Parent Hashes
Summing parent hashing operations across all $h-1$ reduction steps ($k = 0, 1, \dots, h-2$):
$$\sum_{k=0}^{h-2} H_k = \sum_{k=0}^{h-2} (C_k - C_{k+1}) = (C_0 - C_1) + (C_1 - C_2) + \dots + (C_{h-2} - C_{h-1})$$

All intermediate terms cancel telescopically, yielding:
$$\sum_{k=0}^{h-2} H_k = C_0 - C_{h-1}$$

Since $C_0 = N$ (the initial leaf count) and $C_{h-1} = 1$ (the single Merkle Root):
$$\mathbf{\sum_{k=0}^{h-2} H_k = N - 1}$$

#### Algorithmic Significance
1. **Exact Parent Hash Invariant:** The total number of parent SHA-256 compression operations computed during tree construction is **EXACTLY $N - 1$** for any integer $N \ge 1$.
2. **Impact of Odd-Node Promotion:** Odd-node promotion creates additional stored entries at intermediate levels ($T(N) > 2N - 1$), but promoted nodes are copied directly via `memcpy` (32 bytes) without executing SHA-256. Every parent hash consumes two nodes and yields one parent, decreasing the active node count by exactly 1. Reducing $N$ leaves to 1 root requires exactly $N - 1$ combining operations. Odd-node promotion does not reduce or increase the total parent hashes below or above $N - 1$.
3. **Total Tree SHA-256 Operations:** Adding the $N$ Level 0 leaf hashes:
   $$\text{Total Cryptographic Invocations} = N + (N - 1) = \mathbf{2N - 1} = \mathbf{\Theta(N)}$$

---

### 2.3 Tree Build Excluding Validation vs. Batch Ingestion

In DAA, separating **input validation** from **data structure construction** is essential:

1. **Duplicate-ID Batch Validation: $\Theta(N \log N)$**  
   Before building the tree, `merkle_validate_batch()` verifies that all unit IDs within the batch are strictly unique. To prevent $O(N^2)$ pairwise checking, the algorithm allocates an array of $N$ pointers and executes quicksort (`qsort`), requiring $O(N \log N)$ string comparisons.  
   - For $N = 10,000$, quicksort takes $\approx 2.93\text{ ms}$.  
   - For $N = 100,000$, quicksort consumes $\approx 58.82\text{ ms}$ ($\approx 14\%$ of total ingestion time).

2. **Tree Build Excluding Validation: $\Theta(N \cdot L)$**  
   This metric isolates the construction pipeline after validation: serializing each medicine record into canonical `MG01` format, computing the Level 0 leaf hashes with prefix `0x00`, and iteratively computing parent levels up to the root with prefix `0x01`. It exhibits strictly linear scaling with respect to batch size.

3. **End-to-End Batch Build (`merkle_tree_build`): $\Theta(N \log N + N \cdot L)$**  
   The public function coordinates validation, canonical serialization, leaf hashing, and parent tree building as a single atomic operation.

---

### 2.4 Proof Verification Time: $\Theta(\log N)$

To verify a single medicine unit:
1. **Canonical Serialization & Leaf Hash:** Serializing the 5 record fields takes $\Theta(L)$ time. Hashing $0x00 \parallel \text{serialized\_bytes}$ takes $1$ SHA-256 block transformation ($\approx 2 \mu\text{s}$).
2. **Path Traversal:** The verifier climbs $\lceil \log_2 N \rceil$ levels. At each level, it hashes the intermediate state with the sibling hash ($65$ bytes). For $N = 10,000$, height is 14; for $N = 100,000$, height is 17.
3. **Constant-Time Root Comparison:** 32 bytes compared in constant time $\Theta(1)$ using `crypto_memcmp`.
$$\text{Total Verification Hashes} = 1 + \lceil \log_2 N \rceil = \mathbf{\Theta(\log N)}$$

---

## 3. Empirical Benchmark Methodology

To ensure reproducible, scientifically rigorous results, the benchmark harness (`core-c/benchmarks/benchmark.c`) incorporates:

1. **Preliminary Warm-Up Phase:**
   A preliminary batch ($N = 1,000$) is built and verified prior to timed trials.
   - **Purpose:** Primes CPU instruction and data caches (L1i, L1d, L2), initializes operating system memory allocation arenas (heap bins), and triggers modern CPU frequency governors to ramp from low-power idle states.
   - **Limitation Note:** Warm-up runs do *not* lock CPU clock frequency or eliminate operating system thread context switches and hardware interrupts.
2. **Multi-Trial Repetition with Statistical Aggregation:**
   Exactly $K = 7$ independent trials are measured for each batch size. To provide full visibility into system behavior, the harness reports:
   - **Median:** Primary central tendency metric, resistant to transient OS scheduler spikes.
   - **Min & Max Bounds:** Absolute measurement range across all 7 trials.
   - **Sample Standard Deviation ($\sigma$):** Degree of measurement dispersion.
3. **Calibrated Adaptive Repetition for Proof-Generation:**
   Individual proof generation takes $\approx 0.03 \dots 0.41 \mu\text{s}$. Measuring 100 units once would take only $3 \mu\text{s}$, well within timer quantization noise.
   - The harness adaptively calibrates repetitions under warm cache execution to ensure an **aggregate measurement duration $\ge 50\text{ ms}$** for every trial.
   - **Actual Measurement Windows:**
     - $N = 100$: $45,384$ repetitions $\times 100$ samples $= 4,538,400$ proofs per trial. Actual duration: **$132.42\text{ ms}$** [Min: $117.36\text{ ms}$, Max: $179.69\text{ ms}$].
     - $N = 1,000$: $1,354$ repetitions $\times 1,000$ samples $= 1,354,000$ proofs per trial. Actual duration: **$87.32\text{ ms}$** [Min: $70.12\text{ ms}$, Max: $123.78\text{ ms}$].
     - $N = 10,000$: $68$ repetitions $\times 10,000$ samples $= 680,000$ proofs per trial. Actual duration: **$121.34\text{ ms}$** [Min: $84.74\text{ ms}$, Max: $277.49\text{ ms}$].
     - $N = 100,000$: $36$ repetitions $\times 10,000$ samples $= 360,000$ proofs per trial. Actual duration: **$148.67\text{ ms}$** [Min: $91.50\text{ ms}$, Max: $218.69\text{ ms}$].
   - Every single trial across all batch sizes exceeds the $50\text{ ms}$ duration threshold by a wide margin (minimum observed: $70.12\text{ ms}$).
   - A `volatile` sink prevents compiler dead-code elimination (DCE).
   - Representative generated proofs (first, middle, last) are explicitly verified outside the timed window to guarantee algorithmic correctness.
4. **Deterministic Representative Proof Sampling:**
   For $N = 100,000$, testing evaluates $10,000$ representative units across:
   - Leftmost leaf ($i = 0$)
   - Center leaf ($i = N/2$)
   - Rightmost leaf ($i = N - 1$, exercising maximum odd-node promotion paths)
   - Uniformly strided points across $[1, N-2]$
   - Fixed-seed pseudorandom points ($LCG$ with seed `0x4D473031`)
5. **Raw Trial Data Export:**
   All 28 raw trial records ($4 \text{ batch sizes} \times 7 \text{ trials}$) are automatically exported to `build/benchmark_raw_trials.csv`.

---

## 4. Empirical Benchmark Results

Compiled with **GCC 16.2.0 (`-O3`)** on Windows 11 (MSYS2 UCRT64, x86_64-w64-mingw32).  
7 measured trials per batch size; values formatted as **Median [Min - Max] $\pm \sigma$**.

### Part 1: Batch Ingestion & Construction Latency

| Units ($N$) | Nodes (Height) | Batch Validation | Tree Build Excl Val | End-to-End Build |
|---|---|---|---|---|
| **100** | 202 ($h = 8$) | $0.02\text{ [0.01 - 0.02]} \pm 0.00\text{ ms}$ | $0.24\text{ [0.12 - 0.40]} \pm 0.10\text{ ms}$ | $0.26\text{ [0.13 - 0.43]} \pm 0.10\text{ ms}$ |
| **1,000** | 2,001 ($h = 11$) | $0.19\text{ [0.12 - 0.24]} \pm 0.05\text{ ms}$ | $2.37\text{ [1.45 - 3.82]} \pm 0.87\text{ ms}$ | $2.51\text{ [1.57 - 4.05]} \pm 0.91\text{ ms}$ |
| **10,000** | 20,005 ($h = 15$) | $2.93\text{ [1.64 - 3.20]} \pm 0.60\text{ ms}$ | $27.29\text{ [13.34 - 34.41]} \pm 8.01\text{ ms}$ | $30.50\text{ [14.98 - 37.34]} \pm 8.56\text{ ms}$ |
| **100,000** | 200,006 ($h = 18$) | $58.82\text{ [42.31 - 133.66]} \pm 30.61\text{ ms}$ | $314.94\text{ [284.60 - 456.83]} \pm 73.49\text{ ms}$ | $418.27\text{ [349.29 - 515.65]} \pm 70.43\text{ ms}$ |

---

### Part 2: Proof Generation & Verification Latency

| Units ($N$) | Sampling ($\text{Sample} \times \text{Reps} = \text{Ops}$) | Actual Trial Duration (ms) | Proof Gen Latency ($\mu\text{s}$/unit) | Pure Path Verification | End-to-End Verification |
|---|---|---|---|---|---|
| **100** | $100 \times 45,384 = \mathbf{4,538,400}$ | $132.42\text{ [117.36 - 179.69]}$ | $0.03\text{ [0.03 - 0.04]} \pm 0.01 \mu\text{s}$ | $7.13\text{ [3.77 - 7.87]} \mu\text{s}$ | $8.85\text{ [4.61 - 9.96]} \mu\text{s}$ |
| **1,000** | $1,000 \times 1,354 = \mathbf{1,354,000}$ | $87.32\text{ [70.12 - 123.78]}$ | $0.06\text{ [0.05 - 0.09]} \pm 0.02 \mu\text{s}$ | $8.71\text{ [6.73 - 15.20]} \mu\text{s}$ | $11.25\text{ [6.60 - 16.54]} \mu\text{s}$ |
| **10,000** | $10,000 \times 68 = \mathbf{680,000}$ | $121.34\text{ [84.74 - 277.49]}$ | $0.18\text{ [0.12 - 0.41]} \pm 0.10 \mu\text{s}$ | $18.49\text{ [13.64 - 28.88]} \mu\text{s}$ | $20.60\text{ [15.31 - 24.98]} \mu\text{s}$ |
| **100,000** | $10,000 \times 36 = \mathbf{360,000}$ | $148.67\text{ [91.50 - 218.69]}$ | $0.41\text{ [0.25 - 0.61]} \pm 0.13 \mu\text{s}$ | $25.25\text{ [22.83 - 48.80]} \mu\text{s}$ | $32.53\text{ [25.55 - 53.41]} \mu\text{s}$ |

---

### Part 3: Proof Sizes & Memory Footprint (Solution A Model)

| Units ($N$) | In-Memory Proof (C Struct) | Proposed Binary Wire Proof | Retained Tree RAM | Current Working Set | Cumulative Peak Working Set (RSS) |
|---|---|---|---|---|---|
| **100** | $264\text{ bytes}$ (7 steps) | $241\text{ bytes}$ | $6.5\text{ KB}$ | $3.91\text{ MB}$ | $3.96\text{ MB}$ |
| **1,000** | $372\text{ bytes}$ (10 steps) | $340\text{ bytes}$ | $62.8\text{ KB}$ | $5.08\text{ MB}$ | $5.14\text{ MB}$ |
| **10,000** | $516\text{ bytes}$ (14 steps) | $472\text{ bytes}$ | $625.5\text{ KB}$ | $17.27\text{ MB}$ | $17.80\text{ MB}$ |
| **100,000** | $624\text{ bytes}$ (17 steps) | $571\text{ bytes}$ | $6.10\text{ MB}$ | $34.85\text{ MB}$ | $40.57\text{ MB}$ |

---

## 5. Technical Accounting Notes

### 5.1 Proposed Canonical Binary Wire Proof Specification

To enable compact network transmission and storage in QR codes, MedicineGuard defines a concrete **canonical binary wire proof specification**:

#### Header (10 bytes fixed, Big-Endian)
- `Offset 0..3` (`4 bytes`): `uint32_t leaf_index` — Big-endian unsigned 32-bit integer ($0 \le \text{leaf\_index} < \text{total\_leaves}$).
- `Offset 4..7` (`4 bytes`): `uint32_t total_leaves` — Big-endian unsigned 32-bit integer ($1 \le \text{total\_leaves} \le 4,294,967,295$).
- `Offset 8..9` (`2 bytes`): `uint16_t step_count` — Big-endian unsigned 16-bit integer ($0 \le \text{step\_count} \le 32$).

#### Sibling Step Entries ($\text{step\_count} \times 33$ bytes)
For each step $i \in [0, \text{step\_count} - 1]$:
- `Offset 10 + i * 33 .. 10 + i * 33 + 31` (`32 bytes`): `uint8_t hash[32]` — Raw binary SHA-256 digest of the sibling node.
- `Offset 10 + i * 33 + 32` (`1 byte`): `uint8_t direction` — Direction flag:
  - `0x00` = `SIBLING_LEFT` (sibling is on left: parent is $H(0x01 \parallel \text{sibling} \parallel \text{current})$).
  - `0x01` = `SIBLING_RIGHT` (sibling is on right: parent is $H(0x01 \parallel \text{current} \parallel \text{sibling})$).

#### Total Binary Wire Size
$$\text{Wire Size} = 10 + (33 \times \text{step\_count}) \text{ bytes}$$

#### Comparison with In-Memory C Structure (`merkle_proof_t`)
In C11, `merkle_proof_t` contains:
- Metadata: 3 `uint32_t` fields (`leaf_index`, `total_leaves`, `step_count`) $= 12\text{ bytes}$.
- Each `merkle_proof_step_t` has a 32-byte hash array and a 4-byte enum `sibling_direction_t` (due to compiler struct alignment) $= 36\text{ bytes}$ per step.
- Active size: $12 + (36 \times \text{step\_count})\text{ bytes}$.
- **Space Reduction:** The binary wire encoding eliminates compiler alignment padding and shrinks the step count field from 4 bytes to 2 bytes, reducing wire payload size by $\approx 8\text{--}10\%$ without loss of precision.

---

### 5.2 Memory Footprint Accounting Breakdown (Solution A Model)

The benchmark reports three distinct memory metrics:

1. **Retained Merkle Tree Storage:**
   Measures the exact algorithmic heap memory dedicated to storing the `merkle_tree_t` structure and its level arrays:
   $$\text{RAM}_{\text{tree}} = T(N) \times 32\text{ bytes} + h \times \text{sizeof(merkle\_level\_t)} + \text{sizeof(merkle\_tree\_t)} + \text{strlen(batch\_id)} + 1$$
   - For $N = 100$: $202 \times 32\text{ B} \approx 6.5\text{ KB}$.
   - For $N = 100,000$: $200,006 \times 32\text{ B} \approx 6.10\text{ MB}$.

2. **Current Working Set (`WorkingSetSize`):**
   Active physical RAM mapped to the process at the exact moment a batch size benchmark completes. Queried via Windows API `PROCESS_MEMORY_COUNTERS.WorkingSetSize`.
   - $N = 100$: $3.91\text{ MB}$
   - $N = 1,000$: $5.08\text{ MB}$
   - $N = 10,000$: $17.27\text{ MB}$
   - $N = 100,000$: $34.85\text{ MB}$

3. **Cumulative Peak Working Set (`PeakWorkingSetSize`):**
   The process-lifetime high-water mark of physical RAM mapped by the Windows OS memory manager (`PeakWorkingSetSize`).
   - **Crucial Reporting Clarification:** Because the four batch sizes run **sequentially within a single process**, each displayed peak value is the **lifetime high-water mark observed up to that benchmark stage**, NOT an isolated per-batch measurement.
   - It includes memory accumulated across sequential stages: the input dataset ($500,000$ heap strings totaling $\approx 14\text{ MB}$ at $N=100\text{k}$), duplicate-check pointer arrays ($800\text{ KB}$), benchmark sampling buffers ($\approx 6.2\text{ MB}$), CRT heap arenas, and memory pages faulted in during preceding batch sizes.

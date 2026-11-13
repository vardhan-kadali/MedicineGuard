# MedicineGuard — Asymptotic Complexity & Empirical Performance Analysis
**Course Alignment:** Design and Analysis of Algorithms (DAA)  
**Subject:** Divide and Conquer, Binary Trees, Cryptographic Accumulators  

---

## 1. Asymptotic Complexity Formulations

Let:
- $N$ = Number of individual medicine units in a batch.
- $L$ = Byte length of the canonical serialized medicine record ($\approx 65 \dots 80$ bytes).

| Operation | Asymptotic Time Complexity | Asymptotic Space Complexity | Practical Scale ($N = 10,000$) | Practical Scale ($N = 100,000$) |
|---|---|---|---|---|
| **Record Serialization** | $\Theta(L)$ | $\Theta(L)$ | $< 0.1 \mu\text{s}$ per record | $< 0.1 \mu\text{s}$ per record |
| **Leaf Hashing** | $\Theta(L)$ | $\Theta(1)$ | $\approx 15 \mu\text{s}$ per record | $\approx 15 \mu\text{s}$ per record |
| **Batch Tree Construction** | $\Theta(N \cdot L + N)$ | $\Theta(N)$ | $\approx 36 \text{ ms}$ total | $\approx 385 \text{ ms}$ total |
| **Root Hash Retrieval** | $\Theta(1)$ | $\Theta(1)$ | Instantaneous | Instantaneous |
| **Single Proof Generation** | $\Theta(\log N)$ | $\Theta(\log N)$ | $\approx 0.96 \mu\text{s}$ | $\approx 0.96 \mu\text{s}$ |
| **Batch Proof Generation (All $N$)**| $\Theta(N \log N)$ | $\Theta(N \log N)$ | $\approx 9.6 \text{ ms}$ | $\approx 96 \text{ ms}$ |
| **Single Proof Verification** | $\Theta(\log N)$ | $\Theta(1)$ | $\approx 22.5 \mu\text{s}$ ($0.022 \text{ ms}$) | $\approx 27.8 \mu\text{s}$ ($0.027 \text{ ms}$) |
| **Tree In-Memory Storage** | — | $\Theta(N)$ | $625.5 \text{ KB}$ | $6.10 \text{ MB}$ |
| **Individual Proof Size** | — | $\Theta(\log N)$ | $516 \text{ bytes}$ (14 steps) | $624 \text{ bytes}$ (17 steps) |

---

## 2. Mathematical Proofs of Complexity

### 2.1 Proof of Tree Construction Time $\Theta(N)$
A common misconception in DAA is assuming tree construction takes $O(N \log N)$. 

Let $T(N)$ be the number of SHA-256 operations required to build the internal nodes of a balanced binary Merkle Tree with $N$ leaves:
- Level 0 (Leaves): $N$ records are hashed once $\rightarrow N$ operations.
- Level 1: $N / 2$ parent hashes.
- Level 2: $N / 4$ parent hashes.
- Level $k$: $N / 2^k$ parent hashes.
- Root Level ($\lceil \log_2 N \rceil$): $1$ parent hash.

Summing all internal node operations:
$$\text{Internal Operations} = \sum_{k=1}^{\lceil \log_2 N \rceil} \frac{N}{2^k} = N \sum_{k=1}^{\lceil \log_2 N \rceil} \left(\frac{1}{2}\right)^k$$

Using the sum of a finite geometric series $S = \frac{a(1 - r^m)}{1 - r}$ with $a = 1/2, r = 1/2$:
$$\sum_{k=1}^m \left(\frac{1}{2}\right)^k = \frac{\frac{1}{2}\left(1 - \frac{1}{2^m}\right)}{1 - \frac{1}{2}} = 1 - \frac{1}{2^m} < 1$$

Therefore:
$$\text{Internal Operations} < N \cdot 1 = N$$

Total SHA-256 operations = Leaves ($N$) + Internal Nodes ($< N$) $\le 2N - 1$.
Because each SHA-256 compression over two 32-byte hashes (65 bytes with prefix) is bounded by a constant time $c$:
$$T(N) = c \cdot (2N - 1) = \Theta(N)$$

### 2.2 Proof of Verification Time $\Theta(\log N)$
To verify a single medicine unit:
1. Serialize record and compute leaf hash: $1$ hash of length $L \rightarrow \Theta(L) = \Theta(1)$ for fixed-size records.
2. Traverse tree path from level 0 to root. At each level $k$, exactly one 65-byte parent hash is computed with the sibling:
   $$\text{Tree Height} = h = \lceil \log_2 N \rceil$$
   $$\text{Total Hashes} = 1 + h = 1 + \lceil \log_2 N \rceil = \Theta(\log N)$$
3. Root comparison: 32 bytes compared in constant time $\Theta(1)$.

Thus, verification time is strictly **logarithmic** with respect to batch size $N$. For $N = 10,000$, $h = 14$. For $N = 100,000$, $h = 17$.

---

## 3. Empirical Benchmark Results

The following measurements were captured using the native C benchmarking utility (`core-c/benchmarks/benchmark.c`) compiled with GCC 16.2.0 (`-O3`) on a 64-bit Windows workstation using `QueryPerformanceCounter` high-resolution monotonic timing.

| Batch Size ($N$) | Total Tree Nodes | Tree Build Time | Proof Gen (per unit) | Verify Time (per unit) | Single Proof Size | In-Memory RAM |
|---|---|---|---|---|---|---|
| **100** | 202 nodes | $0.33 \text{ ms}$ | $0.81 \mu\text{s}$ | $10.46 \mu\text{s}$ | $264 \text{ bytes}$ | $6.5 \text{ KB}$ |
| **1,000** | 2,001 nodes | $3.38 \text{ ms}$ | $0.68 \mu\text{s}$ | $16.50 \mu\text{s}$ | $372 \text{ bytes}$ | $62.8 \text{ KB}$ |
| **10,000** | 20,005 nodes | $36.69 \text{ ms}$ | $0.96 \mu\text{s}$ | $22.52 \mu\text{s}$ | $516 \text{ bytes}$ | $625.5 \text{ KB}$ |
| **100,000** | 200,006 nodes | $384.88 \text{ ms}$ | $0.96 \mu\text{s}$ | $27.83 \mu\text{s}$ | $624 \text{ bytes}$ | $6.10 \text{ MB}$ |

---

## 4. Key Takeaways for DAA Evaluation

1. **Linear Scalability:** Building a 10,000-unit batch tree requires only **$36.7\text{ ms}$**. Scaling to 100,000 units takes **$0.38\text{ seconds}$**, perfectly matching the theoretical $\Theta(N)$ curve.
2. **Microsecond Verification:** Verifying an individual medicine package takes **$22.5 \mu\text{s}$** (over $44,000$ verifications per second per CPU core). This enables pharmacists and customers to experience instantaneous verification.
3. **Compact Footprint:** The entire tree for 10,000 units occupies just **$625.5\text{ KB}$** of RAM, making it easily embeddable within browser WebAssembly linear memory in Phase 2.
4. **Bandwidth Efficiency:** A single proof for 10,000 units is **$516\text{ bytes}$**, fitting comfortably inside a single HTTP packet or URL payload.

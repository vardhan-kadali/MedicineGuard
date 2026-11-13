# MedicineGuard — Medicine Batch Traceability and Verification Using Merkle Trees

**MedicineGuard** is an academic Data Structures and Algorithms (DAA) and Applied Cryptography project demonstrating how cryptographic hashing (SHA-256) and Merkle Trees can provide scalable, tamper-evident digital record traceability for pharmaceutical medicine batches.

---

## 📌 Project Overview

In a pharmaceutical supply chain, verifying whether an individual medicine blister pack belongs to an authentic manufacturer batch is challenging. Storing thousands of individual digital signatures or records in centralized ledgers is computationally expensive and difficult to scale.

**MedicineGuard** solves this by:
1. Creating a deterministic digital record for every medicine unit.
2. Building a balanced binary **Merkle Tree** from all individual unit hashes.
3. Committing the entire batch of $N$ units into a single 32-byte **Merkle Root**.
4. Generating a compact **Merkle Proof** ($\lceil \log_2 N \rceil$ sibling hashes) for every individual package.
5. Enabling instantaneous, offline-capable verification ($O(\log N)$) by pharmacists and customers using a standard smartphone or web browser.

---

## 🚀 Phase 1 Status: Native C Engine

Phase 1 implements the complete, standalone cryptographic and data structure engine in **standard C11 with zero external dependencies**.

### Key Implemented Components:
- **Standalone FIPS 180-4 SHA-256:** Pure C implementation validated against NIST test vectors.
- **Deterministic Record Serialization:** Canonical `MG01` binary serialization format ensuring bit-for-bit equivalence between C/WASM and JavaScript.
- **Domain Separation:** RFC 6962 compliant prefix hashing (`0x00` for leaves, `0x01` for internal parent nodes) to eliminate second-preimage collision attacks.
- **Merkle Tree Construction:** Balanced binary tree construction with deterministic odd-node promotion (unpaired nodes promoted unchanged without Bitcoin-style duplicate node vulnerabilities).
- **Merkle Proof Generation & Verification:** Directional sibling paths (`LEFT`/`RIGHT`) with constant-time memory comparison (`crypto_memcmp`) to prevent timing side-channel attacks.
- **Automated Test Suite:** 61 automated tests covering small trees (1, 2, 3, 5, 7, 8), large batches (100, 1,000, 10,000 units), and negative security tampering tests.
- **Empirical Benchmarking Utility:** High-resolution monotonic timer benchmarking across 100 to 100,000 units.

---

## 📂 Repository Structure

```
MedicineGuard/
├── README.md
├── .gitignore
├── Makefile                         # Cross-platform Makefile (Linux / macOS / MinGW)
├── core-c/                          # Pure C11 DAA Engine
│   ├── include/
│   │   ├── sha256.h                 # Standalone SHA-256 interface
│   │   └── merkle.h                 # Merkle Tree data structures & function prototypes
│   ├── src/
│   │   ├── sha256.c                 # FIPS 180-4 SHA-256 implementation
│   │   └── merkle.c                 # Serialization, tree building, proofs & verification
│   ├── tests/
│   │   ├── test_sha256.c            # NIST test vectors (empty, 'abc', 56-char, 1M 'a's)
│   │   └── test_merkle.c            # 61-test suite (odd nodes, 10k batch, negative tests)
│   └── benchmarks/
│       └── benchmark.c              # High-resolution performance benchmarks
├── scripts/
│   ├── build.bat                    # Windows batch build script (GCC auto-detection)
│   ├── test.bat                     # Windows automated test runner
│   └── benchmark.bat                # Windows benchmark execution script
└── docs/
    ├── ALGORITHM_DESIGN.md          # Theoretical principles, pseudocode & viva guide
    ├── RECORD_FORMAT.md             # Canonical binary serialization standard (MG01)
    └── COMPLEXITY_ANALYSIS.md       # Asymptotic proofs & empirical benchmark analysis
```

---

## 🛠️ Quick Start (Windows)

### Prerequisites
- GCC compiler (e.g., MinGW-w64 / MSYS2 UCRT64).

### 1. Build the Engine
Run the build script to compile the object files and binaries into `build/`:
```cmd
scripts\build.bat
```

### 2. Run the Automated Test Suite
Execute the full test suite (SHA-256 NIST tests + Merkle Tree & negative tampering tests):
```cmd
scripts\test.bat
```

### 3. Run Performance Benchmarks
Run high-resolution benchmarks across batch sizes ($N = 100, 1000, 10000, 100000$):
```cmd
scripts\benchmark.bat
```

---

## 📊 Empirical Performance Summary

Benchmarked on a 64-bit Windows workstation using GCC 16.2.0 (`-O3`), 7 measured trials per batch size (median reported), preceded by a discarded warm-up run:

| Batch Size ($N$) | Tree Nodes (Height) | Batch Validation | Pure Tree Build | End-to-End Build | Proof Gen (per unit) | Pure Path Verify | End-to-End Verify | Wire Proof Size | Retained Tree RAM | Peak Process RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| **100** | 202 ($h = 8$) | 0.03 ms | 0.40 ms | 0.43 ms | 0.15 μs | 11.49 μs | 12.97 μs | 241 B | 6.5 KB | 3.96 MB |
| **1,000** | 2,001 ($h = 11$) | 0.29 ms | 2.95 ms | 3.55 ms | 0.19 μs | 13.87 μs | 14.97 μs | 340 B | 62.8 KB | 5.12 MB |
| **10,000** | 20,005 ($h = 15$) | 2.60 ms | 25.58 ms | 28.79 ms | 0.22 μs | 12.99 μs | 15.30 μs | 472 B | 625.5 KB | 17.79 MB |
| **100,000** | 200,006 ($h = 18$) | 51.52 ms | 362.79 ms | 428.36 ms | 0.31 μs | 26.90 μs | 29.76 μs | 571 B | 6.10 MB | 40.59 MB |

*Note: For detailed mathematical proofs ($\Theta(N)$ tree construction vs $\Theta(N \log N)$ validation sorting), representative sampling methodology, and memory breakdown, see [docs/COMPLEXITY_ANALYSIS.md](docs/COMPLEXITY_ANALYSIS.md).*

---

## 🗺️ Future Phases

- **Phase 2 (WebAssembly & JS Bridge):** Compile `core-c` to `medicineguard.wasm` via Emscripten / Clang and implement `wasm-loader.js`.
- **Phase 3 (Edge Storage & APIs):** Deploy Cloudflare Pages Functions and Cloudflare D1 for shared batch storage and verification logs.
- **Phase 4 (Frontend UI & QR Code Scanner):** Implement the unified web application with Manufacturer, Pharmacist, and Customer experiences using `html5-qrcode`.
- **Phase 5 (Tree Visualizer & Academic Viva Polish):** Interactive canvas tree visualizer highlighting verification paths and academic documentation.


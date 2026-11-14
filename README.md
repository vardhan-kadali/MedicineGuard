# MedicineGuard — Medicine Batch Traceability and Verification Using Merkle Trees

**MedicineGuard** is an academic Data Structures and Algorithms (DAA) and Applied Cryptography project demonstrating how cryptographic hashing (FIPS 180-4 SHA-256) and binary Merkle Trees provide scalable, tamper-evident digital record traceability for pharmaceutical medicine batches.

---

## 📌 Project Overview

In pharmaceutical supply chains, verifying whether an individual medicine package belongs to an authentic manufacturer batch is computationally challenging. Storing thousands of individual digital signatures or records in centralized ledgers is expensive and fragile.

**MedicineGuard** solves this by:
1. Creating deterministic digital records for every medicine unit using the canonical **MG01** serialization protocol.
2. Building a balanced binary **Merkle Tree** using domain-separated leaf (`0x00`) and parent (`0x01`) SHA-256 hashing.
3. Handling arbitrary batch sizes deterministically using **odd-node promotion** (unpaired nodes promoted unchanged without hashing).
4. Committing the entire batch of $N$ units into a single 32-byte **Merkle Root**.
5. Generating compact **MGP1** Merkle Proofs ($O(\log N)$ sibling hashes) for every individual package.
6. Enabling instant, offline-capable verification by Pharmacists and Customers using a standard browser or mobile device.
7. Providing a real-time, interactive **Merkle Tree Visualizer** that highlights cryptographic proof paths and odd-node promotions with bit-for-bit mathematical fidelity.

---

## 🛡️ Physical Authenticity Boundary & Mandatory Disclaimer

> [!IMPORTANT]
> **MedicineGuard Trust & Security Boundary:**
> 
> MedicineGuard establishes the integrity and provenance of the **digital medicine record** against a cryptographically committed Merkle Tree root. It proves mathematically that the digital unit record has not been altered since the batch commitment was calculated.
> 
> *Mandatory Regulatory Disclaimer:*
> "MedicineGuard verifies the digital medicine record against a registered Merkle Tree commitment. This does not independently establish the physical medicine's chemical composition, safety, storage conditions, manufacturer legitimacy or guarantee that the QR code has not been copied."

---

## 🚀 Completed Project Milestones

| Milestone | Component | Key Capabilities | Automated Tests |
|---|---|---|---|
| **Phase 1** | Native C11 Engine | Standalone FIPS 180-4 SHA-256, MG01 canonical serialization, domain separation (0x00/0x01), odd-node promotion, MGP1 proofs. | **67 / 67 PASS** |
| **Phase 2** | WebAssembly ABI | Emscripten wasm32 compilation, generational handle pool (32 slots), dynamic `HEAPU8` tracking, JavaScript ABI loader (`wasm-loader.js`). | **314 / 314 PASS** |
| **Phase 3A** | UI Foundation | Pure Vanilla HTML5/CSS3/ES6 responsive dashboard, zero external UI frameworks, zero CDNs, role switching. | Foundation Verified |
| **Phase 3B** | Manufacturer Portal | In-browser C/WASM tree generation, Merkle Root commitment, calendar date validation, tamper detection. | **388 / 388 PASS** |
| **Phase 3C** | Pharmacist Portal | Local and shared batch lookup, MGP1 proof verification via C engine, negative security alteration tests. | **177 / 177 PASS** |
| **Phase 3D** | Backend & Registry | Cloudflare Pages Functions, SQLite D1 database, PBKDF2-HMAC-SHA256 authentication (600k iterations), RBAC, audit logging. | **139 / 139 PASS** |
| **Phase 4** | Customer & QR Portal | Offline QR code generation (`qrcode.js`), camera scanner (`jsQR`), 32-char hex references, batch recall/revocation. | **94 / 94 PASS** |
| **Phase 5** | Merkle Visualizer & Hardening | Interactive SVG tree visualizer, proof path highlighting, rate limiting & abuse mitigation, security headers, full regression. | **140 / 140 PASS** |
| **TOTAL** | **Cumulative Test Suite** | **All 7 Automated Test Suites Passing (100% Success Rate)** | **1,319 / 1,319 PASS** |

---

## 🏗️ Architecture & Component Layout

```
                                  +---------------------------------------+
                                  |           MedicineGuard Web           |
                                  |   HTML5 / CSS3 / Vanilla ES6 Module   |
                                  +---------------------------------------+
                                     /                  |                 \
                                    /                   |                  \
                                   v                    v                   v
                     +--------------------+   +-------------------+   +--------------------+
                     |  WebAssembly Core  |   |  Cloudflare Pages |   | Interactive Merkle |
                     | (C11 via Emscripten|   |     Functions     |   |   Tree Visualizer  |
                     |  medicineguard.wasm|   |  (/api/* Backend) |   | (SVG / Canvas DOM) |
                     +--------------------+   +-------------------+   +--------------------+
                                |                       |                       |
                     +--------------------+   +-------------------+   +--------------------+
                     | FIPS 180-4 SHA-256 |   |   Cloudflare D1   |   | Bit-for-bit Parity |
                     | Domain Separation  |   |  SQLite Database  |   | Proof Path Tracing |
                     | Odd Promotion C11  |   | Shared Batch Reg. |   | Odd Promotion Path |
                     +--------------------+   +-------------------+   +--------------------+
```

---

## 🌳 Interactive Merkle Tree Visualizer (Phase 5)

Accessible directly under the **Algorithm & System Status** section (`#status` or `/#visualizer`), the visualizer provides:
- **Topological Layout:** Displays the Root (Level $H-1$), intermediate levels, and leaf units (Level 0) with distinct level badges.
- **Odd-Node Promotion Paths:** Clearly tags unpaired nodes promoted unchanged without hashing with dashed violet borders and `ODD-PROMOTED` badges.
- **Interactive Unit Tracing:** Clicking any leaf node highlights its active path up to the root in bright emerald green, and distinguishes between **Right Siblings** (Amber) and **Left Siblings** (Cyan).
- **Mathematical Progression Inspector:** Displays the step-by-step cryptographic hash accumulation:
  $$H_{\text{leaf}} = \text{SHA-256}(0x00 \ || \ \text{MG01}(\text{unit}))$$
  $$H_{\text{parent}} = \text{SHA-256}(0x01 \ || \ H_{\text{left}} \ || \ H_{\text{right}})$$
- **Large-Batch Support ($N \ge 32$):** Offers **Focused Proof Path View** to render only the active proof path and its direct siblings, keeping DOM element counts at $O(\log N)$ and guaranteeing sub-10ms rendering for batches up to 10,000 units.
- **Pan & Zoom Controls:** Interactive drag-to-pan, mousewheel zoom, reset view, and fit-to-width.

---

## 🔒 Security Hardening & Abuse Mitigation

1. **Strict Input Validation:** `GET /api/public/verify` strictly enforces 32-character hexadecimal format using regex before any database query is executed.
2. **Database Write Throttling:** Failed lookups (`NOT_FOUND`) are rate-limited per client IP hash. If a client exceeds 10 failed lookups in a 60-second window, the service skips writing to the `customer_verifications` audit table and responds with `429 Too Many Requests` (`RATE_LIMIT_EXCEEDED`), protecting D1 database storage from automated scrapers.
3. **Security Headers:** Enforced via `public/_headers`:
   - `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; media-src 'self' blob:;`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: camera=(self), microphone=(), geolocation=()`

---

## 🛠️ Running the Automated Test Suites

All test suites execute locally on Windows without external CDNs or remote dependencies:

```cmd
# 1. Run all test suites cumulatively (1,320 assertions)
npm run test:all

# 2. Individual Phase Suites:
npm run test:native     # Phase 1: Native C SHA-256 & Merkle Tree (67 tests)
npm run test:wasm       # Phase 2: WebAssembly ABI & Generational Handles (314 tests)
npm run test:phase3b    # Phase 3B: Manufacturer Registration & Proof Audit (388 assertions)
npm run test:phase3c    # Phase 3C: Pharmacist Portal & Tamper Resistance (177 assertions)
npm run test:phase3d    # Phase 3D: Cloudflare Functions, D1 DB & Auth (139 assertions)
npm run test:phase4     # Phase 4: QR Codes & Customer Verification (95 assertions)
npm run test:phase5     # Phase 5: Merkle Visualizer & Hardening (140 assertions)
```

---

## 💻 Local Development Workflow

To launch the local Cloudflare Pages dev server with local D1 database:

```cmd
# Apply database migrations to local D1 instance
npx wrangler d1 migrations apply medicineguard-db --local

# Start local dev server on port 8788
npx wrangler pages dev public --port=8788
```

Open your browser to:
```
http://127.0.0.1:8788/
```

### Initial Administrator Bootstrap
1. In the top bar, click **Sign In**.
2. Select the **Admin Bootstrap** tab.
3. Enter email `admin@medicineguard.local`, your desired admin password, and the local bootstrap secret configured in your private `.dev.vars` file (`BOOTSTRAP_ADMIN_SECRET`).
4. Once authenticated, manage accounts in the **Admin Portal** to provision Manufacturer and Pharmacist users. Note: the bootstrap endpoint permanently rejects subsequent calls once an administrator exists (`ADMIN_ALREADY_EXISTS`).

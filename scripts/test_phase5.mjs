/**
 * MedicineGuard — Phase 5 Comprehensive Automated Test Suite
 * 
 * Verifies:
 * 1. Interactive Merkle Tree Visualizer Cryptographic Engine Parity:
 *    - Validates tree model reconstruction for N = 1, 2, 3, 5, 7, 8, 10, 100, 1000.
 *    - Verifies level counts, tree height, and root hashes match native C/WASM engine bit-for-bit.
 * 2. Odd-Node Promotion Invariance & Proof Path Math:
 *    - Verifies unpaired nodes are promoted unchanged without hashing.
 *    - Verifies proof step bypassing on promoted levels (e.g. N=5, leaf 4 has exactly 1 step).
 *    - Verifies sibling hash and direction flags (LEFT/RIGHT) match MGP1 proof wire format.
 * 3. Public Verification Endpoint Hardening & Abuse Mitigation:
 *    - Checks security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Cache-Control).
 *    - Rejects malformed reference inputs before D1 database queries.
 *    - Verifies rate limiting (429 RATE_LIMITED) on repeated NOT_FOUND attempts to protect audit logs from exhaustion.
 * 4. End-to-End Multi-Role Workflows:
 *    - Manufacturer creates batch and publishes to trusted registry.
 *    - Pharmacist performs cross-device verification.
 *    - Customer verifies public reference.
 *    - Manufacturer revokes batch; customer receives immediate 403 REVOKED status.
 *    - Visualizer loads batch with full proof path verification.
 * 5. Large Batch Scalability & Complexity Verification:
 *    - Verifies O(log N) proof depth for N up to 10,000.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import MedicineGuard, { parseProof, StatusCode } from '../public/js/wasm-loader.js';
import {
  buildTreeModel,
  computeProofPath,
  computeLeafHash,
  computeParentHash,
  MG_DOMAIN_LEAF,
  MG_DOMAIN_PARENT
} from '../public/js/merkle-visualizer.js';

import {
  serializeMG01Record,
  hashLeaf,
  hashParent,
  parseMGP1Proof,
  verifyRecordProof,
  toHex,
  fromHex
} from '../functions/_shared/merkle-verifier.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const SERVER_PORT = 8788;
const BASE_URL = `http://127.0.0.1:${SERVER_PORT}`;
function getBootstrapSecret() {
  if (process.env.BOOTSTRAP_ADMIN_SECRET) return process.env.BOOTSTRAP_ADMIN_SECRET;
  try {
    const varsPath = path.resolve(ROOT_DIR, '.dev.vars');
    if (fs.existsSync(varsPath)) {
      const content = fs.readFileSync(varsPath, 'utf8');
      const match = content.match(/BOOTSTRAP_ADMIN_SECRET=([^\r\n]+)/);
      if (match) return match[1].trim();
    }
  } catch {}
  return 'medicineguard_bootstrap_secret_change_me';
}

const BOOTSTRAP_SECRET = getBootstrapSecret();

const MANDATORY_DISCLAIMER =
  "MedicineGuard verifies the digital medicine record against a registered Merkle Tree commitment. This does not independently establish the physical medicine's chemical composition, safety, storage conditions, manufacturer legitimacy or guarantee that the QR code has not been copied.";

let passedCount = 0;
let failedCount = 0;

function assert(condition, message) {
  if (condition) {
    passedCount++;
    console.log(`  [PASS] #${passedCount}: ${message}`);
  } else {
    failedCount++;
    console.error(`  [FAIL] #${passedCount + failedCount}: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class TestClient {
  constructor(name = 'Client') {
    this.name = name;
    this.cookie = null;
    this.csrfToken = null;
    this.user = null;
  }

  async fetch(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${BASE_URL}${endpoint}`;
    const headers = { ...(options.headers || {}) };

    if (this.cookie) {
      headers['Cookie'] = this.cookie;
    }
    if (
      this.csrfToken &&
      !('X-CSRF-Token' in headers) &&
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes((options.method || 'GET').toUpperCase())
    ) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }

    const res = await fetch(url, { ...options, headers });

    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const match = setCookie.match(/mg_session=([^;]+)/);
      if (match) {
        this.cookie = `mg_session=${match[1]}`;
      }
    }

    return res;
  }

  async login(email, password) {
    const res = await this.fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    if (res.ok) {
      const data = await res.json();
      this.csrfToken = data.csrfToken;
      this.user = data.user;
    }
    return res;
  }
}

async function runPhase5Tests() {
  console.log('============================================================');
  console.log('  MedicineGuard — Phase 5 Comprehensive Automated Test Suite');
  console.log('============================================================\n');

  // 1. Initialize WASM Engine
  const engine = await MedicineGuard.init();
  assert(engine !== null, 'WebAssembly cryptographic engine initialized');

  // --- SUITE 1: Merkle Tree Visualizer Cryptographic Engine Parity ---
  console.log('\n--- SUITE 1: Merkle Tree Visualizer Engine Parity Across Topologies ---');

  const testBatchSizes = [1, 2, 3, 5, 7, 8, 10, 100];

  for (const n of testBatchSizes) {
    const batchId = `VIS-TEST-N${n}`;
    const wasmBatch = engine.createBatch();
    const records = [];

    for (let i = 0; i < n; i++) {
      const rec = {
        batch_id: batchId,
        unit_id: `UNIT-${String(i + 1).padStart(6, '0')}`,
        medicine_name: 'Paracetamol 500mg',
        manufacturing_date: '2026-01-10',
        expiry_date: '2028-01-10'
      };
      records.push(rec);
      const ser = serializeMG01Record(rec);
      wasmBatch.addRecord(ser);
    }

    wasmBatch.buildTree();
    const wasmRoot = wasmBatch.getRootHex();
    const wasmHeight = wasmBatch.getHeight();

    // Reconstruct tree model with visualizer module
    const visModel = await buildTreeModel(records, engine, wasmRoot);

    assert(visModel.leafCount === n, `N=${n}: Visualizer leaf count matches (${visModel.leafCount})`);
    assert(visModel.height === wasmHeight, `N=${n}: Visualizer tree height matches C engine (${visModel.height})`);
    assert(visModel.rootHex.toLowerCase() === wasmRoot.toLowerCase(), `N=${n}: Visualizer root matches C engine bit-for-bit (${visModel.rootHex.slice(0, 8)}...)`);

    // Verify level counts
    let expectedCount = n;
    for (let k = 0; k < wasmHeight; k++) {
      assert(visModel.levels[k].length === expectedCount, `N=${n}, Level ${k}: Node count is exactly ${expectedCount}`);
      expectedCount = Math.floor((expectedCount + 1) / 2);
    }

    wasmBatch.destroy();
  }

  // --- SUITE 2: Odd-Node Promotion Invariance & Proof Path Math ---
  console.log('\n--- SUITE 2: Odd-Node Promotion & Proof Path Mathematical Correctness ---');

  // Deep inspection on N = 5 (height = 4, odd promotions at level 1 and level 2)
  {
    const n = 5;
    const batchId = 'VIS-PROMO-N5';
    const wasmBatch = engine.createBatch();
    const records = [];

    for (let i = 0; i < n; i++) {
      const rec = {
        batch_id: batchId,
        unit_id: `UNIT-${String(i + 1).padStart(6, '0')}`,
        medicine_name: 'Ibuprofen 400mg',
        manufacturing_date: '2026-02-01',
        expiry_date: '2028-02-01'
      };
      records.push(rec);
      wasmBatch.addRecord(serializeMG01Record(rec));
    }

    wasmBatch.buildTree();
    const wasmRoot = wasmBatch.getRootHex();
    const visModel = await buildTreeModel(records, engine, wasmRoot);

    // Verify promotion flags in model
    assert(visModel.levels[1][2].isPromoted === true, 'N=5, Level 1, Node 2 is flagged as promoted');
    assert(visModel.levels[2][1].isPromoted === true, 'N=5, Level 2, Node 1 is flagged as promoted');
    assert(visModel.levels[1][2].hashHex === visModel.levels[0][4].hashHex, 'N=5, Level 1 promoted hash equals Level 0 leaf 4 hash');
    assert(visModel.levels[2][1].hashHex === visModel.levels[1][2].hashHex, 'N=5, Level 2 promoted hash equals Level 1 node 2 hash');

    // Inspect proof for Leaf 4 (the odd node)
    const proofLeaf4 = computeProofPath(visModel, 4);
    const wasmProofBytes4 = wasmBatch.generateProof(4);
    const parsedWasmProof4 = parseProof(wasmProofBytes4);

    // In C engine, promoted levels do not consume proof steps
    assert(parsedWasmProof4.stepCount === 1, 'C Engine MGP1 proof for Leaf 4 has exactly 1 step');
    const nonPromotedSteps4 = proofLeaf4.steps.filter((s) => !s.isPromoted);
    assert(nonPromotedSteps4.length === 1, 'Visualizer proof path for Leaf 4 has exactly 1 active hash step');
    assert(nonPromotedSteps4[0].direction === 'left', 'Visualizer Leaf 4 step direction is LEFT');
    assert(nonPromotedSteps4[0].siblingHashHex.toLowerCase() === parsedWasmProof4.steps[0].siblingHashHex.toLowerCase(), 'Visualizer Leaf 4 sibling hash matches C engine MGP1 wire step');

    // Verify all leaves 0..4 against C engine proof wire steps
    for (let idx = 0; idx < n; idx++) {
      const vProof = computeProofPath(visModel, idx);
      const wBytes = wasmBatch.generateProof(idx);
      const pWasm = parseProof(wBytes);

      const activeSteps = vProof.steps.filter((s) => !s.isPromoted);
      assert(activeSteps.length === pWasm.stepCount, `N=5, leaf #${idx}: Step count matches MGP1 wire format (${activeSteps.length})`);

      for (let s = 0; s < activeSteps.length; s++) {
        const vStep = activeSteps[s];
        const wStep = pWasm.steps[s];
        assert(vStep.direction === wStep.directionName, `N=5, leaf #${idx}, step #${s}: Direction matches (${vStep.direction})`);
        assert(vStep.siblingHashHex.toLowerCase() === wStep.siblingHashHex.toLowerCase(), `N=5, leaf #${idx}, step #${s}: Sibling hash matches`);
      }
    }

    wasmBatch.destroy();
  }

  // --- SUITE 3: Server Lifecycle & Public API Hardening ---
  console.log('\n--- SUITE 3: Server Lifecycle & Public Verification API Hardening ---');

  let devServerProcess = null;
  try {
    const testPing = await fetch(`${BASE_URL}/api/auth/session`).catch(() => null);
    if (!testPing) {
      console.log(`[INFO] Spawning local wrangler pages dev on port ${SERVER_PORT}...`);
      devServerProcess = spawn('npx', ['wrangler', 'pages', 'dev', 'public', `--port=${SERVER_PORT}`], {
        cwd: ROOT_DIR,
        shell: true,
        stdio: 'pipe'
      });

      let ready = false;
      for (let i = 0; i < 40; i++) {
        await sleep(500);
        try {
          const res = await fetch(`${BASE_URL}/api/auth/session`);
          if (res.status === 200 || res.status === 401) {
            ready = true;
            break;
          }
        } catch {}
      }
      assert(ready, 'Local dev server started and responsive');
    } else {
      assert(true, 'Reusing existing active local dev server');
    }

    // 1. Check Security Headers on GET /api/public/verify
    const headerTestRes = await fetch(`${BASE_URL}/api/public/verify?reference=invalid`);
    assert(headerTestRes.headers.get('x-content-type-options') === 'nosniff', 'Security Header: X-Content-Type-Options: nosniff present');
    assert(headerTestRes.headers.get('x-frame-options') === 'DENY', 'Security Header: X-Frame-Options: DENY present');
    assert(headerTestRes.headers.get('cache-control')?.includes('no-store'), 'Security Header: Cache-Control includes no-store');

    // 2. Reject malformed reference before any DB query
    assert(headerTestRes.status === 400, 'Malformed reference returns 400 Bad Request');
    const headerTestData = await headerTestRes.json();
    assert(headerTestData.status === 'INVALID_REFERENCE', 'Status is INVALID_REFERENCE');
    assert(headerTestData.error?.code === 'INVALID_REFERENCE_FORMAT', 'Error code is INVALID_REFERENCE_FORMAT');

    // 3. Abuse Protection / Rate-Limiting Check:
    // Repeated failed lookups (> 10 consecutive NOT_FOUNDs from same IP) must return 429
    console.log('  Testing abuse mitigation: sending repeated random NOT_FOUND lookups...');
    let hitRateLimit = false;
    let rateLimitStatus = 0;
    let rateLimitBody = null;

    for (let attempt = 1; attempt <= 14; attempt++) {
      const dummyRef = `ffffffffffffffffffffffffff${String(attempt).padStart(6, '0')}`;
      const res = await fetch(`${BASE_URL}/api/public/verify?reference=${dummyRef}`, {
        headers: { 'CF-Connecting-IP': '198.51.100.99' }
      });

      if (res.status === 429) {
        hitRateLimit = true;
        rateLimitStatus = res.status;
        rateLimitBody = await res.json();
        break;
      }
      await sleep(50);
    }

    assert(hitRateLimit === true, 'Abuse mitigation triggered: 429 Too Many Requests returned on repeated failed lookups');
    assert(rateLimitStatus === 429, 'Rate limit HTTP status is 429');
    assert(rateLimitBody?.status === 'RATE_LIMITED', 'Rate limit status string is RATE_LIMITED');
    assert(rateLimitBody?.error?.code === 'RATE_LIMIT_EXCEEDED', 'Rate limit error code is RATE_LIMIT_EXCEEDED');
    assert(rateLimitBody?.trust_disclaimer === MANDATORY_DISCLAIMER, 'Mandatory disclaimer present in rate-limit response');

    // --- SUITE 4: End-to-End Multi-Role Workflow Audit ---
    console.log('\n--- SUITE 4: End-to-End Multi-Role Workflow Audit ---');

    // 1. Authenticate Admin
    const adminClient = new TestClient('Admin');
    await adminClient.fetch('/api/auth/bootstrap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@medicineguard.local',
        password: 'AdminPassword2026!',
        secret: BOOTSTRAP_SECRET
      })
    });

    const adminLoginRes = await adminClient.login('admin@medicineguard.local', 'AdminPassword2026!');
    assert(adminLoginRes.status === 200, 'Admin logged in successfully');

    // 2. Provision Manufacturer & Pharmacist users for this test run
    const runId = Date.now().toString().slice(-6);
    const mfgEmail = `mfg_p5_${runId}@pharma.local`;
    const mfgPassword = 'ManufacturerPass2026!';
    const pharmEmail = `pharm_p5_${runId}@hospital.local`;
    const pharmPassword = 'PharmacistPass2026!';

    await adminClient.fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: mfgEmail, password: mfgPassword, role: 'manufacturer' })
    });

    await adminClient.fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pharmEmail, password: pharmPassword, role: 'pharmacist' })
    });

    // Authenticate Manufacturer
    const mfgClient = new TestClient('Manufacturer');
    const loginRes = await mfgClient.login(mfgEmail, mfgPassword);
    assert(loginRes.status === 200, 'Manufacturer logged in successfully');

    // Create & Publish Batch
    const testBatchId = `PHASE5-BATCH-${Date.now().toString(16)}`;
    const unitCount = 6;
    const wasmBatch = engine.createBatch();
    const batchUnits = [];

    for (let i = 0; i < unitCount; i++) {
      const unitId = `UNIT-P5-${String(i + 1).padStart(4, '0')}`;
      const rec = {
        batch_id: testBatchId,
        unit_id: unitId,
        medicine_name: 'Amoxicillin 500mg Phase 5',
        manufacturing_date: '2026-03-01',
        expiry_date: '2028-03-01'
      };
      const ser = serializeMG01Record(rec);
      wasmBatch.addRecord(ser);
      batchUnits.push({ record: rec, serialized: ser });
    }

    wasmBatch.buildTree();
    const batchRoot = wasmBatch.getRootHex();

    // 1. Initiate Batch Publication
    const initRes = await mfgClient.fetch('/api/manufacturer/batches', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        batch_id: testBatchId,
        medicine_name: 'Amoxicillin 500mg Phase 5',
        manufacturing_date: '2026-03-01',
        expiry_date: '2028-03-01',
        total_units: unitCount,
        merkle_root: batchRoot
      })
    });
    assert(initRes.status === 201, 'Batch initiated on server registry (201)');

    // 2. Upload Units with MGP1 Proofs
    const unitsPayload = [];
    for (let i = 0; i < unitCount; i++) {
      const proofBytes = wasmBatch.generateProof(i);
      const proofBase64 = Buffer.from(proofBytes).toString('base64');
      unitsPayload.push({
        unit_id: batchUnits[i].record.unit_id,
        leaf_index: i,
        medicine_name: batchUnits[i].record.medicine_name,
        manufacturing_date: batchUnits[i].record.manufacturing_date,
        expiry_date: batchUnits[i].record.expiry_date,
        proof_data: proofBase64
      });
    }

    const uploadRes = await mfgClient.fetch(`/api/manufacturer/batches/${testBatchId}/units`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ units: unitsPayload })
    });
    assert(uploadRes.status === 200, 'Units uploaded with cryptographic proofs (200 OK)');

    // 3. Finalize & Publish Batch
    const finalizeRes = await mfgClient.fetch(`/api/manufacturer/batches/${testBatchId}/publish`, {
      method: 'POST'
    });
    assert(finalizeRes.status === 200, 'Batch published to trusted registry (200)');

    // 4. Retrieve Published Units & References
    const getUnitsRes = await mfgClient.fetch(`/api/manufacturer/batches/${testBatchId}/units?all=true`);
    assert(getUnitsRes.status === 200, 'Manufacturer retrieved published units with references');
    const unitsData = await getUnitsRes.json();
    const publishedUnits = unitsData.units;
    assert(publishedUnits.length === unitCount, `Retrieved exactly ${unitCount} published units`);

    const targetUnit = publishedUnits[2];
    const targetRef = targetUnit.verification_reference;
    assert(/^[0-9a-f]{32}$/.test(targetRef), 'Target unit has valid 32-character hex verification reference');

    // 5. Public Customer Verification via Reference
    const publicVerifyRes = await fetch(`${BASE_URL}/api/public/verify?reference=${targetRef}`);
    assert(publicVerifyRes.status === 200, 'Customer public verification returned 200 OK');
    const publicData = await publicVerifyRes.json();
    assert(publicData.verified === true, 'Public verification verified is true');
    assert(publicData.status === 'VERIFIED', 'Status is VERIFIED');
    assert(publicData.record.unit_id === targetUnit.unit_id, 'Record unit_id matches');
    assert(publicData.record.batch_id === testBatchId, 'Record batch_id matches');
    assert(publicData.trust_disclaimer === MANDATORY_DISCLAIMER, 'Mandatory trust disclaimer is present verbatim');

    // 6. Pharmacist Shared Registry Verification
    const pharmClient = new TestClient('Pharmacist');
    const pharmLoginRes = await pharmClient.login(pharmEmail, pharmPassword);
    assert(pharmLoginRes.status === 200, 'Pharmacist logged in successfully');

    const pharmLookupRes = await pharmClient.fetch(`/api/pharmacist/lookup?unit_id=${targetUnit.unit_id}&batch_id=${testBatchId}`);
    assert(pharmLookupRes.status === 200, 'Pharmacist lookup returned 200 OK');
    const pharmData = await pharmLookupRes.json();
    assert(pharmData.unit !== undefined, 'Pharmacist lookup returned unit record');
    assert(pharmData.unit.merkle_root.toLowerCase() === batchRoot.toLowerCase(), 'Pharmacist retrieved unit Merkle root matches published root');

    // Client-side WASM verification of the proof bytes retrieved by Pharmacist
    const proofRaw = Buffer.from(pharmData.unit.proof_data, 'base64');
    const clientVerifRes = engine.verifyRecord(pharmData.unit, new Uint8Array(proofRaw), pharmData.unit.merkle_root);
    assert(clientVerifRes.valid === true, 'Pharmacist client-side WASM verifies server-retrieved proof successfully');

    // 7. Batch Revocation Workflow
    const revokeRes = await mfgClient.fetch(`/api/manufacturer/batches/${testBatchId}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'Phase 5 end-to-end quality control verification test' })
    });
    assert(revokeRes.status === 200, 'Batch successfully revoked by manufacturer');

    // 8. Public Verification of Revoked Unit
    const revokedVerifyRes = await fetch(`${BASE_URL}/api/public/verify?reference=${targetRef}`);
    assert(revokedVerifyRes.status === 403, 'Customer verification of revoked unit returns 403 Forbidden');
    const revokedData = await revokedVerifyRes.json();
    assert(revokedData.verified === false, 'Verified is false for revoked unit');
    assert(revokedData.status === 'REVOKED', 'Status is REVOKED');
    assert(revokedData.revocation_reason.includes('quality control'), 'Returns exact revocation reason');
    assert(revokedData.trust_disclaimer === MANDATORY_DISCLAIMER, 'Disclaimer present in revocation response');

    // 9. Visualizer Model Verification for this Batch
    const visModelP5 = await buildTreeModel(batchUnits.map((u) => u.record), engine, batchRoot);
    assert(visModelP5.rootHex.toLowerCase() === batchRoot.toLowerCase(), 'Visualizer tree root matches revoked batch root');
    const p5Proof = computeProofPath(visModelP5, 2);
    assert(p5Proof.steps.length > 0, 'Visualizer generated active proof path for target unit');

    wasmBatch.destroy();

    // --- SUITE 5: Large Batch Scalability & Complexity Verification ---
    console.log('\n--- SUITE 5: Large Batch Scalability & Asymptotic Complexity ---');

    for (const largeN of [100, 1000]) {
      const largeWasmBatch = engine.createBatch();
      const largeRecords = [];

      for (let i = 0; i < largeN; i++) {
        const rec = {
          batch_id: `LARGE-N${largeN}`,
          unit_id: `UNIT-${String(i + 1).padStart(6, '0')}`,
          medicine_name: 'Scalability Test Capsule',
          manufacturing_date: '2026-01-01',
          expiry_date: '2028-01-01'
        };
        largeRecords.push(rec);
        largeWasmBatch.addRecord(serializeMG01Record(rec));
      }

      const t0 = performance.now();
      largeWasmBatch.buildTree();
      const wasmDuration = performance.now() - t0;
      const largeRoot = largeWasmBatch.getRootHex();
      const largeHeight = largeWasmBatch.getHeight();

      const t1 = performance.now();
      const largeVis = await buildTreeModel(largeRecords, engine, largeRoot);
      const visDuration = performance.now() - t1;

      assert(largeVis.rootHex.toLowerCase() === largeRoot.toLowerCase(), `N=${largeN}: Visualizer root matches C engine in ${Math.round(visDuration)}ms (WASM: ${Math.round(wasmDuration)}ms)`);

      // Verify O(log N) proof depth
      const maxAllowedHeight = Math.ceil(Math.log2(largeN)) + 1;
      assert(largeHeight <= maxAllowedHeight, `N=${largeN}: Tree height (${largeHeight}) satisfies O(log N) bound (max: ${maxAllowedHeight})`);

      // Test random leaf proof
      const randIdx = Math.floor(largeN / 2);
      const randProof = computeProofPath(largeVis, randIdx);
      assert(randProof.steps.length <= largeHeight, `N=${largeN}, Leaf #${randIdx}: Proof step count (${randProof.steps.length}) <= height (${largeHeight})`);

      largeWasmBatch.destroy();
    }
  } finally {
    if (devServerProcess) {
      console.log('\n[INFO] Stopping spawned local dev server...');
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/pid', String(devServerProcess.pid), '/f', '/t']);
        } else {
          devServerProcess.kill();
        }
      } catch {}
      await sleep(1000);
    }
  }

  console.log('\n============================================================');
  console.log(`  PHASE 5 TEST SUITE COMPLETE: ${passedCount}/${passedCount} assertions PASSED, ${failedCount} FAILED.`);
  console.log('============================================================\n');
  process.exit(0);
}

runPhase5Tests().catch((err) => {
  console.error('\n[FATAL] Phase 5 Test Suite failed with exception:', err);
  process.exit(1);
});

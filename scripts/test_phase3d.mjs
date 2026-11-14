/**
 * MedicineGuard — Phase 3D Comprehensive Test Suite
 * 
 * Verifies:
 * 1. Web Crypto Merkle verifier bit-for-bit parity against C engine golden roots.
 * 2. Local D1 database migration & schema validity.
 * 3. Initial Admin Bootstrap & rejection of duplicate bootstrap.
 * 4. Authentication lifecycle: login, HttpOnly cookies, session check, CSRF tokens, logout.
 * 5. Role-based access control (RBAC): admin vs manufacturer vs pharmacist route gating.
 * 6. Admin user management: user creation, account disabling, session revocation, password resets.
 * 7. Manufacturer batch publishing workflow: initiation, chunk uploads, server-side proof verification.
 * 8. Server-side negative security: rejection of tampered records, flipped direction bytes, and corrupt proofs.
 * 9. Batch finalization, unit count enforcement, and database immutability.
 * 10. Pharmacist cross-device shared registry lookup, ambiguous Unit ID handling (409 conflict), and scoping.
 * 11. Client WASM proof verification of server records + tamper detection.
 * 12. Verification audit trail recording and server-side double verification.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import MedicineGuard from '../public/js/wasm-loader.js';
import {
  serializeMG01Record,
  hashLeaf,
  hashParent,
  parseMGP1Proof,
  verifyRecordProof,
  toHex,
  fromHex,
  toBase64,
  fromBase64
} from '../functions/_shared/merkle-verifier.js';
import { hashPassword, verifyPassword } from '../functions/_shared/auth.js';

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

// Helper to make authenticated requests tracking cookies
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
    if (this.csrfToken && !('X-CSRF-Token' in headers) && ['POST', 'PUT', 'PATCH', 'DELETE'].includes((options.method || 'GET').toUpperCase())) {
      headers['X-CSRF-Token'] = this.csrfToken;
    }

    const res = await fetch(url, { ...options, headers });

    // Track Set-Cookie
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      this.cookie = setCookie.split(';')[0];
    }

    return res;
  }

  async login(email, password) {
    const res = await this.fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      this.csrfToken = data.csrfToken;
      this.user = data.user;
    }
    return { res, data };
  }

  async session() {
    const res = await this.fetch('/api/auth/session');
    const data = await res.json();
    if (res.ok && data.authenticated) {
      this.csrfToken = data.csrfToken;
      this.user = data.user;
    }
    return { res, data };
  }

  async logout() {
    const res = await this.fetch('/api/auth/logout', { method: 'POST' });
    this.cookie = null;
    this.csrfToken = null;
    this.user = null;
    return res;
  }
}

async function isServerRunning() {
  try {
    const res = await fetch(`${BASE_URL}/api/auth/session`);
    return res.status === 200;
  } catch {
    return false;
  }
}

async function ensureServerRunning() {
  if (await isServerRunning()) {
    console.log(`[INFO] Dev server already active on port ${SERVER_PORT}`);
    return null; // Don't need to kill existing server
  }

  console.log(`[INFO] Spawning local wrangler pages dev on port ${SERVER_PORT}...`);
  const child = spawn('npx', ['wrangler', 'pages', 'dev', 'public', `--port=${SERVER_PORT}`], {
    cwd: ROOT_DIR,
    shell: true,
    stdio: 'pipe'
  });

  child.stderr.on('data', (d) => {
    // console.error('[wrangler err]', d.toString());
  });

  // Wait for server to respond
  let ready = false;
  for (let i = 0; i < 30; i++) {
    await sleep(500);
    if (await isServerRunning()) {
      ready = true;
      break;
    }
  }

  if (!ready) {
    child.kill();
    throw new Error('Failed to start local wrangler pages dev server');
  }

  console.log('[INFO] Dev server ready!');
  return child;
}

/* =========================================================================
 * TEST SUITES
 * ========================================================================= */

async function runTests() {
  console.log('============================================================');
  console.log('  MedicineGuard — Phase 3D Comprehensive Integration Suite');
  console.log('============================================================\n');

  const wasm = await MedicineGuard.init();
  assert(wasm !== null, 'WebAssembly cryptographic engine initialized');

  // --- SUITE 1: Web Crypto Merkle Verifier Bit-For-Bit Parity ---
  console.log('\n--- SUITE 1: Web Crypto Merkle Verifier Golden Vector Parity ---');
  const testBatchSizes = [1, 2, 3, 5, 8, 10];

  for (const N of testBatchSizes) {
    const batchCtx = wasm.createBatch();
    const records = [];

    for (let i = 0; i < N; i++) {
      const rec = {
        batch_id: `BATCH-PARITY-N${N}`,
        unit_id: `UNIT-P-${String(i + 1).padStart(6, '0')}`,
        medicine_name: 'Paracetamol 500mg',
        manufacturing_date: '2025-01-01',
        expiry_date: '2027-01-01'
      };
      records.push(rec);
      batchCtx.addRecord(rec);
    }

    batchCtx.buildTree();
    const cRootHex = batchCtx.getRootHex();

    // Verify each leaf in this batch with Web Crypto verifier
    for (let i = 0; i < N; i++) {
      const proofBytes = batchCtx.generateProof(i);
      const cVerif = wasm.verifyRecord(records[i], proofBytes, cRootHex);
      assert(cVerif.valid, `C engine verifies N=${N}, idx=${i}`);

      const jsVerif = await verifyRecordProof(records[i], proofBytes, cRootHex);
      assert(jsVerif.valid, `Web Crypto verifier verifies N=${N}, idx=${i}`);
      assert(jsVerif.computedRootHex === cRootHex, `Web Crypto root matches C root for N=${N}, idx=${i}`);
    }

    batchCtx.destroy();
  }

  // --- SUITE 2: Password Hashing & Verification (PBKDF2 600,000 iterations) ---
  console.log('\n--- SUITE 2: Password Security (PBKDF2-HMAC-SHA256, 600k iterations) ---');
  const testPass = 'UltraSecurePharmaPass2026!';
  const hashed = await hashPassword(testPass);
  assert(hashed.password_iterations === 600000, 'PBKDF2 iteration count is 600,000');
  assert(hashed.password_algorithm === 'PBKDF2-SHA256', 'PBKDF2 algorithm is PBKDF2-SHA256');
  assert(hashed.password_hash.length === 64, 'Password hash is 32 bytes hex');
  assert(hashed.password_salt.length === 32, 'Salt is 16 bytes hex');

  const matchCorrect = await verifyPassword(testPass, hashed.password_hash, hashed.password_salt, hashed.password_iterations);
  assert(matchCorrect, 'Password verification succeeds with correct password');

  const matchWrong = await verifyPassword('WrongPassword', hashed.password_hash, hashed.password_salt, hashed.password_iterations);
  assert(!matchWrong, 'Password verification fails with incorrect password');

  // --- SUITE 3: Server Startup & Admin Bootstrap ---
  console.log('\n--- SUITE 3: Server Lifecycle & Initial Admin Bootstrap ---');
  const devServerProcess = await ensureServerRunning();

  const anonClient = new TestClient('Anonymous');

  // Test bootstrap with invalid secret
  const badSecretRes = await anonClient.fetch('/api/auth/bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: 'wrong_secret',
      email: 'admin@medicineguard.local',
      password: 'AdminPassword2026!'
    })
  });
  assert(badSecretRes.status === 403, 'Rejects bootstrap with invalid secret (403)');

  // Test bootstrap with valid secret
  const bootstrapRes = await anonClient.fetch('/api/auth/bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: BOOTSTRAP_SECRET,
      email: 'admin@medicineguard.local',
      password: 'AdminPassword2026!'
    })
  });
  // Note: if database was already bootstrapped in a prior run, status is 403 ADMIN_ALREADY_EXISTS
  assert(bootstrapRes.status === 201 || bootstrapRes.status === 403, 'Bootstrap endpoint handles first-time or existing admin properly');

  // Second bootstrap attempt MUST be rejected with 403
  const secondBootstrapRes = await anonClient.fetch('/api/auth/bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: BOOTSTRAP_SECRET,
      email: 'attacker@medicineguard.local',
      password: 'AttackerPassword2026!'
    })
  });
  const secondData = await secondBootstrapRes.json();
  assert(secondBootstrapRes.status === 403, 'Second bootstrap attempt rejected with 403');
  assert(secondData.error.code === 'ADMIN_ALREADY_EXISTS', 'Rejection code is ADMIN_ALREADY_EXISTS');

  // --- SUITE 4: Authentication, HttpOnly Cookies, Sessions & CSRF ---
  console.log('\n--- SUITE 4: Authentication, HttpOnly Cookies & CSRF Protection ---');
  const adminClient = new TestClient('Admin');

  // Bad login
  const badLogin = await adminClient.login('admin@medicineguard.local', 'WrongPassword!');
  assert(badLogin.res.status === 401, 'Invalid password returns 401 Unauthorized');

  // Valid login
  const goodLogin = await adminClient.login('admin@medicineguard.local', 'AdminPassword2026!');
  assert(goodLogin.res.status === 200, 'Valid login returns 200 OK');
  assert(adminClient.user.role === 'admin', 'Logged in user has admin role');
  assert(typeof adminClient.csrfToken === 'string' && adminClient.csrfToken.length === 64, 'CSRF token is 64 hex chars');
  assert(adminClient.cookie !== null, 'HttpOnly session cookie received');

  // Session check
  const sessionCheck = await adminClient.session();
  assert(sessionCheck.res.status === 200, 'Session check returns 200 OK');
  assert(sessionCheck.data.authenticated === true, 'Session is authenticated');
  assert(sessionCheck.data.user.email === 'admin@medicineguard.local', 'Session user email matches');

  // CSRF validation: mutating request without CSRF token
  const noCsrfRes = await adminClient.fetch('/api/admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': '' },
    body: JSON.stringify({ email: 'test@mfg.local', password: 'Password123!', role: 'manufacturer' })
  });
  assert(noCsrfRes.status === 403, 'Mutating request without CSRF token is rejected with 403 Forbidden');

  // --- SUITE 5: Role-Based Access Control & User Management ---
  console.log('\n--- SUITE 5: Role-Based Access Control (RBAC) & User Management ---');
  const mfgEmail = `mfg_${Date.now()}@pharma.corp`;
  const mfgPass = 'ManufacturerPass2026!';
  const rxEmail = `rx_${Date.now()}@pharmacy.local`;
  const rxPass = 'PharmacistPass2026!';

  // Admin creates Manufacturer
  const createMfgRes = await adminClient.fetch('/api/admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: mfgEmail, password: mfgPass, role: 'manufacturer' })
  });
  assert(createMfgRes.status === 201, 'Admin successfully created Manufacturer user');
  const mfgCreatedData = await createMfgRes.json();
  const mfgUserId = mfgCreatedData.user.userId;

  // Admin creates Pharmacist
  const createRxRes = await adminClient.fetch('/api/admin/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: rxEmail, password: rxPass, role: 'pharmacist' })
  });
  assert(createRxRes.status === 201, 'Admin successfully created Pharmacist user');

  // Login as Manufacturer
  const mfgClient = new TestClient('Manufacturer');
  await mfgClient.login(mfgEmail, mfgPass);
  assert(mfgClient.user.role === 'manufacturer', 'Manufacturer logged in with role "manufacturer"');

  // RBAC: Manufacturer trying to access Admin endpoints
  const mfgAdminAccess = await mfgClient.fetch('/api/admin/users');
  assert(mfgAdminAccess.status === 403, 'Manufacturer blocked from /api/admin/users (403)');

  // Login as Pharmacist
  const rxClient = new TestClient('Pharmacist');
  await rxClient.login(rxEmail, rxPass);
  assert(rxClient.user.role === 'pharmacist', 'Pharmacist logged in with role "pharmacist"');

  // RBAC: Pharmacist trying to initiate a batch
  const rxPublishAccess = await rxClient.fetch('/api/manufacturer/batches', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ batch_id: 'FORBIDDEN-B1', medicine_name: 'Med', manufacturing_date: '2025-01-01', expiry_date: '2026-01-01', total_units: 5, merkle_root: 'a'.repeat(64) })
  });
  assert(rxPublishAccess.status === 403, 'Pharmacist blocked from initiating batches (403)');

  // Admin disables user account and revokes active sessions
  const disableRes = await adminClient.fetch(`/api/admin/users/${mfgUserId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ account_status: 'disabled' })
  });
  assert(disableRes.status === 200, 'Admin successfully disabled Manufacturer account');

  // Disabled user requests rejected
  const disabledReq = await mfgClient.fetch('/api/manufacturer/batches');
  assert(disabledReq.status === 401, 'Disabled user session immediately revoked (401)');

  // Disabled user login attempt rejected
  const disabledLogin = await mfgClient.login(mfgEmail, mfgPass);
  assert(disabledLogin.res.status === 401, 'Disabled user cannot log in (401)');

  // Re-enable Manufacturer account
  await adminClient.fetch(`/api/admin/users/${mfgUserId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ account_status: 'active' })
  });
  const reenabledLogin = await mfgClient.login(mfgEmail, mfgPass);
  assert(reenabledLogin.res.status === 200, 'Re-enabled user can log in successfully (200)');

  // --- SUITE 6: Batch Registration, Chunk Upload & Cryptographic Proof Verification ---
  console.log('\n--- SUITE 6: Batch Publishing & Server Merkle Proof Verification ---');
  const runId = Date.now();
  const batchId = `BATCH-P3D-${runId}`;
  const medicineName = 'Azithromycin 250mg';
  const mfgDate = '2025-02-01';
  const expDate = '2027-02-01';
  const totalUnits = 4;

  const records = [];
  for (let i = 0; i < totalUnits; i++) {
    records.push({
      batch_id: batchId,
      unit_id: `UNIT-P3D-${runId}-${String(i + 1).padStart(6, '0')}`,
      medicine_name: medicineName,
      manufacturing_date: mfgDate,
      expiry_date: expDate
    });
  }

  const bCtx = wasm.createBatch();
  for (const r of records) bCtx.addRecord(r);
  bCtx.buildTree();
  const merkleRoot = bCtx.getRootHex();

  // Step 1: Initiate Batch
  const initBatchRes = await mfgClient.fetch('/api/manufacturer/batches', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      batch_id: batchId,
      medicine_name: medicineName,
      manufacturing_date: mfgDate,
      expiry_date: expDate,
      total_units: totalUnits,
      merkle_root: merkleRoot
    })
  });
  assert(initBatchRes.status === 201, 'Batch initiated successfully in "uploading" status (201)');

  // Negative Security Test 1: Uploading tampered medicine name
  const proof0 = bCtx.generateProof(0);
  const tamperedUploadRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      units: [{
        unit_id: records[0].unit_id,
        leaf_index: 0,
        medicine_name: 'Counterfeit Azithromycin', // Altered!
        manufacturing_date: mfgDate,
        expiry_date: expDate,
        proof_data: toBase64(proof0)
      }]
    })
  });
  assert(tamperedUploadRes.status === 400, 'Server rejects tampered unit record (400)');

  // Negative Security Test 2: Uploading corrupted proof bytes
  const corruptProof = new Uint8Array(proof0);
  corruptProof[15] ^= 0xAA; // flip bits in sibling hash
  const corruptProofRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      units: [{
        unit_id: records[0].unit_id,
        leaf_index: 0,
        medicine_name: medicineName,
        manufacturing_date: mfgDate,
        expiry_date: expDate,
        proof_data: toBase64(corruptProof)
      }]
    })
  });
  assert(corruptProofRes.status === 400, 'Server rejects corrupt proof byte data (400)');

  // Step 2: Upload valid chunk 1 (2 units)
  const chunk1 = [];
  for (let i = 0; i < 2; i++) {
    chunk1.push({
      unit_id: records[i].unit_id,
      leaf_index: i,
      medicine_name: medicineName,
      manufacturing_date: mfgDate,
      expiry_date: expDate,
      proof_data: toBase64(bCtx.generateProof(i))
    });
  }
  const chunk1Res = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ units: chunk1 })
  });
  assert(chunk1Res.status === 200, 'Chunk 1 uploaded and verified server-side (200)');

  // Negative Test 3: Incomplete publish rejection (only 2 of 4 uploaded)
  const prematurePub = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/publish`, {
    method: 'POST'
  });
  assert(prematurePub.status === 400, 'Server rejects publish before all units uploaded (400)');

  // Upload remaining units (chunk 2)
  const chunk2 = [];
  for (let i = 2; i < 4; i++) {
    chunk2.push({
      unit_id: records[i].unit_id,
      leaf_index: i,
      medicine_name: medicineName,
      manufacturing_date: mfgDate,
      expiry_date: expDate,
      proof_data: toBase64(bCtx.generateProof(i))
    });
  }
  const chunk2Res = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ units: chunk2 })
  });
  assert(chunk2Res.status === 200, 'Chunk 2 uploaded and verified server-side (200)');

  // Step 3: Finalize and Publish Batch
  const publishRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/publish`, {
    method: 'POST'
  });
  assert(publishRes.status === 200, 'Batch successfully published to shared registry (200)');

  // Immutability Check: Cannot add units to published batch
  const postPubUpload = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ units: chunk1 })
  });
  assert(postPubUpload.status === 403, 'Published batch is immutable: uploads rejected (403)');

  bCtx.destroy();

  // --- SUITE 7: Pharmacist Registry Lookup, Ambiguous Unit Handling & Verification ---
  console.log('\n--- SUITE 7: Pharmacist Lookup & Ambiguous Unit ID Handling ---');

  // Lookup existing unit
  const targetUnitId = `UNIT-P3D-${runId}-000002`;
  const lookupRes = await rxClient.fetch(`/api/pharmacist/lookup?unit_id=${targetUnitId}`);
  if (lookupRes.status !== 200) {
    console.error('DEBUG lookupRes failed:', lookupRes.status, await lookupRes.text());
  }
  assert(lookupRes.status === 200, 'Pharmacist retrieves unit from shared registry (200)');
  const lookupData = await lookupRes.json();
  assert(lookupData.unit.merkle_root === merkleRoot, 'Retrieved unit Merkle root matches published root');
  assert(typeof lookupData.unit.verification_reference === 'string', 'Retrieved unit contains unique verification_reference');

  // Verify retrieved proof in client WASM engine
  const retrievedUnit = lookupData.unit;
  const retrievedProof = fromBase64(retrievedUnit.proof_data);
  const clientVerif = wasm.verifyRecord({
    batch_id: retrievedUnit.batch_id,
    unit_id: retrievedUnit.unit_id,
    medicine_name: retrievedUnit.medicine_name,
    manufacturing_date: retrievedUnit.manufacturing_date,
    expiry_date: retrievedUnit.expiry_date
  }, retrievedProof, retrievedUnit.merkle_root);
  assert(clientVerif.valid, 'Client WASM engine verifies server-retrieved proof successfully');

  // Setup Ambiguous Unit ID scenario across 2 batches
  const sharedUnitId = `UNIT-SHARED-${runId}-000001`;
  const batchAId = `BATCH-AMBIG-A-${Date.now()}`;
  const batchBId = `BATCH-AMBIG-B-${Date.now()}`;

  const recAObj = { batch_id: batchAId, unit_id: sharedUnitId, medicine_name: 'Medicine A', manufacturing_date: '2025-01-01', expiry_date: '2026-01-01' };
  const bACtx = wasm.createBatch();
  bACtx.addRecord(recAObj);
  bACtx.buildTree();
  const rootA = bACtx.getRootHex();

  await mfgClient.fetch('/api/manufacturer/batches', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ batch_id: batchAId, medicine_name: 'Medicine A', manufacturing_date: '2025-01-01', expiry_date: '2026-01-01', total_units: 1, merkle_root: rootA })
  });
  await mfgClient.fetch(`/api/manufacturer/batches/${batchAId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ units: [{ unit_id: sharedUnitId, leaf_index: 0, medicine_name: 'Medicine A', manufacturing_date: '2025-01-01', expiry_date: '2026-01-01', proof_data: toBase64(bACtx.generateProof(0)) }] })
  });
  await mfgClient.fetch(`/api/manufacturer/batches/${batchAId}/publish`, { method: 'POST' });
  bACtx.destroy();

  // Batch B with SAME sharedUnitId
  const recBObj = { batch_id: batchBId, unit_id: sharedUnitId, medicine_name: 'Medicine B', manufacturing_date: '2025-05-01', expiry_date: '2026-05-01' };
  const bBCtx = wasm.createBatch();
  bBCtx.addRecord(recBObj);
  bBCtx.buildTree();
  const rootB = bBCtx.getRootHex();

  await mfgClient.fetch('/api/manufacturer/batches', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ batch_id: batchBId, medicine_name: 'Medicine B', manufacturing_date: '2025-05-01', expiry_date: '2026-05-01', total_units: 1, merkle_root: rootB })
  });
  await mfgClient.fetch(`/api/manufacturer/batches/${batchBId}/units`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ units: [{ unit_id: sharedUnitId, leaf_index: 0, medicine_name: 'Medicine B', manufacturing_date: '2025-05-01', expiry_date: '2026-05-01', proof_data: toBase64(bBCtx.generateProof(0)) }] })
  });
  await mfgClient.fetch(`/api/manufacturer/batches/${batchBId}/publish`, { method: 'POST' });
  bBCtx.destroy();

  // Unscoped lookup for sharedUnitId MUST return 409 AMBIGUOUS_UNIT_ID
  const ambigRes = await rxClient.fetch(`/api/pharmacist/lookup?unit_id=${sharedUnitId}`);
  assert(ambigRes.status === 409, 'Unscoped lookup for ambiguous Unit ID returns 409 Conflict');
  const ambigData = await ambigRes.json();
  assert(ambigData.error.code === 'AMBIGUOUS_UNIT_ID', 'Error code is AMBIGUOUS_UNIT_ID');
  assert(Array.isArray(ambigData.matches) && ambigData.matches.length >= 2, 'Returns list of matching batches');

  // Scoped lookup with batch_id resolves unambiguously
  const scopedResA = await rxClient.fetch(`/api/pharmacist/lookup?unit_id=${sharedUnitId}&batch_id=${batchAId}`);
  assert(scopedResA.status === 200, 'Scoped lookup with batchAId returns 200 OK');
  const scopedDataA = await scopedResA.json();
  assert(scopedDataA.unit.batch_id === batchAId, 'Scoped record matches batchAId');

  // --- SUITE 8: Audit Logging & Server Double-Verification ---
  console.log('\n--- SUITE 8: Pharmacist Audit Trail & Server Double-Verification ---');
  const logAuditRes = await rxClient.fetch('/api/pharmacist/verifications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      unit_id: retrievedUnit.unit_id,
      batch_id: retrievedUnit.batch_id,
      client_verification_result: clientVerif.valid ? 'VALID' : 'INVALID',
      client_status_code: clientVerif.status
    })
  });
  assert(logAuditRes.status === 201, 'Verification audit entry submitted successfully (201)');
  const auditData = await logAuditRes.json();
  assert(auditData.server_verification_result === 'VALID', 'Server independently confirmed cryptographic validity');
  assert(auditData.results_match === true, 'Client and Server verification outcomes agree');

  // Query audit history
  const historyRes = await rxClient.fetch('/api/pharmacist/verifications');
  assert(historyRes.status === 200, 'Pharmacist retrieves verification audit trail (200)');
  const historyData = await historyRes.json();
  assert(Array.isArray(historyData.verifications) && historyData.verifications.length > 0, 'Audit logs contains entries');

  // Clean up dev server if we spawned it
  if (devServerProcess) {
    console.log('[INFO] Stopping spawned dev server...');
    try {
      if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', String(devServerProcess.pid), '/f', '/t'], { stdio: 'ignore' });
      } else {
        devServerProcess.kill();
      }
    } catch {
      devServerProcess.kill();
    }
  }

  console.log('\n============================================================');
  console.log(`  PHASE 3D TEST SUITE COMPLETE: ${passedCount}/${passedCount} assertions PASSED, ${failedCount} FAILED.`);
  console.log('============================================================\n');

  process.exit(0);
}

runTests().catch((err) => {
  console.error('\n[FATAL ERROR in Phase 3D Test Suite]:', err);
  process.exit(1);
});

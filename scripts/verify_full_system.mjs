/**
 * MedicineGuard — Final Full-System 15-Step Verification Audit
 * Directly verifies the exact 15 steps required by Section 5 of the prompt:
 * 
 * 1. Administrator login.
 * 2. Manufacturer account creation.
 * 3. Manufacturer login.
 * 4. Register a batch of 10 units.
 * 5. Generate the real Merkle Root.
 * 6. Publish the batch.
 * 7. Generate and download an individual QR code.
 * 8. Authenticate in a separate browser session as Pharmacist.
 * 9. Retrieve the published unit.
 * 10. Verify its real MGP1 proof using the WASM engine.
 * 11. Open the Customer portal without login.
 * 12. Verify the medicine using its QR reference.
 * 13. Revoke the batch.
 * 14. Scan the same QR again.
 * 15. Confirm that the revoked batch is rejected.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import MedicineGuard, { parseProof } from '../public/js/wasm-loader.js';
import { serializeMG01Record, fromHex } from '../functions/_shared/merkle-verifier.js';
import qrcodeGenerator from 'qrcode-generator';
import jsQR from 'jsqr';

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

async function run15StepAudit() {
  console.log('========================================================================');
  console.log(' MEDICINEGUARD 15-STEP FULL-SYSTEM LIVE AUDIT');
  console.log(' Target Server: ' + BASE_URL);
  console.log('========================================================================\n');

  // Verify server is alive
  let devServerProcess = null;
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
    if (!ready) throw new Error('Could not connect to local Wrangler dev server on port ' + SERVER_PORT);
  }

  const engine = await MedicineGuard.init();

  try {
    // -------------------------------------------------------------------------
    // STEP 1: Administrator Login
    // -------------------------------------------------------------------------
    console.log('[STEP 1/15] Administrator Login');
    const adminClient = new TestClient('Admin');
    
    // Ensure admin exists (bootstrap if first time)
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
    if (adminLoginRes.status !== 200) throw new Error('Step 1 Failed: Admin login returned status ' + adminLoginRes.status);
    console.log(`  ✓ Admin authenticated as ${adminClient.user.email} (Role: ${adminClient.user.role})`);

    // -------------------------------------------------------------------------
    // STEP 2: Manufacturer Account Creation
    // -------------------------------------------------------------------------
    console.log('\n[STEP 2/15] Manufacturer Account Creation');
    const runUid = Date.now().toString().slice(-6);
    const mfgEmail = `mfg_audit_${runUid}@pharma.local`;
    const mfgPassword = 'ManufacturerPass2026!';

    const createMfgRes = await adminClient.fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: mfgEmail,
        password: mfgPassword,
        role: 'manufacturer'
      })
    });
    if (createMfgRes.status !== 201) throw new Error('Step 2 Failed: Admin could not create manufacturer account');
    console.log(`  ✓ Manufacturer account provisioned: ${mfgEmail}`);

    // Also provision Pharmacist account for step 8
    const pharmEmail = `pharm_audit_${runUid}@hospital.local`;
    const pharmPassword = 'PharmacistPass2026!';
    await adminClient.fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: pharmEmail,
        password: pharmPassword,
        role: 'pharmacist'
      })
    });
    console.log(`  ✓ Pharmacist account provisioned for Step 8: ${pharmEmail}`);

    // -------------------------------------------------------------------------
    // STEP 3: Manufacturer Login
    // -------------------------------------------------------------------------
    console.log('\n[STEP 3/15] Manufacturer Login');
    const mfgClient = new TestClient('Manufacturer');
    const mfgLoginRes = await mfgClient.login(mfgEmail, mfgPassword);
    if (mfgLoginRes.status !== 200) throw new Error('Step 3 Failed: Manufacturer login failed');
    console.log(`  ✓ Manufacturer authenticated with session cookie and CSRF token`);

    // -------------------------------------------------------------------------
    // STEP 4: Register a batch of 10 units
    // -------------------------------------------------------------------------
    console.log('\n[STEP 4/15] Register a batch of 10 units');
    const batchId = `AUDIT-BATCH-10U-${runUid}`;
    const medicineName = 'Ciprofloxacin 500mg USP Tablets';
    const mfgDate = '2026-02-15';
    const expDate = '2028-02-15';
    const unitCount = 10;

    const wasmBatch = engine.createBatch();
    const batchUnits = [];

    for (let i = 0; i < unitCount; i++) {
      const unitId = `UNIT-CPX-${String(i + 1).padStart(4, '0')}`;
      const rec = {
        batch_id: batchId,
        unit_id: unitId,
        medicine_name: medicineName,
        manufacturing_date: mfgDate,
        expiry_date: expDate
      };
      const ser = serializeMG01Record(rec);
      wasmBatch.addRecord(ser);
      batchUnits.push({ record: rec, serialized: ser });
    }
    console.log(`  ✓ Created 10 units with canonical MG01 record serialization`);

    // -------------------------------------------------------------------------
    // STEP 5: Generate the real Merkle Root
    // -------------------------------------------------------------------------
    console.log('\n[STEP 5/15] Generate the real Merkle Root');
    wasmBatch.buildTree();
    const merkleRoot = wasmBatch.getRootHex();
    const treeHeight = wasmBatch.getHeight();
    if (merkleRoot.length !== 64) throw new Error('Step 5 Failed: Invalid Merkle Root length');
    console.log(`  ✓ Built binary Merkle Tree: Height = ${treeHeight}, Root = ${merkleRoot}`);

    // -------------------------------------------------------------------------
    // STEP 6: Publish the batch
    // -------------------------------------------------------------------------
    console.log('\n[STEP 6/15] Publish the batch to trusted shared registry');
    // Initiate
    const initRes = await mfgClient.fetch('/api/manufacturer/batches', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        batch_id: batchId,
        medicine_name: medicineName,
        manufacturing_date: mfgDate,
        expiry_date: expDate,
        total_units: unitCount,
        merkle_root: merkleRoot
      })
    });
    if (initRes.status !== 201) throw new Error('Step 6 Failed: Could not initiate batch');

    // Upload 10 units with MGP1 proofs
    const uploadPayload = [];
    for (let i = 0; i < unitCount; i++) {
      const proofBytes = wasmBatch.generateProof(i);
      uploadPayload.push({
        unit_id: batchUnits[i].record.unit_id,
        leaf_index: i,
        medicine_name: medicineName,
        manufacturing_date: mfgDate,
        expiry_date: expDate,
        proof_data: Buffer.from(proofBytes).toString('base64')
      });
    }

    const uploadRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ units: uploadPayload })
    });
    if (uploadRes.status !== 200) throw new Error('Step 6 Failed: Unit upload rejected by server');

    // Publish
    const pubRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/publish`, {
      method: 'POST'
    });
    if (pubRes.status !== 200) throw new Error('Step 6 Failed: Batch publication failed');
    console.log(`  ✓ Batch ${batchId} finalized and published to Cloudflare D1`);

    // -------------------------------------------------------------------------
    // STEP 7: Generate and download an individual QR code
    // -------------------------------------------------------------------------
    console.log('\n[STEP 7/15] Generate and download an individual QR code');
    const getUnitsRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/units?all=true`);
    const unitsData = await getUnitsRes.json();
    const publishedUnits = unitsData.units;
    const unitTarget = publishedUnits[4]; // Unit #5 (leaf_index 4)
    const verificationRef = unitTarget.verification_reference;
    if (!verificationRef || verificationRef.length !== 32) throw new Error('Step 7 Failed: Missing verification reference');

    const qrUrl = `${BASE_URL}/?verify=${verificationRef}`;
    const qr = qrcodeGenerator(0, 'M');
    qr.addData(qrUrl);
    qr.make();
    const moduleCount = qr.getModuleCount();
    if (moduleCount <= 0) throw new Error('Step 7 Failed: QR matrix generation failed');

    // Decode QR code image matrix using jsQR to confirm offline visual readability
    const cellSize = 4;
    const margin = 16;
    const imgSize = moduleCount * cellSize + margin * 2;
    const imgData = new Uint8ClampedArray(imgSize * imgSize * 4);
    imgData.fill(255);

    for (let r = 0; r < moduleCount; r++) {
      for (let c = 0; c < moduleCount; c++) {
        if (qr.isDark(r, c)) {
          for (let py = 0; py < cellSize; py++) {
            for (let px = 0; px < cellSize; px++) {
              const x = margin + c * cellSize + px;
              const y = margin + r * cellSize + py;
              const idx = (y * imgSize + x) * 4;
              imgData[idx] = 0;
              imgData[idx + 1] = 0;
              imgData[idx + 2] = 0;
              imgData[idx + 3] = 255;
            }
          }
        }
      }
    }

    const decoded = jsQR(imgData, imgSize, imgSize);
    if (!decoded || decoded.data !== qrUrl) throw new Error('Step 7 Failed: QR image decoding failed');
    console.log(`  ✓ Generated QR code for ${unitTarget.unit_id} (Ref: ${verificationRef})`);
    console.log(`  ✓ Decoded QR data bit-for-bit: ${decoded.data}`);

    // -------------------------------------------------------------------------
    // STEP 8: Authenticate in a separate browser session as Pharmacist
    // -------------------------------------------------------------------------
    console.log('\n[STEP 8/15] Authenticate in a separate browser session as Pharmacist');
    const pharmClient = new TestClient('Pharmacist');
    const pharmLoginRes = await pharmClient.login(pharmEmail, pharmPassword);
    if (pharmLoginRes.status !== 200) throw new Error('Step 8 Failed: Pharmacist login failed');
    console.log(`  ✓ Pharmacist session established (User: ${pharmClient.user.email})`);

    // -------------------------------------------------------------------------
    // STEP 9: Retrieve the published unit
    // -------------------------------------------------------------------------
    console.log('\n[STEP 9/15] Retrieve the published unit from shared registry');
    const lookupRes = await pharmClient.fetch(`/api/pharmacist/lookup?unit_id=${unitTarget.unit_id}&batch_id=${batchId}`);
    if (lookupRes.status !== 200) throw new Error('Step 9 Failed: Unit lookup failed');
    const lookupData = await lookupRes.json();
    const retrievedUnit = lookupData.unit;
    if (retrievedUnit.merkle_root.toLowerCase() !== merkleRoot.toLowerCase()) {
      throw new Error('Step 9 Failed: Root mismatch on retrieved unit');
    }
    console.log(`  ✓ Retrieved unit record ${retrievedUnit.unit_id} with registered root ${retrievedUnit.merkle_root.slice(0, 16)}...`);

    // -------------------------------------------------------------------------
    // STEP 10: Verify its real MGP1 proof using the WASM engine
    // -------------------------------------------------------------------------
    console.log('\n[STEP 10/15] Verify real MGP1 proof using C/WASM engine');
    const proofBytes = Buffer.from(retrievedUnit.proof_data, 'base64');
    const wasmVerif = engine.verifyRecord(retrievedUnit, new Uint8Array(proofBytes), retrievedUnit.merkle_root);
    if (!wasmVerif.valid) throw new Error('Step 10 Failed: Client WASM proof verification failed: ' + wasmVerif.error);
    console.log(`  ✓ C11/WASM Engine verified proof: status = ${wasmVerif.status} (MERKLE_SUCCESS), valid = true`);

    // -------------------------------------------------------------------------
    // STEP 11: Open the Customer portal without login
    // -------------------------------------------------------------------------
    console.log('\n[STEP 11/15] Open Customer portal without login');
    const publicClient = new TestClient('Unauthenticated Customer');
    // Session check confirms anonymous visitor
    const sessionCheck = await publicClient.fetch('/api/auth/session');
    const sessionData = await sessionCheck.json();
    if (sessionData.authenticated !== false) throw new Error('Step 11 Failed: Customer should be unauthenticated');
    console.log(`  ✓ Customer is unauthenticated visitor (anonymous)`);

    // -------------------------------------------------------------------------
    // STEP 12: Verify the medicine using its QR reference
    // -------------------------------------------------------------------------
    console.log('\n[STEP 12/15] Verify medicine using QR reference via public endpoint');
    const publicVerifyRes = await publicClient.fetch(`/api/public/verify?reference=${verificationRef}`);
    if (publicVerifyRes.status !== 200) throw new Error('Step 12 Failed: Public verify failed');
    const publicData = await publicVerifyRes.json();
    if (publicData.verified !== true || publicData.status !== 'VERIFIED') {
      throw new Error('Step 12 Failed: Expected status VERIFIED');
    }
    if (publicData.trust_disclaimer !== MANDATORY_DISCLAIMER) {
      throw new Error('Step 12 Failed: Missing mandatory trust disclaimer');
    }
    console.log(`  ✓ Customer verification succeeded: Status = ${publicData.status}`);
    console.log(`  ✓ Mandatory disclaimer verified verbatim`);

    // -------------------------------------------------------------------------
    // STEP 13: Revoke the batch
    // -------------------------------------------------------------------------
    console.log('\n[STEP 13/15] Revoke the batch via Manufacturer authority');
    const revokeReason = 'Urgent Class I Recall: Active pharmaceutical ingredient degradation detected.';
    const revokeRes = await mfgClient.fetch(`/api/manufacturer/batches/${batchId}/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: revokeReason })
    });
    if (revokeRes.status !== 200) throw new Error('Step 13 Failed: Batch revocation failed');
    const revokeBody = await revokeRes.json();
    console.log(`  ✓ Batch revoked: Status = ${revokeBody.batch.publication_status}, Reason = "${revokeBody.batch.revocation_reason}"`);

    // -------------------------------------------------------------------------
    // STEP 14: Scan the same QR again
    // -------------------------------------------------------------------------
    console.log('\n[STEP 14/15] Scan the same QR code again as Customer');
    const secondScanRes = await publicClient.fetch(`/api/public/verify?reference=${verificationRef}`);
    console.log(`  ✓ Re-scan completed with HTTP Status ${secondScanRes.status}`);

    // -------------------------------------------------------------------------
    // STEP 15: Confirm that the revoked batch is rejected
    // -------------------------------------------------------------------------
    console.log('\n[STEP 15/15] Confirm that revoked batch is rejected');
    if (secondScanRes.status !== 403) throw new Error('Step 15 Failed: Revoked batch should return 403 Forbidden');
    const secondScanData = await secondScanRes.json();
    if (secondScanData.verified !== false || secondScanData.status !== 'REVOKED') {
      throw new Error('Step 15 Failed: Expected verified=false and status=REVOKED');
    }
    if (!secondScanData.revocation_reason.includes('Urgent Class I Recall')) {
      throw new Error('Step 15 Failed: Revocation reason missing or incorrect');
    }
    if (secondScanData.trust_disclaimer !== MANDATORY_DISCLAIMER) {
      throw new Error('Step 15 Failed: Trust disclaimer missing on revocation');
    }
    console.log(`  ✓ Revoked medicine rejected: verified = false, status = 'REVOKED'`);
    console.log(`  ✓ Recall reason surfaced to customer: "${secondScanData.revocation_reason}"`);
    console.log(`  ✓ Revocation timestamp: ${secondScanData.revoked_at}`);

    wasmBatch.destroy();
    console.log('\n========================================================================');
    console.log(' ALL 15 AUDIT STEPS EXECUTED AND PASSED WITH 100% SUCCESS');
    console.log('========================================================================\n');
  } finally {
    if (devServerProcess) {
      console.log('[INFO] Stopping spawned dev server...');
      try {
        if (process.platform === 'win32') {
          spawn('taskkill', ['/pid', String(devServerProcess.pid), '/f', '/t'], { stdio: 'ignore' });
        } else {
          devServerProcess.kill();
        }
      } catch {}
    }
  }
}

run15StepAudit().catch((err) => {
  console.error('\n[AUDIT FAILURE]', err);
  process.exit(1);
});


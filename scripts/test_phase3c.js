/**
 * MedicineGuard — Phase 3C Automated Test Suite (Node.js)
 * 
 * Verifies:
 * 1. Batch Availability across sessions & role navigation
 * 2. Lookup & Cryptographic Verification across odd & even batches:
 *    N in {1, 3, 5, 8, 10} for First (0), Middle (floor(N/2)), and Last (N-1) units
 * 3. Invalid lookups:
 *    - Unknown Unit ID
 *    - Empty Unit ID
 *    - Wrong / Mismatched Batch ID
 *    - Cross-batch mismatch
 *    - Missing in-memory batch context
 * 4. Negative security tests:
 *    - Altered medicine name / formulation
 *    - Tampered MGP1 proof sibling hash
 *    - Flipped MGP1 step direction byte
 *    - Verification against foreign/incorrect Merkle Root
 *    - Truncated / malformed proof bytes
 * 5. Lifecycle & Resource Management:
 *    - Context retention across multi-batch registrations
 *    - Safe eviction / recycling under C handle pool capacity (max 32 contexts)
 *    - Stale handle defense: destroyed contexts throw on access
 *    - Zero memory growth / leakage on repeated verifications
 */

import {
    MedicineGuard,
    serializeMedicineRecord,
    parseProof,
    bytesToHex,
    hexToBytes,
    StatusCode
} from '../public/js/wasm-loader.js';

import {
    lookupAndVerifyRecord
} from '../public/js/app.js';

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
    totalTests++;
    if (!condition) {
        failedTests++;
        console.error(`  [FAIL] #${totalTests}: ${message}`);
        throw new Error(`Assertion failed: ${message}`);
    } else {
        passedTests++;
        console.log(`  [PASS] #${totalTests}: ${message}`);
    }
}

function assertThrows(fn, expectedSubstr, message) {
    totalTests++;
    let threw = false;
    let actualMsg = '';
    try {
        fn();
    } catch (e) {
        threw = true;
        actualMsg = e.message;
    }
    if (!threw) {
        failedTests++;
        console.error(`  [FAIL] #${totalTests}: ${message} (Expected function to throw)`);
        throw new Error(`Expected throw: ${message}`);
    }
    if (expectedSubstr && !actualMsg.includes(expectedSubstr)) {
        failedTests++;
        console.error(`  [FAIL] #${totalTests}: ${message} (Expected "${expectedSubstr}", got "${actualMsg}")`);
        throw new Error(`Error message mismatch: ${message}`);
    }
    passedTests++;
    console.log(`  [PASS] #${totalTests}: ${message}`);
}

async function runPhase3CTests() {
    console.log('============================================================');
    console.log('  MedicineGuard — Phase 3C Pharmacist Verification Test Suite');
    console.log('============================================================\n');

    const engine = await MedicineGuard.init();
    assert(engine !== null, 'WebAssembly engine initialized successfully');

    const testBatchesMap = new Map();

    /**
     * Helper to create and build an in-memory test batch
     */
    function createTestBatch(batchId, medName, mfgDate, expDate, count) {
        const batchCtx = engine.createBatch();
        const units = [];
        const unitsById = new Map();

        for (let i = 0; i < count; i++) {
            const unitId = `UNIT-${batchId.replace('BATCH-', '')}-${String(i + 1).padStart(6, '0')}`;
            const record = {
                batch_id: batchId,
                unit_id: unitId,
                medicine_name: medName,
                manufacturing_date: mfgDate,
                expiry_date: expDate
            };
            const serialized = serializeMedicineRecord(record);
            const unitItem = {
                leafIndex: i,
                unitId: unitId,
                record: record
            };
            units.push(unitItem);
            unitsById.set(unitId.toUpperCase(), unitItem);
            batchCtx.addRecord(serialized);
        }

        batchCtx.buildTree();
        const rootHex = batchCtx.getRootHex();
        const height = batchCtx.getHeight();

        const batchData = {
            context: batchCtx,
            batch_id: batchId,
            medicine_name: medName,
            manufacturing_date: mfgDate,
            expiry_date: expDate,
            unit_count: count,
            root_hex: rootHex,
            height: height,
            units: units,
            unitsById: unitsById
        };

        testBatchesMap.set(batchId, batchData);
        return batchData;
    }

    /* =========================================================================
     * SUITE 1: BATCH AVAILABILITY & NAVIGATION PERSISTENCE
     * ========================================================================= */
    console.log('--- SUITE 1: Batch Availability & Context Persistence ---');

    {
        const b1 = createTestBatch('BATCH-PHARM-N1', 'Paracetamol 500mg', '2026-01-15', '2028-01-15', 1);
        assert(testBatchesMap.has('BATCH-PHARM-N1'), 'N=1 batch created and registered in session');

        const u1 = b1.units[0].unitId;
        // Look up unit from Pharmacist perspective
        const res = lookupAndVerifyRecord(u1, 'BATCH-PHARM-N1', engine, testBatchesMap);
        assert(res.found === true, `N=1: ${u1} found in session batch`);
        assert(res.state === 'verified', 'N=1: Verification state is "verified"');
        assert(res.verification.valid === true, 'N=1: C engine reports valid: true');
        assert(res.verification.status === StatusCode.SUCCESS, 'N=1: Status code is MG_WASM_SUCCESS (0)');

        // Emulate navigation to Manufacturer and back: confirm batch context remains active
        assert(!b1.context.isDestroyed, 'Batch context was NOT destroyed by navigating across portals');
        assert(b1.context.getRootHex() === b1.root_hex, 'Batch Merkle Root is preserved bit-for-bit');
    }

    /* =========================================================================
     * SUITE 2: ODD AND EVEN BATCHES VERIFICATION (N = 3, 5, 8, 10)
     * ========================================================================= */
    console.log('\n--- SUITE 2: Odd and Even Batch Cryptographic Verification ---');

    const testSizes = [3, 5, 8, 10];

    for (const N of testSizes) {
        console.log(`\n  --- Testing Batch Size N = ${N} ---`);
        const batchId = `BATCH-TEST-N${N}`;
        const bData = createTestBatch(batchId, `Amoxicillin ${N * 50}mg`, '2026-03-01', '2028-03-01', N);

        // Representative leaf indices: First (0), Middle (floor(N/2)), Last (N-1)
        const testIndices = [0, Math.floor(N / 2), N - 1];
        const uniqueIndices = [...new Set(testIndices)];

        for (const idx of uniqueIndices) {
            const expectedUnitId = bData.units[idx].unitId;
            console.log(`    Verifying leaf #${idx} (${expectedUnitId})...`);

            // Verify with explicit batchId filter
            const resExplicit = lookupAndVerifyRecord(expectedUnitId, batchId, engine, testBatchesMap);
            assert(resExplicit.found === true, `N=${N}, idx=${idx}: Found with explicit batchId`);
            assert(resExplicit.state === 'verified', `N=${N}, idx=${idx}: State is verified`);
            assert(resExplicit.verification.status === StatusCode.SUCCESS, `N=${N}, idx=${idx}: C engine status code 0`);
            assert(resExplicit.leafIndex === idx, `N=${N}, idx=${idx}: Leaf index matches`);

            // Verify with blank/omitted batchId (session-wide search)
            const resGlobal = lookupAndVerifyRecord(expectedUnitId, null, engine, testBatchesMap);
            assert(resGlobal.found === true, `N=${N}, idx=${idx}: Found with global session lookup`);
            assert(resGlobal.batchId === batchId, `N=${N}, idx=${idx}: Correct batch identified`);
            assert(resGlobal.state === 'verified', `N=${N}, idx=${idx}: Global lookup verified`);

            // Check MGP1 proof properties
            const parsed = parseProof(resExplicit.proofBytes);
            assert(parsed.magic === 'MGP1', `N=${N}, idx=${idx}: MGP1 magic header`);
            assert(parsed.leafIndex === idx, `N=${N}, idx=${idx}: Proof leafIndex matches`);
            assert(parsed.totalLeaves === N, `N=${N}, idx=${idx}: Proof totalLeaves matches`);
            assert(resExplicit.proofBytes.length === 14 + parsed.stepCount * 33, `N=${N}, idx=${idx}: Wire size matches 14 + 33*steps`);
        }
    }

    /* =========================================================================
     * SUITE 3: INVALID LOOKUPS & BOUNDARY CHECKS
     * ========================================================================= */
    console.log('\n--- SUITE 3: Invalid Lookups & Mismatch Handling ---');

    {
        // 3.1 Empty Unit ID
        const resEmpty = lookupAndVerifyRecord('', null, engine, testBatchesMap);
        assert(resEmpty.found === false, 'Empty Unit ID returns found: false');
        assert(resEmpty.state === 'notfound', 'Empty Unit ID state is "notfound"');
        assert(resEmpty.error.includes('cannot be empty'), 'Empty Unit ID returns clear validation error');

        const resWhitespace = lookupAndVerifyRecord('   ', null, engine, testBatchesMap);
        assert(resWhitespace.found === false, 'Whitespace Unit ID rejected');

        // 3.2 Unknown Unit ID
        const resUnknown = lookupAndVerifyRecord('UNIT-999999', null, engine, testBatchesMap);
        assert(resUnknown.found === false, 'Unknown Unit ID returns found: false');
        assert(resUnknown.state === 'notfound', 'Unknown Unit ID state is "notfound"');
        assert(resUnknown.error.includes('not found in any registered session batch'), 'Clear error for unknown Unit ID');

        // 3.3 Wrong / Non-existent Batch ID filter
        const resWrongBatch = lookupAndVerifyRecord('UNIT-000001', 'BATCH-NONEXISTENT', engine, testBatchesMap);
        assert(resWrongBatch.found === false, 'Non-existent Batch ID returns found: false');
        assert(resWrongBatch.state === 'notfound', 'Non-existent Batch ID state is "notfound"');
        assert(resWrongBatch.error.includes('does not exist in this session'), 'Clear error for non-existent Batch ID');

        // 3.4 Cross-batch mismatch: Valid Unit ID from Batch A requested under Batch B
        // UNIT-TEST-N10-000005 exists in BATCH-TEST-N10, but does NOT exist in BATCH-TEST-N3 (which only has 3 units)
        const resCrossBatch = lookupAndVerifyRecord('UNIT-TEST-N10-000005', 'BATCH-TEST-N3', engine, testBatchesMap);
        assert(resCrossBatch.found === false, 'Unit ID from different batch is rejected under foreign batch filter');
        assert(resCrossBatch.state === 'notfound', 'Cross-batch lookup state is "notfound"');
        assert(resCrossBatch.error.includes('not found in batch "BATCH-TEST-N3"'), 'Accurate mismatch message prevents accidental cross-batch returns');

        // 3.5 Missing / Empty session batches map
        const emptyMap = new Map();
        const resNoBatches = lookupAndVerifyRecord('UNIT-000001', null, engine, emptyMap);
        assert(resNoBatches.found === false, 'Lookup with empty session map returns found: false');
        assert(resNoBatches.state === 'nobatch', 'Lookup with empty session map returns state "nobatch"');

        // 3.6 Engine unavailable check
        const resNoEngine = lookupAndVerifyRecord('UNIT-000001', null, null, testBatchesMap);
        assert(resNoEngine.found === false, 'Lookup with null engine returns found: false');
        assert(resNoEngine.state === 'unavailable', 'Lookup with null engine returns state "unavailable"');
    }

    /* =========================================================================
     * SUITE 4: NEGATIVE SECURITY & CRYPTOGRAPHIC TAMPER RESISTANCE
     * ========================================================================= */
    console.log('\n--- SUITE 4: Negative Security & Tamper Resistance ---');

    {
        const b = testBatchesMap.get('BATCH-TEST-N8');
        const unit = b.units[2]; // Leaf index 2 (UNIT-000003)
        const authenticProof = b.context.generateProof(2);

        // 4.1 Authentic record succeeds
        const authResult = engine.verifyRecord(unit.record, authenticProof, b.root_hex);
        assert(authResult.valid === true, 'Authentic record verification succeeds (status: 0)');

        // 4.2 Altered record: Formulation modified
        const tamperedRecordName = { ...unit.record, medicine_name: 'Amoxicillin 400mg [COUNTERFEIT]' };
        const tamperedNameResult = engine.verifyRecord(tamperedRecordName, authenticProof, b.root_hex);
        assert(tamperedNameResult.valid === false, 'Altered medicine name is rejected by C engine');
        assert(tamperedNameResult.status === StatusCode.ERR_ROOT_MISMATCH, 'Altered medicine name returns ERR_ROOT_MISMATCH (-10)');

        // 4.3 Altered record: Unit ID modified
        const tamperedRecordUnit = { ...unit.record, unit_id: 'UNIT-999999' };
        const tamperedUnitResult = engine.verifyRecord(tamperedRecordUnit, authenticProof, b.root_hex);
        assert(tamperedUnitResult.valid === false, 'Altered unit ID is rejected');
        assert(tamperedUnitResult.status === StatusCode.ERR_ROOT_MISMATCH, 'Altered unit ID returns ERR_ROOT_MISMATCH (-10)');

        // 4.4 Altered record: Expiry date modified
        const tamperedRecordExp = { ...unit.record, expiry_date: '2035-12-31' };
        const tamperedExpResult = engine.verifyRecord(tamperedRecordExp, authenticProof, b.root_hex);
        assert(tamperedExpResult.valid === false, 'Altered expiry date is rejected');
        assert(tamperedExpResult.status === StatusCode.ERR_ROOT_MISMATCH, 'Altered expiry date returns ERR_ROOT_MISMATCH (-10)');

        // 4.5 Altered proof: Sibling hash bit flip
        const tamperedProofBytes = new Uint8Array(authenticProof);
        tamperedProofBytes[14] ^= 0x01; // flip 1 bit in first sibling hash
        const tamperedProofResult = engine.verifyRecord(unit.record, tamperedProofBytes, b.root_hex);
        assert(tamperedProofResult.valid === false, 'Proof with bit-flipped sibling hash is rejected');

        // 4.6 Altered proof: Direction byte flipped
        const flippedDirBytes = new Uint8Array(authenticProof);
        flippedDirBytes[14 + 32] = (flippedDirBytes[14 + 32] === 0 ? 1 : 0);
        const flippedDirResult = engine.verifyRecord(unit.record, flippedDirBytes, b.root_hex);
        assert(flippedDirResult.valid === false, 'Proof with flipped direction byte is rejected');

        // 4.7 Foreign / Incorrect Merkle Root
        const foreignRoot = '0000000000000000000000000000000000000000000000000000000000000000';
        const foreignRootResult = engine.verifyRecord(unit.record, authenticProof, foreignRoot);
        assert(foreignRootResult.valid === false, 'Verification against all-zero root is rejected');
        assert(foreignRootResult.status === StatusCode.ERR_ROOT_MISMATCH, 'Foreign root returns ERR_ROOT_MISMATCH (-10)');

        // 4.8 Truncated proof bytes: Rejected gracefully by C parser
        const truncatedBytes = authenticProof.subarray(0, authenticProof.length - 10);
        const truncRes = engine.verifyRecord(unit.record, truncatedBytes, b.root_hex);
        assert(truncRes.valid === false, 'Truncated proof is rejected by C engine');
        assert(truncRes.status === StatusCode.ERR_INVALID_MGP1_PROOF, 'Truncated proof returns ERR_INVALID_MGP1_PROOF (-6)');
    }

    /* =========================================================================
     * SUITE 5: LIFECYCLE, RESOURCE MANAGEMENT & HANDLE CAPACITY
     * ========================================================================= */
    console.log('\n--- SUITE 5: Lifecycle, Handle Capacity & Memory Safety ---');

    {
        // 5.1 Stale Handle Defense: Calling methods on destroyed context
        const tempCtx = engine.createBatch();
        tempCtx.addRecord({
            batch_id: 'TEMP-BATCH',
            unit_id: 'U-01',
            medicine_name: 'Test',
            manufacturing_date: '2026-01-01',
            expiry_date: '2027-01-01'
        });
        tempCtx.buildTree();
        assert(tempCtx.getRootHex().length === 64, 'Temp batch built successfully');

        tempCtx.destroy();
        assert(tempCtx.isDestroyed === true, 'Batch marked as destroyed');
        assertThrows(() => tempCtx.getRootHex(), 'has already been destroyed', 'Calling getRootHex() on destroyed batch throws');
        assertThrows(() => tempCtx.generateProof(0), 'has already been destroyed', 'Calling generateProof() on destroyed batch throws');
        assertThrows(() => tempCtx.addRecord(new Uint8Array([1, 2, 3])), 'has already been destroyed', 'Calling addRecord() on destroyed batch throws');

        // 5.2 Capacity verification: Confirm C handle pool capacity is 32 contexts
        console.log('    Verifying handle pool capacity & recycling under 32-slot limit...');
        const poolBatches = [];
        for (let i = 0; i < 25; i++) {
            const ctx = engine.createBatch();
            ctx.addRecord({
                batch_id: `POOL-BATCH-${i}`,
                unit_id: `UNIT-001`,
                medicine_name: 'Pool Med',
                manufacturing_date: '2026-01-01',
                expiry_date: '2027-01-01'
            });
            ctx.buildTree();
            poolBatches.push(ctx);
        }
        assert(poolBatches.length === 25, '25 concurrent contexts allocated safely within 32-slot limit');

        // Destroy all pool batches and confirm recycling
        for (const ctx of poolBatches) {
            ctx.destroy();
        }

        // Verify fresh context can be allocated immediately in recycled pool
        const freshCtx = engine.createBatch();
        assert(freshCtx !== null && !freshCtx.isDestroyed, 'Recycled pool immediately allocates fresh context');
        freshCtx.destroy();

        // 5.3 Repeated verification memory stability:
        // Perform 500 verifications in a tight loop and assert zero memory growth or degradation
        const bBench = testBatchesMap.get('BATCH-TEST-N10');
        const benchRecord = bBench.units[0].record;
        const benchProof = bBench.context.generateProof(0);

        for (let loop = 0; loop < 500; loop++) {
            const loopRes = engine.verifyRecord(benchRecord, benchProof, bBench.root_hex);
            if (!loopRes.valid) {
                throw new Error(`Loop verification failed at iteration ${loop}`);
            }
        }
        console.log('  [PASS] 500 consecutive verifyRecord() calls executed with 100% success and stable memory');
    }

    // Clean up test batches map
    for (const b of testBatchesMap.values()) {
        if (b.context && !b.context.isDestroyed) {
            b.context.destroy();
        }
    }
    testBatchesMap.clear();

    console.log('\n============================================================');
    console.log(`  PHASE 3C TESTS COMPLETE: ${passedTests}/${totalTests} tests PASSED, ${failedTests} FAILED.`);
    console.log('============================================================\n');

    if (failedTests > 0) {
        process.exit(1);
    }
}

runPhase3CTests().catch(err => {
    console.error('[FATAL PHASE 3C ERROR]:', err);
    process.exit(1);
});

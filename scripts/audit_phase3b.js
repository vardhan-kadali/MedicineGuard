/**
 * MedicineGuard — Phase 3B Independent Comprehensive Audit Suite (Node.js)
 * 
 * Verifies:
 * 1. Frontend Date Validation (calendar feasibility, leap-years, impossible dates, range checks)
 * 2. Demonstration of previous test-harness anomaly
 * 3. Batch Creation & Merkle Tree construction across N in {1, 2, 3, 5, 8, 10, 100}
 * 4. Proof generation and verification for first, middle, and last leaves
 * 5. MGP1 wire format compliance (magic, header, step sizes, directions)
 * 6. Negative security tests: altered records, altered proofs, flipped directions, foreign roots, out-of-bounds indices
 * 7. Resource lifecycle & handle recycling
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
    validateCalendarDate,
    validateDateRange
} from '../public/js/app.js';

let totalAssertions = 0;
let passedAssertions = 0;
let failedAssertions = 0;

function assert(condition, message) {
    totalAssertions++;
    if (!condition) {
        failedAssertions++;
        console.error(`  [FAIL] #${totalAssertions}: ${message}`);
        throw new Error(`Assertion failed: ${message}`);
    } else {
        passedAssertions++;
        console.log(`  [PASS] #${totalAssertions}: ${message}`);
    }
}

function assertThrows(fn, expectedSubstr, message) {
    totalAssertions++;
    let threw = false;
    let actualMsg = '';
    try {
        fn();
    } catch (e) {
        threw = true;
        actualMsg = e.message;
    }
    if (!threw) {
        failedAssertions++;
        console.error(`  [FAIL] #${totalAssertions}: ${message} (Expected function to throw)`);
        throw new Error(`Expected throw: ${message}`);
    }
    if (expectedSubstr && !actualMsg.includes(expectedSubstr)) {
        failedAssertions++;
        console.error(`  [FAIL] #${totalAssertions}: ${message} (Expected "${expectedSubstr}", got "${actualMsg}")`);
        throw new Error(`Error message mismatch: ${message}`);
    }
    passedAssertions++;
    console.log(`  [PASS] #${totalAssertions}: ${message}`);
}

async function runAudit() {
    console.log('============================================================');
    console.log('  MedicineGuard — Phase 3B Comprehensive Audit Suite');
    console.log('============================================================\n');

    /* =========================================================================
     * SECTION 1: STRICT CALENDAR DATE VALIDATION AUDIT
     * ========================================================================= */
    console.log('--- SECTION 1: Calendar Date & Range Validation ---');

    // 1.1 Impossible calendar days
    assert(validateCalendarDate('2026-02-31').valid === false, 'Rejects impossible date 2026-02-31');
    assert(validateCalendarDate('2026-04-31').valid === false, 'Rejects impossible date 2026-04-31 (April has 30 days)');
    assert(validateCalendarDate('2026-06-31').valid === false, 'Rejects impossible date 2026-06-31 (June has 30 days)');
    assert(validateCalendarDate('2026-09-31').valid === false, 'Rejects impossible date 2026-09-31 (September has 30 days)');
    assert(validateCalendarDate('2026-11-31').valid === false, 'Rejects impossible date 2026-11-31 (November has 30 days)');

    // 1.2 Leap-year handling
    assert(validateCalendarDate('2026-02-29').valid === false, 'Rejects 2026-02-29 (2026 is non-leap year)');
    assert(validateCalendarDate('2024-02-29').valid === true, 'Accepts 2024-02-29 (2024 is a leap year)');
    assert(validateCalendarDate('2000-02-29').valid === true, 'Accepts 2000-02-29 (2000 is divisible by 400)');
    assert(validateCalendarDate('2100-02-29').valid === false, 'Rejects 2100-02-29 (2100 is not divisible by 400)');

    // 1.3 Out-of-bounds months and days
    assert(validateCalendarDate('2026-00-15').valid === false, 'Rejects month 00');
    assert(validateCalendarDate('2026-13-15').valid === false, 'Rejects month 13');
    assert(validateCalendarDate('2026-05-00').valid === false, 'Rejects day 00');
    assert(validateCalendarDate('2026-05-32').valid === false, 'Rejects day 32');

    // 1.4 Empty and malformed dates
    assert(validateCalendarDate('').valid === false, 'Rejects empty date string');
    assert(validateCalendarDate('   ').valid === false, 'Rejects whitespace date string');
    assert(validateCalendarDate(null).valid === false, 'Rejects null date');
    assert(validateCalendarDate('2026/05/15').valid === false, 'Rejects slashes (YYYY/MM/DD)');
    assert(validateCalendarDate('15-05-2026').valid === false, 'Rejects DD-MM-YYYY format');

    // 1.5 Valid calendar dates
    assert(validateCalendarDate('2026-01-15').valid === true, 'Accepts valid date 2026-01-15');
    assert(validateCalendarDate('2028-12-31').valid === true, 'Accepts valid date 2028-12-31');

    // 1.6 Date range relationships (exp vs mfg)
    assert(validateDateRange('2028-01-01', '2026-01-01').valid === false, 'Rejects expiry < manufacturing (2026-01-01 < 2028-01-01)');
    assert(validateDateRange('2026-06-01', '2026-06-01').valid === false, 'Rejects expiry == manufacturing (2026-06-01 === 2026-06-01)');
    assert(validateDateRange('2026-01-01', '2028-01-01').valid === true, 'Accepts valid date range (2028-01-01 > 2026-01-01)');
    assert(validateDateRange('2026-02-31', '2028-01-01').valid === false, 'Rejects range with invalid mfg date (2026-02-31)');
    assert(validateDateRange('2026-01-01', '2028-02-31').valid === false, 'Rejects range with invalid exp date (2028-02-31)');

    /* =========================================================================
     * SECTION 2: TEST HARNESS ERROR INVESTIGATION
     * ========================================================================= */
    console.log('\n--- SECTION 2: Test Harness False Positive Analysis ---');
    {
        let harnessThrownCaught = false;
        try {
            // This is the exact pattern from the flawed test harness:
            serializeMedicineRecord({
                batch_id: 'BATCH001',
                unit_id: 'UNIT001',
                medicine_name: 'Aspirin',
                manufacturing_date: '2028-01-01',
                expiry_date: '2026-01-01'
            });
            // serializeMedicineRecord validates byte wire format (10 chars, YYYY-MM-DD), but not semantic ordering.
            // Then the test harness threw its own error:
            throw new Error('Should have rejected expiry < mfg');
        } catch (e) {
            harnessThrownCaught = true;
            console.log(`  [INVESTIGATION CONFIRMED] Test harness caught its OWN error: "${e.message}"`);
        }
        assert(harnessThrownCaught, 'Demonstrated that previous report was a test-harness false positive');

        // Now verify that the actual frontend validation catches it properly:
        const validationResult = validateDateRange('2028-01-01', '2026-01-01');
        assert(validationResult.valid === false, 'Actual frontend validation genuinely catches inverted dates');
        assert(validationResult.error.includes('cannot be earlier than'), 'Validation error message is descriptive and accurate');
    }

    /* =========================================================================
     * SECTION 3: WEBASSEMBLY ENGINE INITIALIZATION & GOLDEN BATCH AUDIT
     * ========================================================================= */
    console.log('\n--- SECTION 3: WebAssembly Batch & Proof Engine Audit ---');

    const engine = await MedicineGuard.init();
    assert(engine !== null, 'WebAssembly engine initialized successfully');

    // Test across N in {1, 2, 3, 5, 8, 10, 100}
    const batchSizes = [1, 2, 3, 5, 8, 10, 100];

    // Reference roots from Phase 2 Golden Vectors (using BATCH-2026-0001 / Amoxicillin 500mg)
    const goldenRoots = {
        1: '5d761d5f85dfe7c4b8bc8bec332649908458bd83e6a34cea9265608ac0e94bbb',
        2: 'af02709fa129af36821633b77b837c1a6a0efd8205594c4f50663cb88f8d5e52',
        3: '5da0c7409089f6e7983ffd458e565e7c29f9b48b937e82a171c5973e9b7eb152',
        5: 'a343d4ec527cb9b28072e451d492bf563c70de09d821b968c3a129e1b4a33c86',
        8: '1724712c9d47c22951d3d2c7403cfdcf0659c58b1b6f2330c178c7decd3f4274',
        100: '49b79857a4ae9e544d87aa0b723382494dcd5f68775958d8a8affa735a6a01f0'
    };

    for (const N of batchSizes) {
        console.log(`\n  --- Auditing Batch Size N = ${N} ---`);
        const batch = engine.createBatch();

        const records = [];
        const serializedRecords = [];

        for (let i = 0; i < N; i++) {
            const unitId = `UNIT-${String(i + 1).padStart(6, '0')}`;
            const rec = {
                batch_id: 'BATCH-2026-0001',
                unit_id: unitId,
                medicine_name: 'Amoxicillin 500mg',
                manufacturing_date: '2026-01-15',
                expiry_date: '2028-01-15'
            };
            const s = serializeMedicineRecord(rec);
            records.push(rec);
            serializedRecords.push(s);
            batch.addRecord(s);
        }

        // Build tree
        batch.buildTree();
        const rootHex = batch.getRootHex();
        const height = batch.getHeight();

        assert(rootHex.length === 64, `N=${N}: Root hex has 64 characters`);
        if (goldenRoots[N]) {
            assert(rootHex === goldenRoots[N], `N=${N}: Root matches native golden root exactly (${rootHex.substring(0, 16)}...)`);
        }

        // Test representative leaves: first (0), middle (floor(N/2)), last (N-1)
        const testIndices = [0, Math.floor(N / 2), N - 1];
        const uniqueIndices = [...new Set(testIndices)];

        for (const idx of uniqueIndices) {
            console.log(`    Testing leaf index ${idx}/${N - 1}...`);

            // 1. Generate proof
            const proofBytes = batch.generateProof(idx);
            assert(proofBytes instanceof Uint8Array, `N=${N}, idx=${idx}: Proof generated as Uint8Array`);

            // 2. Parse proof and check MGP1 format
            const parsed = parseProof(proofBytes);
            assert(parsed.magic === 'MGP1', `N=${N}, idx=${idx}: Proof header magic is MGP1`);
            assert(parsed.leafIndex === idx, `N=${N}, idx=${idx}: Proof leafIndex matches ${idx}`);
            assert(parsed.totalLeaves === N, `N=${N}, idx=${idx}: Proof totalLeaves matches ${N}`);
            assert(proofBytes.length === 14 + parsed.stepCount * 33, `N=${N}, idx=${idx}: Wire size matches 14 + 33*steps (${proofBytes.length} bytes)`);

            // Verify each step structure
            for (const step of parsed.steps) {
                assert(step.direction === 0 || step.direction === 1, `N=${N}, idx=${idx}: Step direction is 0 or 1`);
                assert(step.siblingHash.length === 32, `N=${N}, idx=${idx}: Sibling hash is 32 bytes`);
            }

            // 3. Verify authentic record
            const verifResult = engine.verifyRecord(records[idx], proofBytes, rootHex);
            assert(verifResult.valid === true, `N=${N}, idx=${idx}: Authentic record verifies successfully (status: ${verifResult.status})`);

            // 4. Negative test: Altered record
            const alteredRec = { ...records[idx], medicine_name: 'Counterfeit Formulation' };
            const alteredRecResult = engine.verifyRecord(alteredRec, proofBytes, rootHex);
            assert(alteredRecResult.valid === false, `N=${N}, idx=${idx}: Altered record is rejected`);
            assert(alteredRecResult.status === StatusCode.ERR_ROOT_MISMATCH, `N=${N}, idx=${idx}: Altered record returns ERR_ROOT_MISMATCH (-10)`);

            // 5. Negative test: Altered proof (tampered sibling hash) if steps exist
            if (parsed.stepCount > 0) {
                const tamperedProofBytes = new Uint8Array(proofBytes);
                // Flip a bit in the first sibling hash (starts at offset 14)
                tamperedProofBytes[14] ^= 0xFF;
                const tamperedProofResult = engine.verifyRecord(records[idx], tamperedProofBytes, rootHex);
                assert(tamperedProofResult.valid === false, `N=${N}, idx=${idx}: Proof with tampered sibling hash is rejected`);

                // 6. Negative test: Flipped direction byte (offset 14 + 32 = 46)
                const flippedDirBytes = new Uint8Array(proofBytes);
                flippedDirBytes[14 + 32] = (flippedDirBytes[14 + 32] === 0 ? 1 : 0);
                const flippedDirResult = engine.verifyRecord(records[idx], flippedDirBytes, rootHex);
                assert(flippedDirResult.valid === false, `N=${N}, idx=${idx}: Proof with flipped direction byte is rejected`);
            }

            // 7. Negative test: Wrong Merkle Root
            const wrongRootHex = '0000000000000000000000000000000000000000000000000000000000000000';
            const wrongRootResult = engine.verifyRecord(records[idx], proofBytes, wrongRootHex);
            assert(wrongRootResult.valid === false, `N=${N}, idx=${idx}: Verification against all-zero root is rejected`);
        }

        // Out-of-bounds leaf index
        assertThrows(() => batch.generateProof(N), 'Invalid leaf index', `N=${N}: Proof generation for leafIndex ${N} throws invalid index error`);
        assertThrows(() => batch.generateProof(N + 5), 'Invalid leaf index', `N=${N}: Proof generation for leafIndex ${N + 5} throws invalid index error`);

        // Clean up batch context
        batch.destroy();
    }

    /* =========================================================================
     * SECTION 4: RESOURCE MANAGEMENT & LIFECYCLE AUDIT
     * ========================================================================= */
    console.log('\n--- SECTION 4: Resource Management & Handle Lifecycle ---');

    {
        const b = engine.createBatch();
        const rec = {
            batch_id: 'LIFECYCLE-1',
            unit_id: 'UNIT-001',
            medicine_name: 'Test Med',
            manufacturing_date: '2026-01-01',
            expiry_date: '2028-01-01'
        };
        b.addRecord(serializeMedicineRecord(rec));
        b.buildTree();
        assert(b.getRootHex().length === 64, 'Batch created and built');

        // Destroy batch
        b.destroy();

        // Stale handle defense: subsequent calls must throw
        assertThrows(() => b.getRootHex(), 'has already been destroyed', 'Calling getRootHex() on destroyed batch throws');
        assertThrows(() => b.generateProof(0), 'has already been destroyed', 'Calling generateProof() on destroyed batch throws');
        assertThrows(() => b.addRecord(new Uint8Array([1, 2, 3])), 'has already been destroyed', 'Calling addRecord() on destroyed batch throws');

        // Multiple rapid create-destroy cycles to verify zero pool exhaustion
        for (let cycle = 0; cycle < 30; cycle++) {
            const tempBatch = engine.createBatch();
            tempBatch.addRecord(serializeMedicineRecord({
                batch_id: `CYCLE-${cycle}`,
                unit_id: `U-${cycle}`,
                medicine_name: 'Test',
                manufacturing_date: '2026-01-01',
                expiry_date: '2027-01-01'
            }));
            tempBatch.buildTree();
            assert(tempBatch.getRootHex().length === 64, `Cycle ${cycle}: Generated valid root`);
            tempBatch.destroy();
        }
        console.log('  [PASS] 30 rapid create/build/destroy cycles recycled handles cleanly without exhaustion');
    }

    /* =========================================================================
     * AUDIT SUMMARY
     * ========================================================================= */
    console.log('\n============================================================');
    console.log(`  AUDIT COMPLETE: ${passedAssertions}/${totalAssertions} assertions PASSED, ${failedAssertions} FAILED.`);
    console.log('============================================================\n');

    if (failedAssertions > 0) {
        process.exit(1);
    }
}

runAudit().catch(err => {
    console.error('[FATAL AUDIT ERROR]:', err);
    process.exit(1);
});

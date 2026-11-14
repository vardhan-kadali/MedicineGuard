/**
 * MedicineGuard - WebAssembly Engine Test Suite (Node.js)
 * 
 * Comprehensive automated test suite verifying:
 *   1. Primitive SHA-256 (NIST test vectors)
 *   2. MG01 Record serialization and validation
 *   3. Native C engine parity across N in {1, 2, 3, 5, 7, 8, 100, 1000, 10000}
 *   4. Merkle proof generation, parsing, and verification
 *   5. Negative security and tamper resistance
 *   6. Handle pool lifecycle, generation counters, and stress tests
 */

import {
    MedicineGuard,
    serializeMedicineRecord,
    parseProof,
    bytesToHex,
    hexToBytes,
    StatusCode
} from '../public/js/wasm-loader.js';

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
    totalTests++;
    if (!condition) {
        failedTests++;
        console.error(`  FAIL [${totalTests}]: ${message}`);
        throw new Error(`Assertion failed: ${message}`);
    } else {
        passedTests++;
        console.log(`  PASS [${totalTests}]: ${message}`);
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
        console.error(`  FAIL [${totalTests}]: ${message} (Expected function to throw, but it did not)`);
        throw new Error(`Expected throw: ${message}`);
    }
    if (expectedSubstr && !actualMsg.includes(expectedSubstr)) {
        failedTests++;
        console.error(`  FAIL [${totalTests}]: ${message} (Expected error containing "${expectedSubstr}", got "${actualMsg}")`);
        throw new Error(`Error message mismatch: ${message}`);
    }
    passedTests++;
    console.log(`  PASS [${totalTests}]: ${message}`);
}

async function runTests() {
    console.log('============================================================');
    console.log('  MedicineGuard - WebAssembly Test Suite (Node.js)');
    console.log('============================================================');

    const engine = await MedicineGuard.init();
    assert(engine !== null && typeof engine === 'object', 'MedicineGuard initialized successfully');

    /* --------------------------------------------------------------------
     * Suite 1: Primitive Cryptographic Primitives (NIST SHA-256 Vectors)
     * -------------------------------------------------------------------- */
    console.log('\n--- Suite 1: NIST SHA-256 Test Vectors ---');
    
    // NIST Vector 1: Empty string
    const hashEmpty = engine.sha256Hex('');
    assert(hashEmpty === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'NIST SHA-256 for empty string matches');

    // NIST Vector 2: "abc"
    const hashAbc = engine.sha256Hex('abc');
    assert(hashAbc === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        'NIST SHA-256 for "abc" matches');

    // NIST Vector 3: 56-byte message
    const msg56 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
    const hash56 = engine.sha256Hex(msg56);
    assert(hash56 === '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
        'NIST SHA-256 for 56-byte message matches');

    // Byte input vs String input equivalence
    const hashBytes = engine.sha256(new TextEncoder().encode('abc'));
    assert(bytesToHex(hashBytes) === hashAbc, 'engine.sha256(Uint8Array) matches engine.sha256Hex(string)');

    /* --------------------------------------------------------------------
     * Suite 2: MG01 Record Serialization & Validation
     * -------------------------------------------------------------------- */
    console.log('\n--- Suite 2: MG01 Record Serialization & Validation ---');

    const validRecord = {
        batch_id: 'BATCH-2026-0001',
        unit_id: 'UNIT-000001',
        medicine_name: 'Amoxicillin 500mg',
        manufacturing_date: '2026-01-15',
        expiry_date: '2028-01-15'
    };

    const mg01Bytes = serializeMedicineRecord(validRecord);
    assert(mg01Bytes.length > 24, 'Serialized record has non-trivial length');
    assert(mg01Bytes[0] === 0x4d && mg01Bytes[1] === 0x47 && mg01Bytes[2] === 0x30 && mg01Bytes[3] === 0x31,
        'MG01 header magic is "MG01"');

    // Invalid record checks
    assertThrows(() => serializeMedicineRecord({ ...validRecord, batch_id: '' }),
        'batch_id cannot be empty', 'Rejects empty batch_id');
    assertThrows(() => serializeMedicineRecord({ ...validRecord, unit_id: '' }),
        'unit_id cannot be empty', 'Rejects empty unit_id');
    assertThrows(() => serializeMedicineRecord({ ...validRecord, medicine_name: '' }),
        'medicine_name cannot be empty', 'Rejects empty medicine_name');
    assertThrows(() => serializeMedicineRecord({ ...validRecord, manufacturing_date: '15-01-2026' }),
        'Invalid manufacturing_date format', 'Rejects invalid date format');
    assertThrows(() => serializeMedicineRecord({ ...validRecord, batch_id: 'BATCH\0NULL' }),
        'embedded null characters', 'Rejects embedded null characters');

    /* --------------------------------------------------------------------
     * Suite 3: Native C Parity & Golden Root Vectors
     * -------------------------------------------------------------------- */
    console.log('\n--- Suite 3: Native C Parity & Golden Root Vectors ---');

    const goldenVectors = [
        { n: 1, height: 1, root: '5d761d5f85dfe7c4b8bc8bec332649908458bd83e6a34cea9265608ac0e94bbb' },
        { n: 2, height: 2, root: 'af02709fa129af36821633b77b837c1a6a0efd8205594c4f50663cb88f8d5e52' },
        { n: 3, height: 3, root: '5da0c7409089f6e7983ffd458e565e7c29f9b48b937e82a171c5973e9b7eb152' },
        { n: 5, height: 4, root: 'a343d4ec527cb9b28072e451d492bf563c70de09d821b968c3a129e1b4a33c86' },
        { n: 7, height: 4, root: '1b5230d15958d1e7c02d70c076c1a9bec783af1031ea79462ede7a2095f6c988' },
        { n: 8, height: 4, root: '1724712c9d47c22951d3d2c7403cfdcf0659c58b1b6f2330c178c7decd3f4274' },
        { n: 100, height: 8, root: '49b79857a4ae9e544d87aa0b723382494dcd5f68775958d8a8affa735a6a01f0' },
        { n: 1000, height: 11, root: 'f95ddec8799732ab9093cd5a94a13ce6795b6774bde436a7d9df8972b030e080' },
        { n: 10000, height: 15, root: '9fadfeef96fcde03f86dbe6c2cabf987c3287c86d7ccaf65bb8ac05b18d8e8e8' }
    ];

    for (const vector of goldenVectors) {
        const batch = engine.createBatch();
        for (let i = 1; i <= vector.n; i++) {
            const padStr = String(i).padStart(6, '0');
            batch.addRecord({
                batch_id: 'BATCH-2026-0001',
                unit_id: `UNIT-${padStr}`,
                medicine_name: 'Amoxicillin 500mg',
                manufacturing_date: '2026-01-15',
                expiry_date: '2028-01-15'
            });
        }
        batch.buildTree();

        assert(batch.getLeafCount() === vector.n, `N=${vector.n}: leaf count is ${vector.n}`);
        assert(batch.getHeight() === vector.height, `N=${vector.n}: tree height is ${vector.height}`);
        assert(batch.getRootHex() === vector.root, `N=${vector.n}: Merkle Root matches native GCC root bit-for-bit`);

        batch.destroy();
    }

    /* --------------------------------------------------------------------
     * Suite 4: Proof Generation, Parsing & Verification
     * -------------------------------------------------------------------- */
    console.log('\n--- Suite 4: Proof Generation, Parsing & Verification ---');

    // Test across odd and even counts: N=1, N=2, N=3, N=5, N=7, N=8
    for (const n of [1, 2, 3, 5, 7, 8]) {
        const batch = engine.createBatch();
        const records = [];
        for (let i = 1; i <= n; i++) {
            const rec = {
                batch_id: 'BATCH-2026-PROOF',
                unit_id: `UNIT-${String(i).padStart(6, '0')}`,
                medicine_name: 'Paracetamol 500mg',
                manufacturing_date: '2026-02-01',
                expiry_date: '2028-02-01'
            };
            records.push(rec);
            batch.addRecord(rec);
        }
        batch.buildTree();
        const rootHex = batch.getRootHex();

        // Verify proof for every single leaf in this tree
        for (let leafIdx = 0; leafIdx < n; leafIdx++) {
            const proofBytes = batch.generateProof(leafIdx);
            const parsed = parseProof(proofBytes);

            assert(parsed.magic === 'MGP1', `N=${n}, leaf=${leafIdx}: proof magic is MGP1`);
            assert(parsed.leafIndex === leafIdx, `N=${n}, leaf=${leafIdx}: leafIndex matches`);
            assert(parsed.totalLeaves === n, `N=${n}, leaf=${leafIdx}: totalLeaves matches`);
            assert(proofBytes.length === 14 + parsed.stepCount * 33, `N=${n}, leaf=${leafIdx}: byte length matches formula 14 + steps*33`);

            // Verify via verifyRecord
            const vRecord = engine.verifyRecord(records[leafIdx], proofBytes, rootHex);
            assert(vRecord.valid === true && vRecord.status === StatusCode.SUCCESS,
                `N=${n}, leaf=${leafIdx}: verifyRecord succeeds`);

            // Verify via verifyLeafHash
            // Compute leaf hash: SHA256(0x00 || serialized_mg01)
            const serialized = serializeMedicineRecord(records[leafIdx]);
            const leafData = new Uint8Array(1 + serialized.length);
            leafData[0] = 0x00; // MG_DOMAIN_LEAF
            leafData.set(serialized, 1);
            const leafHash = engine.sha256(leafData);

            const vLeaf = engine.verifyLeafHash(leafHash, proofBytes, rootHex);
            assert(vLeaf.valid === true && vLeaf.status === StatusCode.SUCCESS,
                `N=${n}, leaf=${leafIdx}: verifyLeafHash succeeds`);
        }

        batch.destroy();
    }

    /* --------------------------------------------------------------------
     * Suite 5: Negative Security & Tamper Resistance
     * -------------------------------------------------------------------- */
    console.log('\n--- Suite 5: Negative Security & Tamper Resistance ---');

    {
        const batch = engine.createBatch();
        const recA = {
            batch_id: 'BATCH-SEC-01',
            unit_id: 'UNIT-000001',
            medicine_name: 'Amoxicillin 500mg',
            manufacturing_date: '2026-01-01',
            expiry_date: '2028-01-01'
        };
        const recB = {
            batch_id: 'BATCH-SEC-01',
            unit_id: 'UNIT-000002',
            medicine_name: 'Amoxicillin 500mg',
            manufacturing_date: '2026-01-01',
            expiry_date: '2028-01-01'
        };
        batch.addRecord(recA);
        batch.addRecord(recB);
        batch.buildTree();
        const rootHex = batch.getRootHex();
        const proofA = batch.generateProof(0);

        // 1. Tampered record field (medicine name altered)
        const tamperedRec = { ...recA, medicine_name: 'Counterfeit Pill' };
        const vTamperedRec = engine.verifyRecord(tamperedRec, proofA, rootHex);
        assert(vTamperedRec.valid === false && vTamperedRec.status === StatusCode.ERR_ROOT_MISMATCH,
            'Tampered medicine_name causes verification failure (ERR_ROOT_MISMATCH)');

        // 2. Tampered unit ID
        const tamperedUnit = { ...recA, unit_id: 'UNIT-999999' };
        const vTamperedUnit = engine.verifyRecord(tamperedUnit, proofA, rootHex);
        assert(vTamperedUnit.valid === false && vTamperedUnit.status === StatusCode.ERR_ROOT_MISMATCH,
            'Tampered unit_id causes verification failure (ERR_ROOT_MISMATCH)');

        // 3. Tampered date
        const tamperedDate = { ...recA, expiry_date: '2099-01-01' };
        const vTamperedDate = engine.verifyRecord(tamperedDate, proofA, rootHex);
        assert(vTamperedDate.valid === false && vTamperedDate.status === StatusCode.ERR_ROOT_MISMATCH,
            'Tampered expiry_date causes verification failure (ERR_ROOT_MISMATCH)');

        // 4. Bit flip in proof sibling hash
        const bitFlippedProof = new Uint8Array(proofA);
        bitFlippedProof[14] ^= 0x01; // flip 1 bit in sibling hash
        const vBitFlip = engine.verifyRecord(recA, bitFlippedProof, rootHex);
        assert(vBitFlip.valid === false && vBitFlip.status === StatusCode.ERR_ROOT_MISMATCH,
            'Bit flip in sibling hash causes verification failure');

        // 5. Toggled direction byte in proof step
        const flippedDirProof = new Uint8Array(proofA);
        flippedDirProof[14 + 32] ^= 0x01; // 1 -> 0
        const vFlippedDir = engine.verifyRecord(recA, flippedDirProof, rootHex);
        assert(vFlippedDir.valid === false && vFlippedDir.status === StatusCode.ERR_INVALID_MGP1_PROOF,
            'Flipping sibling direction causes validation failure (ERR_INVALID_MGP1_PROOF)');

        // 6. Truncated proof buffer
        const truncatedProof = proofA.subarray(0, proofA.length - 10);
        const vTruncated = engine.verifyRecord(recA, truncatedProof, rootHex);
        assert(vTruncated.valid === false && vTruncated.status === StatusCode.ERR_INVALID_MGP1_PROOF,
            'Truncated proof buffer returns ERR_INVALID_MGP1_PROOF');

        // 7. Corrupted proof magic
        const corruptedMagicProof = new Uint8Array(proofA);
        corruptedMagicProof[0] = 0x58; // 'X'
        const vCorruptMagic = engine.verifyRecord(recA, corruptedMagicProof, rootHex);
        assert(vCorruptMagic.valid === false && vCorruptMagic.status === StatusCode.ERR_INVALID_MGP1_PROOF,
            'Corrupted magic returns ERR_INVALID_MGP1_PROOF');

        // 8. Incorrect root hash
        const wrongRoot = '0000000000000000000000000000000000000000000000000000000000000000';
        const vWrongRoot = engine.verifyRecord(recA, proofA, wrongRoot);
        assert(vWrongRoot.valid === false && vWrongRoot.status === StatusCode.ERR_ROOT_MISMATCH,
            'Mismatching root hash fails verification');

        batch.destroy();
    }

    // Batch validation negative tests
    {
        // Empty batch
        const emptyBatch = engine.createBatch();
        assertThrows(() => emptyBatch.buildTree(),
            'Failed to build Merkle tree', 'Empty batch cannot build tree');
        emptyBatch.destroy();

        // Duplicate unit ID
        const dupBatch = engine.createBatch();
        dupBatch.addRecord({
            batch_id: 'BATCH-DUP',
            unit_id: 'UNIT-DUP-01',
            medicine_name: 'Aspirin',
            manufacturing_date: '2026-01-01',
            expiry_date: '2028-01-01'
        });
        dupBatch.addRecord({
            batch_id: 'BATCH-DUP',
            unit_id: 'UNIT-DUP-01', // duplicate!
            medicine_name: 'Aspirin',
            manufacturing_date: '2026-01-01',
            expiry_date: '2028-01-01'
        });
        assertThrows(() => dupBatch.buildTree(),
            'duplicate medicine unit ID', 'Duplicate unit ID rejected with ERR_DUPLICATE_UNIT');
        dupBatch.destroy();

        // Mixed batch IDs: caught on addRecord
        const mixedBatch = engine.createBatch();
        mixedBatch.addRecord({
            batch_id: 'BATCH-001',
            unit_id: 'UNIT-01',
            medicine_name: 'Aspirin',
            manufacturing_date: '2026-01-01',
            expiry_date: '2028-01-01'
        });
        assertThrows(() => {
            mixedBatch.addRecord({
                batch_id: 'BATCH-002', // different batch!
                unit_id: 'UNIT-02',
                medicine_name: 'Aspirin',
                manufacturing_date: '2026-01-01',
                expiry_date: '2028-01-01'
            });
        }, 'conflicting batch IDs', 'Mixed batch ID rejected on addRecord with ERR_MIXED_BATCH');
        mixedBatch.destroy();
    }

    /* --------------------------------------------------------------------
     * Suite 6: Handle Pool, Lifecycle & Stress Test
     * -------------------------------------------------------------------- */
    console.log('\n--- Suite 6: Handle Pool, Lifecycle & Stress Test ---');

    {
        // Stale handle protection
        const b = engine.createBatch();
        const handleVal = b.handle;
        b.destroy();

        // Calling addRecord on destroyed context
        assertThrows(() => b.addRecord(validRecord),
            'already been destroyed', 'Operating on destroyed JS wrapper throws');

        // Direct low-level call with stale handle into WASM
        const mg01 = serializeMedicineRecord(validRecord);
        const staleStatus = engine.withAllocatedBuffer(mg01, (ptr, len) => {
            return engine.module._mg_wasm_batch_add_record(handleVal, ptr, len);
        });
        assert(staleStatus === StatusCode.ERR_INVALID_HANDLE,
            'Direct WASM call with stale handle returns ERR_INVALID_HANDLE');

        // Generation counter increments on recycling
        const b1 = engine.createBatch();
        const h1 = b1.handle;
        b1.destroy();
        const b2 = engine.createBatch();
        const h2 = b2.handle;
        assert(h1 !== h2, `Recycled slot gets new generation: h1=${h1}, h2=${h2}`);
        b2.destroy();

        // Concurrency: Multiple concurrent contexts without crosstalk
        const contexts = [];
        for (let c = 0; c < 5; c++) {
            const ctx = engine.createBatch();
            ctx.addRecord({
                batch_id: `BATCH-CONCUR-${c}`,
                unit_id: 'UNIT-0001',
                medicine_name: `Drug ${c}`,
                manufacturing_date: '2026-01-01',
                expiry_date: '2028-01-01'
            });
            contexts.push(ctx);
        }

        for (let c = 0; c < 5; c++) {
            contexts[c].buildTree();
            assert(contexts[c].getLeafCount() === 1, `Context ${c} has 1 leaf`);
            contexts[c].destroy();
        }

        // Stress loop: 100 consecutive create/build/destroy cycles
        for (let cycle = 0; cycle < 100; cycle++) {
            const loopBatch = engine.createBatch();
            loopBatch.addRecord({
                batch_id: 'BATCH-STRESS',
                unit_id: `UNIT-${cycle}`,
                medicine_name: 'Stress Test Med',
                manufacturing_date: '2026-01-01',
                expiry_date: '2028-01-01'
            });
            loopBatch.buildTree();
            const root = loopBatch.getRootHex();
            assert(root.length === 64, `Stress cycle ${cycle} generated valid root`);
            loopBatch.destroy();
        }
        console.log('  PASS: 100 consecutive create/build/destroy stress cycles passed cleanly');
    }

    console.log('\n============================================================');
    console.log(`  TEST RESULTS: ${passedTests} passed, ${failedTests} failed, ${totalTests} total`);
    console.log('============================================================');

    if (failedTests > 0) {
        process.exit(1);
    }
}

runTests().catch(err => {
    console.error('Fatal test runner error:', err);
    process.exit(1);
});

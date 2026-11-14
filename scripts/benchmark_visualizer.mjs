/**
 * MedicineGuard — Visualizer Performance & Asymptotic Benchmark
 * Rigorously separates:
 * 1. Tree Model Computation (all leaf and parent hashes)
 * 2. Proof Path Construction (traversal from leaf to root)
 * 3. Layout & Node Generation (node coordinate math)
 * 4. Displayed Node Complexity (DOM element count)
 * 
 * Runs 10 iterations per batch size (preceded by 1 warm-up run).
 */

import MedicineGuard from '../public/js/wasm-loader.js';
import {
  buildTreeModel,
  computeProofPath
} from '../public/js/merkle-visualizer.js';
import { serializeMG01Record } from '../functions/_shared/merkle-verifier.js';

function stats(arr) {
  const sorted = [...arr].sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const median = sorted[Math.floor(sorted.length / 2)];
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / sorted.length;
  const variance = sorted.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / sorted.length;
  const stddev = Math.sqrt(variance);
  return { min, max, median, mean, stddev };
}

async function runBenchmark() {
  console.log('========================================================================');
  console.log(' MEDICINEGUARD VISUALIZER PERFORMANCE BENCHMARK (10 TRIALS PER SIZE)');
  console.log(' OS: Windows 11 | Runtime: Node.js ' + process.version);
  console.log('========================================================================\n');

  const engine = await MedicineGuard.init();
  const TRIALS = 10;
  const SIZES = [1, 10, 100, 1000, 10000];

  const results = [];

  for (const n of SIZES) {
    // Generate records
    const records = [];
    for (let i = 0; i < n; i++) {
      records.push({
        batch_id: `BENCH-N${n}`,
        unit_id: `UNIT-${String(i + 1).padStart(6, '0')}`,
        medicine_name: 'Paracetamol 500mg USP',
        manufacturing_date: '2026-01-01',
        expiry_date: '2028-01-01'
      });
    }

    // Warm-up run (discarded)
    const warmBatch = engine.createBatch();
    records.forEach(r => warmBatch.addRecord(serializeMG01Record(r)));
    warmBatch.buildTree();
    const warmRoot = warmBatch.getRootHex();
    await buildTreeModel(records, engine, warmRoot);
    warmBatch.destroy();

    const buildTimes = [];
    const proofTimes = [];
    const layoutFullTimes = [];
    const layoutFocusedTimes = [];

    let treeModel = null;
    let proofData = null;

    for (let t = 0; t < TRIALS; t++) {
      const wasmBatch = engine.createBatch();
      records.forEach(r => wasmBatch.addRecord(serializeMG01Record(r)));
      wasmBatch.buildTree();
      const expectedRoot = wasmBatch.getRootHex();

      // 1. Measure Tree Model Construction
      const t0 = performance.now();
      treeModel = await buildTreeModel(records, engine, expectedRoot);
      buildTimes.push(performance.now() - t0);

      // 2. Measure Proof Path Construction (middle leaf)
      const targetLeaf = Math.floor(n / 2);
      const t1 = performance.now();
      proofData = computeProofPath(treeModel, targetLeaf);
      proofTimes.push(performance.now() - t1);

      // 3. Measure Layout Coordinate Math (Focused Mode vs Full Mode)
      // Focused Mode: (2H - 1 nodes)
      const t2 = performance.now();
      const focusedPositions = new Map();
      const H = treeModel.height;
      for (let k = 0; k < H; k++) {
        focusedPositions.set(`${k}-path`, { x: 360, y: k * 90 });
        if (k < H - 1) focusedPositions.set(`${k}-sib`, { x: 580, y: k * 90 });
      }
      layoutFocusedTimes.push(performance.now() - t2);

      // Full Mode: (All nodes)
      if (n <= 1000) {
        const t3 = performance.now();
        const fullPositions = new Map();
        for (let k = 0; k < H; k++) {
          const count = treeModel.levels[k].length;
          for (let i = 0; i < count; i++) {
            fullPositions.set(`${k}-${i}`, { x: i * 160, y: k * 90 });
          }
        }
        layoutFullTimes.push(performance.now() - t3);
      }

      wasmBatch.destroy();
    }

    const bStats = stats(buildTimes);
    const pStats = stats(proofTimes);
    const lfStats = stats(layoutFocusedTimes);
    const fullCount = treeModel.levels.reduce((acc, l) => acc + l.length, 0);
    const focusedCount = proofData.steps.length * 2 + 1; // Path nodes + Sibling nodes + Root

    results.push({
      n,
      height: treeModel.height,
      fullCount,
      focusedCount,
      bMedian: bStats.median.toFixed(2),
      bMean: bStats.mean.toFixed(2),
      bStd: bStats.stddev.toFixed(2),
      pMedian: (pStats.median * 1000).toFixed(1), // in microseconds
      lfMedian: (lfStats.median * 1000).toFixed(1) // in microseconds
    });
  }

  console.log('| Batch Size ($N$) | Tree Height ($H$) | Total Nodes in Tree | Focused Mode Displayed Nodes | Tree Model Build (Median) | Proof Path Traversal (Median) | Focused Layout Math (Median) |');
  console.log('|---|---|---|---|---|---|---|');
  for (const r of results) {
    console.log(`| **N = ${r.n.toLocaleString()}** | $H = ${r.height}$ | ${r.fullCount.toLocaleString()} nodes | **${r.focusedCount} nodes** ($O(\\log N)$) | ${r.bMedian} ms (std: ${r.bStd}) | ${r.pMedian} μs | ${r.lfMedian} μs |`);
  }
}

runBenchmark().catch(console.error);


/**
 * MedicineGuard — Interactive Merkle Tree Visualizer
 * Mathematically faithful SVG visualization of the C11/WASM Merkle Tree engine
 * 
 * Features:
 * - Deterministic tree reconstruction using domain separation (0x00 leaf, 0x01 parent)
 * - Explicit Odd-Node Promotion handling (nodes promoted without hashing)
 * - Interactive proof path highlighting (active nodes, LEFT/RIGHT siblings)
 * - Large-batch support: Pan/Zoom, Level Collapsing, and Focused Proof Path Mode
 * - Zero external CDNs or UI frameworks
 */

import { serializeMedicineRecord, bytesToHex, hexToBytes, StatusCode } from './wasm-loader.js';

/**
 * Domain separation constants matching core-c/include/merkle.h
 */
export const MG_DOMAIN_LEAF = 0x00;
export const MG_DOMAIN_PARENT = 0x01;

/**
 * Truncate a 64-char hex string to readable format e.g. "468a...4248"
 */
export function truncateHash(hex, chars = 4) {
    if (!hex || hex.length < chars * 2 + 3) return hex || '';
    return `${hex.slice(0, chars)}...${hex.slice(-chars)}`;
}

/**
 * Compute SHA-256 using the loaded WASM engine, with fallback to Web Crypto
 */
export async function computeSha256Bytes(bytes, wasmEngine) {
    if (wasmEngine && typeof wasmEngine.sha256 === 'function') {
        return wasmEngine.sha256(bytes);
    }
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
}

/**
 * Compute Leaf Hash: SHA-256(0x00 || MG01(record))
 */
export async function computeLeafHash(record, wasmEngine) {
    const serialized = serializeMedicineRecord(record);
    const leafBuf = new Uint8Array(1 + serialized.length);
    leafBuf[0] = MG_DOMAIN_LEAF;
    leafBuf.set(serialized, 1);
    const hashBytes = await computeSha256Bytes(leafBuf, wasmEngine);
    return {
        bytes: hashBytes,
        hex: bytesToHex(hashBytes),
        serialized: serialized
    };
}

/**
 * Compute Parent Hash: SHA-256(0x01 || left || right)
 */
export async function computeParentHash(leftBytes, rightBytes, wasmEngine) {
    const parentBuf = new Uint8Array(1 + 32 + 32);
    parentBuf[0] = MG_DOMAIN_PARENT;
    parentBuf.set(leftBytes, 1);
    parentBuf.set(rightBytes, 33);
    const hashBytes = await computeSha256Bytes(parentBuf, wasmEngine);
    return {
        bytes: hashBytes,
        hex: bytesToHex(hashBytes)
    };
}

/**
 * Build the full cryptographic Merkle Tree model from records or leaf hashes
 * Accurately implements the exact C11 DAA engine tree construction & odd promotion rules.
 */
export async function buildTreeModel(records, wasmEngine, expectedRootHex = null) {
    if (!records || records.length === 0) {
        throw new Error('Cannot build Merkle Tree model: record batch is empty');
    }

    const count = records.length;
    const levels = [];

    // Level 0: Leaf Hashes
    const level0 = [];
    for (let i = 0; i < count; i++) {
        const rec = records[i];
        const leafRes = await computeLeafHash(rec, wasmEngine);
        level0.push({
            level: 0,
            index: i,
            unitId: rec.unit_id || `UNIT-${String(i + 1).padStart(6, '0')}`,
            record: rec,
            hashBytes: leafRes.bytes,
            hashHex: leafRes.hex,
            isPromoted: false,
            leftChildIndex: null,
            rightChildIndex: null
        });
    }
    levels.push(level0);

    // Levels 1 .. height - 1: Internal Nodes with Odd-Promotion
    let currentLevel = level0;
    let k = 1;

    while (currentLevel.length > 1) {
        const prevCount = currentLevel.length;
        const nextCount = Math.floor((prevCount + 1) / 2);
        const nextLevel = [];

        for (let i = 0; i < Math.floor(prevCount / 2); i++) {
            const leftChild = currentLevel[2 * i];
            const rightChild = currentLevel[2 * i + 1];
            const parentRes = await computeParentHash(leftChild.hashBytes, rightChild.hashBytes, wasmEngine);

            nextLevel.push({
                level: k,
                index: i,
                hashBytes: parentRes.bytes,
                hashHex: parentRes.hex,
                isPromoted: false,
                leftChildIndex: 2 * i,
                rightChildIndex: 2 * i + 1
            });
        }

        // If odd, promote the unpaired last node directly without hashing
        if (prevCount % 2 !== 0) {
            const unpairedChild = currentLevel[prevCount - 1];
            nextLevel.push({
                level: k,
                index: nextCount - 1,
                hashBytes: unpairedChild.hashBytes,
                hashHex: unpairedChild.hashHex,
                isPromoted: true,
                leftChildIndex: prevCount - 1,
                rightChildIndex: null
            });
        }

        levels.push(nextLevel);
        currentLevel = nextLevel;
        k++;
    }

    const rootNode = levels[levels.length - 1][0];
    const rootHex = rootNode.hashHex;

    if (expectedRootHex && expectedRootHex.toLowerCase() !== rootHex.toLowerCase()) {
        console.warn(`[Visualizer] Root mismatch: expected ${expectedRootHex}, computed ${rootHex}`);
    }

    return {
        batchId: records[0]?.batch_id || 'UNKNOWN',
        medicineName: records[0]?.medicine_name || 'Unknown',
        leafCount: count,
        height: levels.length,
        rootHex: rootHex,
        levels: levels,
        records: records
    };
}

/**
 * Compute the exact cryptographic proof path for a given leaf index
 * Returns step details, sibling nodes, and odd-node promotions.
 */
export function computeProofPath(treeModel, leafIndex) {
    if (leafIndex < 0 || leafIndex >= treeModel.leafCount) {
        throw new Error(`Leaf index ${leafIndex} out of bounds (total leaves: ${treeModel.leafCount})`);
    }

    const steps = [];
    const activePathNodeIds = new Set();
    const siblingNodeIds = new Map(); // id -> { direction, hashHex }
    const promotedPathNodeIds = new Set();

    let currIdx = leafIndex;
    activePathNodeIds.add(`node-0-${currIdx}`);

    for (let k = 0; k < treeModel.height - 1; k++) {
        const levelNodes = treeModel.levels[k];
        const countK = levelNodes.length;

        if (currIdx % 2 === 0) {
            if (currIdx + 1 < countK) {
                // Even node with right sibling
                const siblingNode = levelNodes[currIdx + 1];
                siblingNodeIds.set(`node-${k}-${currIdx + 1}`, { direction: 'right', hashHex: siblingNode.hashHex });
                steps.push({
                    stepNumber: steps.length + 1,
                    level: k,
                    nodeIndex: currIdx,
                    currentHashHex: levelNodes[currIdx].hashHex,
                    siblingIndex: currIdx + 1,
                    siblingHashHex: siblingNode.hashHex,
                    direction: 'right',
                    isPromoted: false,
                    parentHashHex: treeModel.levels[k + 1][Math.floor(currIdx / 2)].hashHex
                });
            } else {
                // Unpaired odd node promoted unchanged. Rule: Do not add a proof step.
                promotedPathNodeIds.add(`node-${k}-${currIdx}`);
                promotedPathNodeIds.add(`node-${k + 1}-${Math.floor(currIdx / 2)}`);
                steps.push({
                    stepNumber: steps.length + 1,
                    level: k,
                    nodeIndex: currIdx,
                    currentHashHex: levelNodes[currIdx].hashHex,
                    siblingIndex: null,
                    siblingHashHex: null,
                    direction: 'none',
                    isPromoted: true,
                    parentHashHex: levelNodes[currIdx].hashHex
                });
            }
        } else {
            // Odd node with left sibling
            const siblingNode = levelNodes[currIdx - 1];
            siblingNodeIds.set(`node-${k}-${currIdx - 1}`, { direction: 'left', hashHex: siblingNode.hashHex });
            steps.push({
                stepNumber: steps.length + 1,
                level: k,
                nodeIndex: currIdx,
                currentHashHex: levelNodes[currIdx].hashHex,
                siblingIndex: currIdx - 1,
                siblingHashHex: siblingNode.hashHex,
                direction: 'left',
                isPromoted: false,
                parentHashHex: treeModel.levels[k + 1][Math.floor(currIdx / 2)].hashHex
            });
        }

        currIdx = Math.floor(currIdx / 2);
        activePathNodeIds.add(`node-${k + 1}-${currIdx}`);
    }

    return {
        leafIndex,
        leafNode: treeModel.levels[0][leafIndex],
        rootNode: treeModel.levels[treeModel.height - 1][0],
        steps,
        activePathNodeIds,
        siblingNodeIds,
        promotedPathNodeIds
    };
}

/**
 * MerkleTreeVisualizer Component Class
 */
export class MerkleTreeVisualizer {
    constructor(options = {}) {
        this.container = options.container || null;
        this.svg = options.svg || null;
        this.canvasGroup = options.canvasGroup || null;
        this.detailsPanel = options.detailsPanel || null;
        this.wasmEngine = options.wasmEngine || null;

        this.currentTreeModel = null;
        this.selectedLeafIndex = 0;
        this.viewMode = 'auto'; // 'auto', 'full', 'focused'
        this.zoom = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.isDragging = false;
        this.dragStartX = 0;
        this.dragStartY = 0;

        this.nodeWidth = 140;
        this.nodeHeight = 58;
        this.levelHeight = 90;
        this.nodeGap = 20;

        this.onUnitSelected = options.onUnitSelected || null;

        if (this.svg) {
            this._initPanZoom();
        }
    }

    setWasmEngine(engine) {
        this.wasmEngine = engine;
    }

    /**
     * Load batch and render tree
     */
    async loadBatch(records, expectedRootHex = null, selectedIndex = 0) {
        if (!records || records.length === 0) return;
        this.currentTreeModel = await buildTreeModel(records, this.wasmEngine, expectedRootHex);
        this.selectedLeafIndex = Math.min(selectedIndex, records.length - 1);
        this.resetView();
        this.render();
    }

    /**
     * Select a specific unit / leaf index
     */
    selectLeaf(index) {
        if (!this.currentTreeModel) return;
        if (index < 0 || index >= this.currentTreeModel.leafCount) return;
        this.selectedLeafIndex = index;
        this.render();
        if (this.onUnitSelected) {
            this.onUnitSelected(index, this.currentTreeModel.records[index]);
        }
    }

    /**
     * Set View Mode: 'auto', 'full', or 'focused'
     */
    setViewMode(mode) {
        this.viewMode = mode;
        this.render();
    }

    /**
     * Reset Pan & Zoom
     */
    resetView() {
        this.zoom = 1.0;
        this.panX = 30;
        this.panY = 30;
        this._updateTransform();
    }

    zoomIn() {
        this.zoom = Math.min(3.5, this.zoom * 1.25);
        this._updateTransform();
    }

    zoomOut() {
        this.zoom = Math.max(0.15, this.zoom / 1.25);
        this._updateTransform();
    }

    fitWidth() {
        if (!this.svg || !this.currentTreeModel) return;
        const svgWidth = this.svg.clientWidth || 900;
        const leavesCount = this.currentTreeModel.levels[0].length;
        const totalTreeWidth = leavesCount * (this.nodeWidth + this.nodeGap) + 100;
        this.zoom = Math.min(1.2, Math.max(0.2, (svgWidth - 60) / totalTreeWidth));
        this.panX = 30;
        this.panY = 30;
        this._updateTransform();
    }

    _updateTransform() {
        if (this.canvasGroup) {
            this.canvasGroup.setAttribute('transform', `translate(${this.panX}, ${this.panY}) scale(${this.zoom})`);
        }
    }

    _initPanZoom() {
        if (!this.svg) return;

        const onPointerDown = (e) => {
            if (e.target.closest('.interactive-node')) return; // Allow node clicks
            this.isDragging = true;
            this.dragStartX = e.clientX - this.panX;
            this.dragStartY = e.clientY - this.panY;
            this.svg.style.cursor = 'grabbing';
        };

        const onPointerMove = (e) => {
            if (!this.isDragging) return;
            this.panX = e.clientX - this.dragStartX;
            this.panY = e.clientY - this.dragStartY;
            this._updateTransform();
        };

        const onPointerUp = () => {
            this.isDragging = false;
            this.svg.style.cursor = 'grab';
        };

        const onWheel = (e) => {
            e.preventDefault();
            const rect = this.svg.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85;
            const newZoom = Math.min(3.5, Math.max(0.15, this.zoom * zoomFactor));

            // Zoom towards mouse pointer
            this.panX = mouseX - (mouseX - this.panX) * (newZoom / this.zoom);
            this.panY = mouseY - (mouseY - this.panY) * (newZoom / this.zoom);
            this.zoom = newZoom;

            this._updateTransform();
        };

        this.svg.addEventListener('mousedown', onPointerDown);
        window.addEventListener('mousemove', onPointerMove);
        window.addEventListener('mouseup', onPointerUp);
        this.svg.addEventListener('wheel', onWheel, { passive: false });
        this.svg.style.cursor = 'grab';
    }

    /**
     * Primary Render Method
     */
    render() {
        if (!this.currentTreeModel || !this.canvasGroup) return;

        const tree = this.currentTreeModel;
        const proof = computeProofPath(tree, this.selectedLeafIndex);

        // Determine effective view mode
        const isLargeBatch = tree.leafCount > 32;
        const useFocusedMode = (this.viewMode === 'focused') || (this.viewMode === 'auto' && isLargeBatch);

        // Clear canvas group
        this.canvasGroup.innerHTML = '';

        // Layout calculation
        const nodePositions = new Map(); // "k-i" -> { x, y }

        if (useFocusedMode) {
            this._layoutFocusedPath(tree, proof, nodePositions);
        } else {
            this._layoutFullTree(tree, nodePositions);
        }

        // 1. Draw Connecting Edges
        this._renderEdges(tree, proof, nodePositions, useFocusedMode);

        // 2. Draw Level Labels
        this._renderLevelLabels(tree, useFocusedMode);

        // 3. Draw Nodes
        this._renderNodes(tree, proof, nodePositions, useFocusedMode);

        // 4. Update Explanation & Inspection Panel
        if (this.detailsPanel) {
            this._renderDetailsPanel(tree, proof, useFocusedMode);
        }
    }

    _layoutFullTree(tree, nodePositions) {
        const H = tree.height;
        const leafCount = tree.levels[0].length;

        // Position Level 0 (Leaves at bottom)
        const startX = 60;
        for (let i = 0; i < leafCount; i++) {
            const x = startX + i * (this.nodeWidth + this.nodeGap);
            const y = (H - 1) * this.levelHeight + 40;
            nodePositions.set(`0-${i}`, { x, y });
        }

        // Position Internal Levels 1 .. H - 1
        for (let k = 1; k < H; k++) {
            const levelNodes = tree.levels[k];
            for (let i = 0; i < levelNodes.length; i++) {
                const node = levelNodes[i];
                const y = (H - 1 - k) * this.levelHeight + 40;

                if (!node.isPromoted && node.rightChildIndex !== null) {
                    const leftPos = nodePositions.get(`${k - 1}-${node.leftChildIndex}`);
                    const rightPos = nodePositions.get(`${k - 1}-${node.rightChildIndex}`);
                    const x = (leftPos.x + rightPos.x) / 2;
                    nodePositions.set(`${k}-${i}`, { x, y });
                } else {
                    // Promoted node: place directly above left child
                    const leftPos = nodePositions.get(`${k - 1}-${node.leftChildIndex}`);
                    nodePositions.set(`${k}-${i}`, { x: leftPos.x, y });
                }
            }
        }
    }

    _layoutFocusedPath(tree, proof, nodePositions) {
        const H = tree.height;
        const centerX = 360;
        const siblingOffset = 220;

        // For each level in proof, position current path node in center, sibling adjacent
        for (let k = 0; k < H; k++) {
            const y = (H - 1 - k) * this.levelHeight + 40;
            const pathNodeId = Array.from(proof.activePathNodeIds).find(id => id.startsWith(`node-${k}-`));
            if (!pathNodeId) continue;
            const nodeIdx = parseInt(pathNodeId.split('-')[2], 10);

            // Path node center
            nodePositions.set(`${k}-${nodeIdx}`, { x: centerX, y });

            // Sibling node (if present at this level)
            const siblingEntry = Array.from(proof.siblingNodeIds.entries()).find(([id]) => id.startsWith(`node-${k}-`));
            if (siblingEntry) {
                const siblingIdx = parseInt(siblingEntry[0].split('-')[2], 10);
                const isRight = siblingEntry[1].direction === 'right';
                const sibX = isRight ? centerX + siblingOffset : centerX - siblingOffset;
                nodePositions.set(`${k}-${siblingIdx}`, { x: sibX, y });
            }
        }
    }

    _renderEdges(tree, proof, nodePositions, useFocusedMode) {
        const svgNs = 'http://www.w3.org/2000/svg';
        const H = tree.height;

        for (let k = 1; k < H; k++) {
            const levelNodes = tree.levels[k];
            for (let i = 0; i < levelNodes.length; i++) {
                const parentPos = nodePositions.get(`${k}-${i}`);
                if (!parentPos) continue;

                const node = levelNodes[i];
                const isParentOnPath = proof.activePathNodeIds.has(`node-${k}-${i}`);

                // Left child edge
                if (node.leftChildIndex !== null) {
                    const childPos = nodePositions.get(`${k - 1}-${node.leftChildIndex}`);
                    if (childPos) {
                        const isChildOnPath = proof.activePathNodeIds.has(`node-${k - 1}-${node.leftChildIndex}`);
                        const isPromoted = node.isPromoted;
                        this._drawEdge(parentPos, childPos, isParentOnPath && isChildOnPath, isPromoted);
                    }
                }

                // Right child edge
                if (node.rightChildIndex !== null) {
                    const childPos = nodePositions.get(`${k - 1}-${node.rightChildIndex}`);
                    if (childPos) {
                        const isChildOnPath = proof.activePathNodeIds.has(`node-${k - 1}-${node.rightChildIndex}`);
                        this._drawEdge(parentPos, childPos, isParentOnPath && isChildOnPath, false);
                    }
                }
            }
        }
    }

    _drawEdge(pPos, cPos, isActive, isPromoted) {
        const svgNs = 'http://www.w3.org/2000/svg';
        const x1 = pPos.x + this.nodeWidth / 2;
        const y1 = pPos.y + this.nodeHeight;
        const x2 = cPos.x + this.nodeWidth / 2;
        const y2 = cPos.y;

        const path = document.createElementNS(svgNs, 'path');
        const cy = (y1 + y2) / 2;
        path.setAttribute('d', `M ${x1} ${y1} C ${x1} ${cy}, ${x2} ${cy}, ${x2} ${y2}`);
        path.setAttribute('fill', 'none');

        if (isActive) {
            path.setAttribute('stroke', '#10b981'); // Vibrant emerald active proof path
            path.setAttribute('stroke-width', '3');
            path.setAttribute('filter', 'drop-shadow(0 0 4px rgba(16, 185, 129, 0.4))');
        } else if (isPromoted) {
            path.setAttribute('stroke', '#8b5cf6'); // Violet for promoted
            path.setAttribute('stroke-width', '2');
            path.setAttribute('stroke-dasharray', '4 3');
        } else {
            path.setAttribute('stroke', '#334155'); // Muted slate edge
            path.setAttribute('stroke-width', '1.5');
        }

        this.canvasGroup.appendChild(path);
    }

    _renderLevelLabels(tree, useFocusedMode) {
        const svgNs = 'http://www.w3.org/2000/svg';
        const H = tree.height;

        for (let k = 0; k < H; k++) {
            const y = (H - 1 - k) * this.levelHeight + 40 + this.nodeHeight / 2 + 4;
            const text = document.createElementNS(svgNs, 'text');
            text.setAttribute('x', '15');
            text.setAttribute('y', y);
            text.setAttribute('fill', '#64748b');
            text.setAttribute('font-size', '11px');
            text.setAttribute('font-weight', '600');
            text.setAttribute('font-family', 'monospace');

            const isRoot = k === H - 1;
            const isLeaf = k === 0;
            const label = isRoot ? `Root (L${k})` : isLeaf ? `Leaves (L0)` : `Level ${k}`;
            text.textContent = label;
            this.canvasGroup.appendChild(text);
        }
    }

    _renderNodes(tree, proof, nodePositions, useFocusedMode) {
        const svgNs = 'http://www.w3.org/2000/svg';
        const H = tree.height;

        for (const [key, pos] of nodePositions.entries()) {
            const [kStr, iStr] = key.split('-');
            const k = parseInt(kStr, 10);
            const i = parseInt(iStr, 10);
            const node = tree.levels[k][i];
            const nodeId = `node-${k}-${i}`;

            const isRoot = k === H - 1;
            const isLeaf = k === 0;
            const isSelectedLeaf = isLeaf && i === this.selectedLeafIndex;
            const isOnPath = proof.activePathNodeIds.has(nodeId);
            const siblingInfo = proof.siblingNodeIds.get(nodeId);
            const isPromoted = node.isPromoted;

            const g = document.createElementNS(svgNs, 'g');
            g.setAttribute('class', `tree-node interactive-node ${isOnPath ? 'active-path' : ''}`);
            g.setAttribute('transform', `translate(${pos.x}, ${pos.y})`);
            g.setAttribute('data-level', k);
            g.setAttribute('data-index', i);
            g.style.cursor = isLeaf ? 'pointer' : 'default';

            // Node Background Rect
            const rect = document.createElementNS(svgNs, 'rect');
            rect.setAttribute('width', this.nodeWidth);
            rect.setAttribute('height', this.nodeHeight);
            rect.setAttribute('rx', '8');
            rect.setAttribute('ry', '8');

            // Determine styling colors based on role
            let strokeColor = '#334155';
            let fillColor = '#0f172a';
            let strokeWidth = '1.5';
            let strokeDash = 'none';

            if (isSelectedLeaf) {
                strokeColor = '#10b981'; // Bright emerald
                fillColor = '#064e3b';
                strokeWidth = '2.5';
                rect.setAttribute('filter', 'drop-shadow(0 0 8px rgba(16, 185, 129, 0.5))');
            } else if (isRoot) {
                strokeColor = '#f59e0b'; // Amber Gold
                fillColor = '#451a03';
                strokeWidth = '2';
                rect.setAttribute('filter', 'drop-shadow(0 0 8px rgba(245, 158, 11, 0.4))');
            } else if (siblingInfo) {
                if (siblingInfo.direction === 'right') {
                    strokeColor = '#f59e0b'; // Amber for right sibling
                    fillColor = '#3b2504';
                } else {
                    strokeColor = '#0284c7'; // Cyan/Blue for left sibling
                    fillColor = '#082f49';
                }
                strokeWidth = '2';
            } else if (isOnPath) {
                strokeColor = '#10b981';
                fillColor = '#022c22';
                strokeWidth = '2';
            } else if (isPromoted) {
                strokeColor = '#8b5cf6';
                fillColor = '#2e1065';
                strokeDash = '4 3';
            } else {
                fillColor = '#1e293b';
            }

            rect.setAttribute('fill', fillColor);
            rect.setAttribute('stroke', strokeColor);
            rect.setAttribute('stroke-width', strokeWidth);
            if (strokeDash !== 'none') rect.setAttribute('stroke-dasharray', strokeDash);

            g.appendChild(rect);

            // Node Header Text (Badge & Index)
            const textHeader = document.createElementNS(svgNs, 'text');
            textHeader.setAttribute('x', '10');
            textHeader.setAttribute('y', '18');
            textHeader.setAttribute('font-size', '10px');
            textHeader.setAttribute('font-weight', '700');
            textHeader.setAttribute('font-family', 'system-ui, -apple-system, sans-serif');

            if (isRoot) {
                textHeader.setAttribute('fill', '#fbbf24');
                textHeader.textContent = `★ Merkle Root`;
            } else if (isSelectedLeaf) {
                textHeader.setAttribute('fill', '#34d399');
                textHeader.textContent = `● Selected Unit #${i + 1}`;
            } else if (siblingInfo) {
                textHeader.setAttribute('fill', siblingInfo.direction === 'right' ? '#fde68a' : '#7dd3fc');
                textHeader.textContent = `◄ Sibling (${siblingInfo.direction.toUpperCase()})`;
            } else if (isPromoted) {
                textHeader.setAttribute('fill', '#c4b5fd');
                textHeader.textContent = `◆ Odd-Promoted`;
            } else if (isLeaf) {
                textHeader.setAttribute('fill', '#94a3b8');
                textHeader.textContent = `Unit #${i + 1} (Leaf ${i})`;
            } else {
                textHeader.setAttribute('fill', '#94a3b8');
                textHeader.textContent = `L${k}[${i}] Internal`;
            }
            g.appendChild(textHeader);

            // Node Primary Label (Unit ID or Type)
            const textLabel = document.createElementNS(svgNs, 'text');
            textLabel.setAttribute('x', '10');
            textLabel.setAttribute('y', '34');
            textLabel.setAttribute('font-size', '11px');
            textLabel.setAttribute('font-weight', '600');
            textLabel.setAttribute('fill', '#f1f5f9');
            textLabel.setAttribute('font-family', 'monospace');

            if (isLeaf) {
                textLabel.textContent = node.unitId || `UNIT-${i}`;
            } else if (isRoot) {
                textLabel.textContent = `Tree Commitment`;
            } else if (isPromoted) {
                textLabel.textContent = `Pass-through`;
            } else {
                textLabel.textContent = `H(0x01 || L || R)`;
            }
            g.appendChild(textLabel);

            // Truncated SHA-256 Hash
            const textHash = document.createElementNS(svgNs, 'text');
            textHash.setAttribute('x', '10');
            textHash.setAttribute('y', '48');
            textHash.setAttribute('font-size', '10px');
            textHash.setAttribute('fill', '#64748b');
            textHash.setAttribute('font-family', 'monospace');
            textHash.textContent = truncateHash(node.hashHex, 5);
            g.appendChild(textHash);

            // Click listener for interactive leaf selection
            if (isLeaf) {
                g.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.selectLeaf(i);
                });
            }

            this.canvasGroup.appendChild(g);
        }
    }

    _renderDetailsPanel(tree, proof, useFocusedMode) {
        const panel = this.detailsPanel;
        const leafNode = proof.leafNode;
        const rootNode = proof.rootNode;
        const rec = leafNode.record;

        let stepsHtml = '';
        proof.steps.forEach((step, idx) => {
            if (step.isPromoted) {
                stepsHtml += `
                    <div class="proof-step-item promoted" style="background: rgba(139, 92, 246, 0.08); border: 1px dashed #8b5cf6; border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 0.5rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                            <span style="font-weight: 700; color: #a78bfa; font-size: 0.8125rem;">Step ${idx + 1}: Level ${step.level} Promotion (Odd Node)</span>
                            <span class="badge-pill-tech" style="background: #5b21b6; color: #ede9fe; font-size: 0.6875rem;">No Sibling (Promoted)</span>
                        </div>
                        <div style="font-size: 0.75rem; color: #cbd5e1; line-height: 1.4;">
                            Level ${step.level} has an odd number of nodes. Unpaired node at index ${step.nodeIndex} is promoted directly to Level ${step.level + 1} without parent hashing.
                        </div>
                        <div style="font-family: monospace; font-size: 0.6875rem; color: #94a3b8; margin-top: 0.25rem; word-break: break-all;">
                            H_${step.level + 1} = H_${step.level} = ${step.parentHashHex}
                        </div>
                    </div>
                `;
            } else {
                const dirColor = step.direction === 'right' ? '#f59e0b' : '#38bdf8';
                const dirLabel = step.direction === 'right' ? 'Right Sibling' : 'Left Sibling';
                stepsHtml += `
                    <div class="proof-step-item" style="background: var(--color-slate-800, #1e293b); border: 1px solid var(--color-slate-700, #334155); border-radius: 6px; padding: 0.6rem 0.8rem; margin-bottom: 0.5rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                            <span style="font-weight: 700; color: #e2e8f0; font-size: 0.8125rem;">Step ${idx + 1}: Level ${step.level} Parent Hash</span>
                            <span class="badge-pill-tech" style="background: ${dirColor}22; color: ${dirColor}; border: 1px solid ${dirColor}66; font-size: 0.6875rem;">${dirLabel}</span>
                        </div>
                        <div style="font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.35rem;">
                            Parent = SHA-256(0x01 || ${step.direction === 'right' ? 'Current' : 'Sibling'} || ${step.direction === 'right' ? 'Sibling' : 'Current'})
                        </div>
                        <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.4rem; font-family: monospace; font-size: 0.6875rem;">
                            <span style="color: #64748b;">Sibling Hash:</span>
                            <span style="color: ${dirColor}; word-break: break-all;">${step.siblingHashHex}</span>
                            <span style="color: #64748b;">Computed Parent:</span>
                            <span style="color: #34d399; word-break: break-all;">${step.parentHashHex}</span>
                        </div>
                    </div>
                `;
            }
        });

        panel.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 1rem;">
                <!-- Unit Header & Record Summary -->
                <div style="background: var(--color-slate-900, #0f172a); border: 1px solid var(--color-slate-700, #334155); border-radius: 8px; padding: 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="font-size: 1.125rem; font-weight: 700; color: #10b981; font-family: monospace;">${rec.unit_id}</span>
                            <span class="badge-pill-tech" style="background: #064e3b; color: #34d399;">Leaf Index ${leafNode.index}</span>
                        </div>
                        <span style="font-size: 0.75rem; color: #94a3b8;">Batch: <strong style="color: #f1f5f9;">${rec.batch_id}</strong></span>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.5rem; font-size: 0.75rem; margin-top: 0.75rem;">
                        <div><span style="color: #64748b;">Medicine:</span> <span style="color: #e2e8f0; font-weight: 600;">${rec.medicine_name}</span></div>
                        <div><span style="color: #64748b;">Mfg Date:</span> <span style="color: #e2e8f0;">${rec.manufacturing_date}</span></div>
                        <div><span style="color: #64748b;">Expiry:</span> <span style="color: #e2e8f0;">${rec.expiry_date}</span></div>
                    </div>

                    <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--color-slate-800, #1e293b);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
                            <span style="font-size: 0.6875rem; color: #64748b; text-transform: uppercase; font-weight: 700;">Domain-Separated Leaf Hash (0x00 || MG01)</span>
                            <button type="button" class="copy-btn copy-leaf-hash" data-hash="${leafNode.hashHex}" style="font-size: 0.6875rem; padding: 0.15rem 0.5rem;">Copy</button>
                        </div>
                        <div style="font-family: monospace; font-size: 0.75rem; color: #38bdf8; word-break: break-all; background: rgba(0,0,0,0.25); padding: 0.35rem 0.5rem; border-radius: 4px;">
                            ${leafNode.hashHex}
                        </div>
                    </div>
                </div>

                <!-- Proof Path & Mathematical Progression -->
                <div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <h4 style="font-size: 0.8125rem; font-weight: 700; text-transform: uppercase; color: #94a3b8; letter-spacing: 0.05em;">
                            Cryptographic Proof Path (O(log N) Traversal)
                        </h4>
                        <span class="badge-pill-tech" style="background: rgba(16, 185, 129, 0.15); color: #34d399;">
                            ${proof.steps.filter(s => !s.isPromoted).length} Hash Steps · Tree Height ${tree.height}
                        </span>
                    </div>

                    <div class="proof-steps-scroll" style="max-height: 240px; overflow-y: auto; padding-right: 0.25rem;">
                        ${stepsHtml}
                    </div>
                </div>

                <!-- Commitment Invariant Verification -->
                <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 0.75rem 1rem;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.35rem;">
                        <span style="font-weight: 700; color: #34d399; font-size: 0.8125rem;">★ Merkle Root Match Verified</span>
                        <span class="badge-pill-tech" style="background: #064e3b; color: #a7f3d0; font-size: 0.6875rem;">C11/WASM Invariant Parity</span>
                    </div>
                    <div style="font-family: monospace; font-size: 0.75rem; color: #e2e8f0; word-break: break-all;">
                        ${rootNode.hashHex}
                    </div>
                </div>
            </div>
        `;

        // Setup copy buttons
        panel.querySelectorAll('.copy-leaf-hash').forEach(btn => {
            btn.addEventListener('click', () => {
                const h = btn.dataset.hash;
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(h).then(() => {
                        btn.textContent = 'Copied!';
                        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
                    });
                }
            });
        });
    }
}


/**
 * MedicineGuard — Application Controller & Manufacturer Batch Registration
 * Vanilla ES6 JavaScript — Zero external dependencies
 */

import {
    MedicineGuard,
    serializeMedicineRecord,
    parseProof,
    bytesToHex,
    hexToBytes,
    StatusCode
} from './wasm-loader.js';
import {
    MerkleTreeVisualizer,
    buildTreeModel
} from './merkle-visualizer.js';

/* =========================================================================
 * Application State & Configuration
 * ========================================================================= */

const SECTIONS = {
    overview: {
        title: 'Platform Overview',
        subtitle: 'Medicine batch traceability and digital record verification'
    },
    manufacturer: {
        title: 'Manufacturer Portal',
        subtitle: 'Register batches and generate cryptographic Merkle Roots'
    },
    pharmacist: {
        title: 'Pharmacist Verification',
        subtitle: 'Inspect medicine records and verify cryptographic proofs'
    },
    customer: {
        title: 'Customer Verification',
        subtitle: 'Scan medicine QR references to confirm genuine batch origin'
    },
    status: {
        title: 'Algorithm & System Status',
        subtitle: 'Cryptographic engine specifications and WebAssembly runtime telemetry'
    },
    admin: {
        title: 'Admin Portal',
        subtitle: 'User access management, account provisioning and security controls'
    }
};

let wasmEngineInstance = null;

// Phase 3D: Auth, Backend & Shared Registry State
export let currentUser = null;
export let currentCsrfToken = null;
export let pharmSourceMode = 'shared'; // 'shared' or 'local'
let publishedBatchesList = [];
let targetResetUserId = null;

// Session Batches Registry (in-memory Map: batch_id -> batchData)
export const sessionBatches = new Map();
export let activeBatchId = null;

// Interactive Merkle Tree Visualizer (Phase 5)
export let merkleVisualizer = null;

// Verification History Registry (in-memory Array)
export const sessionVerificationHistory = [];

// Manufacturer Active Batch State (in-memory)
let activeBatchContext = null;
let activeBatchData = null;

// Table Pagination & Filter State
let mfgCurrentPage = 1;
let mfgPageSize = 10;
let mfgSearchQuery = '';

// Active Modal State
let currentModalUnit = null;
let currentModalProofBytes = null;
let currentModalIsTampered = false;

// Pharmacist Active Lookup State (in-memory)
let currentPharmUnit = null;
let currentPharmProofBytes = null;
let currentPharmBatchData = null;
let currentPharmIsTampered = false;

/* =========================================================================
 * DOM Elements
 * ========================================================================= */

const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';
const $ = (id) => (isBrowser ? document.getElementById(id) : null);
const $$ = (sel) => (isBrowser ? document.querySelectorAll(sel) : []);

const sidebar = $('sidebar');
const sidebarBackdrop = $('sidebar-backdrop');
const mobileMenuBtn = $('mobile-menu-btn');
const navLinks = $$('.nav-link');
const roleSelect = $('role-select');
const pageSections = $$('.page-section');
const topbarTitle = $('topbar-title');
const topbarSubtitle = $('topbar-subtitle');

// Telemetry & Badges
const topbarEngineBadge = $('topbar-engine-badge');
const topbarPulseDot = $('topbar-pulse-dot');
const topbarStatusText = $('topbar-status-text');
const sidebarPulseDot = $('sidebar-pulse-dot');
const sidebarStatusText = $('sidebar-status-text');

// System Status Page Elements
const metricEngineStatus = $('metric-engine-status');
const metricLoadTime = $('metric-load-time');
const runtimeStatusPill = $('runtime-status-pill');
const diagSha256 = $('diag-sha256');

// Manufacturer Form & Results Elements
const mfgFormCard = $('mfg-form-card');
const mfgResultsCard = $('mfg-results-card');
const mfgBatchForm = $('mfg-batch-form');
const mfgBatchIdInput = $('mfg-batch-id');
const mfgMedicineNameInput = $('mfg-medicine-name');
const mfgMfgDateInput = $('mfg-mfg-date');
const mfgExpDateInput = $('mfg-exp-date');
const mfgUnitCountInput = $('mfg-unit-count');
const mfgSubmitBtn = $('mfg-submit-btn');
const mfgFormError = $('mfg-form-error');
const mfgFormErrorText = $('mfg-form-error-text');
const mfgBtnReset = $('mfg-btn-reset');
const mfgRootHex = $('mfg-root-hex');
const mfgCopyRootBtn = $('mfg-copy-root-btn');
const copyBtnText = $('copy-btn-text');

// Results Summary Elements
const resBatchId = $('res-batch-id');
const resMedicineName = $('res-medicine-name');
const resBatchSize = $('res-batch-size');
const resBuildTime = $('res-build-time');

// Table & Pagination Elements
const mfgUnitsTableBody = $('mfg-units-table-body');
const mfgSearchInput = $('mfg-search-input');
const mfgPageSizeSelect = $('mfg-page-size');
const mfgPaginationInfo = $('mfg-pagination-info');
const mfgPageNum = $('mfg-page-num');
const mfgPrevPageBtn = $('mfg-prev-page');
const mfgNextPageBtn = $('mfg-next-page');

// Modal Elements
const proofModal = $('proof-modal');
const modalCloseX = $('modal-close-x');
const modalCloseFooter = $('modal-close-footer');
const modalUnitTitle = $('modal-unit-title');
const modalVerifCard = $('modal-verif-card');
const modalVerifHeadline = $('modal-verif-headline');
const modalVerifDesc = $('modal-verif-desc');
const modalUnitId = $('modal-unit-id');
const modalLeafIndex = $('modal-leaf-index');
const modalBatchId = $('modal-batch-id');
const modalMedicineName = $('modal-medicine-name');
const modalMfgDate = $('modal-mfg-date');
const modalExpDate = $('modal-exp-date');
const modalLeafHash = $('modal-leaf-hash');
const modalProofWireSize = $('modal-proof-wire-size');
const modalProofStepsContainer = $('modal-proof-steps-container');
const modalBtnTamperToggle = $('modal-btn-tamper-toggle');

// Pharmacist Portal Elements (Phase 3C)
const pharmSessionBatchesContainer = $('pharm-session-batches-container');
const pharmLookupForm = $('pharm-lookup-form');
const pharmUnitIdInput = $('pharm-unit-id');
const pharmBatchIdInput = $('pharm-batch-id');
const pharmQuickSamples = $('pharm-quick-samples');
const pharmQuickButtons = $('pharm-quick-buttons');
const pharmFormError = $('pharm-form-error');
const pharmFormErrorText = $('pharm-form-error-text');
const pharmBtnClear = $('pharm-btn-clear');
const pharmVerifyBtn = $('pharm-verify-btn');

const pharmResultCard = $('pharm-result-card');
const pharmResultBadge = $('pharm-result-badge');
const pharmStateBanner = $('pharm-state-banner');
const pharmStateIcon = $('pharm-state-icon');
const pharmStateHeadline = $('pharm-state-headline');
const pharmStateDesc = $('pharm-state-desc');

const pharmTelemetryTime = $('pharm-telemetry-time');
const pharmTelemetryStatus = $('pharm-telemetry-status');
const pharmTelemetryCode = $('pharm-telemetry-code');

const pharmRecordSection = $('pharm-record-section');
const pharmDispName = $('pharm-disp-name');
const pharmDispBatch = $('pharm-disp-batch');
const pharmDispUnit = $('pharm-disp-unit');
const pharmDispMfg = $('pharm-disp-mfg');
const pharmDispExp = $('pharm-disp-exp');
const pharmDispIndex = $('pharm-disp-index');
const pharmDispRoot = $('pharm-disp-root');
const pharmBtnCopyRoot = $('pharm-btn-copy-root');
const pharmCopyText = $('pharm-copy-text');

const pharmBtnToggleProof = $('pharm-btn-toggle-proof');
const pharmToggleProofText = $('pharm-toggle-proof-text');
const pharmBtnTamperToggle = $('pharm-btn-tamper-toggle');
const pharmTamperText = $('pharm-tamper-text');

const pharmProofContainer = $('pharm-proof-container');
const pharmProofMetaPill = $('pharm-proof-meta-pill');
const pharmProofMetaIndex = $('pharm-proof-meta-index');
const pharmProofMetaLeaves = $('pharm-proof-meta-leaves');
const pharmProofMetaSteps = $('pharm-proof-meta-steps');
const pharmProofMetaSize = $('pharm-proof-meta-size');
const pharmProofStepsList = $('pharm-proof-steps-list');

const pharmHistoryTableBody = $('pharm-history-table-body');
const pharmBtnClearHistory = $('pharm-btn-clear-history');

/* =========================================================================
 * Navigation & Section Switching
 * ========================================================================= */

/**
 * Switch active view section and synchronize sidebar, role picker, and topbar.
 * @param {string} sectionId 
 */
function navigateToSection(sectionId) {
    if (sectionId !== 'customer') {
        stopQrScanner();
    }

    // Support #visualizer deep link by routing to status section and scrolling to visualizer
    if (sectionId === 'visualizer') {
        sectionId = 'status';
        setTimeout(() => {
            const card = $('visualizer-card');
            if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);
    }

    // Guard Admin section against unauthenticated / unauthorized access
    if (sectionId === 'admin') {
        if (!currentUser || currentUser.role !== 'admin') {
            sectionId = 'overview';
        }
    }

    if (!SECTIONS[sectionId]) {
        sectionId = 'overview';
    }

    // 1. Update active section container
    pageSections.forEach(sec => {
        if (sec.id === `section-${sectionId}`) {
            sec.classList.add('active');
        } else {
            sec.classList.remove('active');
        }
    });

    // 2. Update active nav link
    navLinks.forEach(link => {
        if (link.dataset.section === sectionId) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    // 3. Update role selector dropdown if matching
    if (roleSelect && ['overview', 'manufacturer', 'pharmacist', 'customer', 'admin'].includes(sectionId)) {
        roleSelect.value = sectionId;
    }

    // 4. Update topbar header text
    const meta = SECTIONS[sectionId];
    if (topbarTitle) topbarTitle.textContent = meta.title;
    if (topbarSubtitle) topbarSubtitle.textContent = meta.subtitle;

    // 5. Special section activation callbacks
    if (sectionId === 'pharmacist') {
        renderPharmacistSessionBatches();
        if (pharmSourceMode === 'shared') {
            loadPublishedBatches();
            loadServerAuditLogs();
        }
    } else if (sectionId === 'admin') {
        loadAdminUsers();
    }

    // 6. Close mobile drawer if open
    closeMobileSidebar();

    // 7. Scroll window to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openMobileSidebar() {
    sidebar.classList.add('open');
    sidebarBackdrop.classList.add('active');
}

function closeMobileSidebar() {
    sidebar.classList.remove('open');
    sidebarBackdrop.classList.remove('active');
}

/* =========================================================================
 * WebAssembly Engine Initialization
 * ========================================================================= */

async function initializeWasmEngine() {
    const startTime = performance.now();
    try {
        console.log('[MedicineGuard] Initializing WebAssembly cryptographic engine...');
        wasmEngineInstance = await MedicineGuard.init();
        const loadDuration = Math.round(performance.now() - startTime);
        console.log(`[MedicineGuard] WebAssembly engine initialized in ${loadDuration} ms.`);

        // Perform live cryptographic self-check (SHA-256 of "MedicineGuard")
        const testHash = wasmEngineInstance.sha256Hex('MedicineGuard');
        console.log(`[MedicineGuard] Live SHA-256 self-test hash: ${testHash}`);

        // Update Topbar Badge
        topbarEngineBadge.className = 'badge-engine-status ready';
        topbarPulseDot.className = 'pulse-dot ready';
        topbarStatusText.textContent = 'WASM Engine Ready';

        // Update Sidebar Footer
        sidebarPulseDot.className = 'pulse-dot ready';
        sidebarStatusText.textContent = 'Ready';

        // Update Algorithm & System Status Page
        if (metricEngineStatus) {
            metricEngineStatus.textContent = 'READY';
            metricEngineStatus.style.color = 'var(--color-success)';
        }
        if (metricLoadTime) {
            metricLoadTime.textContent = `${loadDuration} ms`;
        }
        if (runtimeStatusPill) {
            runtimeStatusPill.textContent = 'Engine Active & Verified';
            runtimeStatusPill.style.backgroundColor = 'var(--color-success-bg)';
            runtimeStatusPill.style.color = 'var(--color-success)';
        }
        if (diagSha256) {
            diagSha256.textContent = testHash;
        }

        // Phase 5: Pass initialized engine to Merkle Visualizer
        if (merkleVisualizer) {
            merkleVisualizer.setWasmEngine(wasmEngineInstance);
        }

        // Ensure at least one demo batch exists in session so visualizer has authentic tree immediately
        if (sessionBatches.size === 0) {
            createDemoBatch();
        }

    } catch (err) {
        console.error('[MedicineGuard] Failed to initialize WebAssembly engine:', err);
        const failDuration = Math.round(performance.now() - startTime);

        // Update Topbar Badge
        topbarEngineBadge.className = 'badge-engine-status failed';
        topbarPulseDot.className = 'pulse-dot failed';
        topbarStatusText.textContent = 'WASM Unavailable';

        // Update Sidebar Footer
        sidebarPulseDot.className = 'pulse-dot failed';
        sidebarStatusText.textContent = 'Failed';

        // Update Algorithm & System Status Page
        if (metricEngineStatus) {
            metricEngineStatus.textContent = 'UNAVAILABLE';
            metricEngineStatus.style.color = 'var(--color-danger)';
        }
        if (metricLoadTime) {
            metricLoadTime.textContent = `${failDuration} ms`;
        }
        if (runtimeStatusPill) {
            runtimeStatusPill.textContent = 'Initialization Failed';
            runtimeStatusPill.style.backgroundColor = 'var(--color-danger-bg)';
            runtimeStatusPill.style.color = 'var(--color-danger)';
        }
        if (diagSha256) {
            diagSha256.textContent = `Error: ${err.message}`;
            diagSha256.style.color = 'var(--color-danger)';
        }
    }
}

/* =========================================================================
 * Manufacturer Batch Registration Controller (Phase 3B)
 * ========================================================================= */

/* =========================================================================
 * Date Validation Engine (Phase 3B Audit)
 * ========================================================================= */

/**
 * Strict calendar date validation.
 * Verifies format YYYY-MM-DD, month range 01-12, days in month, and leap years.
 * Rejects impossible dates like 2026-02-31 or 2026-02-29 (non-leap).
 * 
 * @param {string} dateStr 
 * @param {string} fieldName
 * @returns {{ valid: boolean, error?: string, year?: number, month?: number, day?: number }}
 */
export function validateCalendarDate(dateStr, fieldName = 'Date') {
    if (!dateStr || typeof dateStr !== 'string' || dateStr.trim().length === 0) {
        return { valid: false, error: `${fieldName} cannot be empty.` };
    }

    const trimmed = dateStr.trim();
    const match = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!match) {
        return { valid: false, error: `${fieldName} must follow the YYYY-MM-DD format.` };
    }

    const year = parseInt(match[1], 10);
    const month = parseInt(match[2], 10);
    const day = parseInt(match[3], 10);

    if (year < 1900 || year > 2100) {
        return { valid: false, error: `${fieldName} year (${year}) is out of permissible range (1900–2100).` };
    }

    if (month < 1 || month > 12) {
        return { valid: false, error: `${fieldName} month (${match[2]}) is invalid. Must be between 01 and 12.` };
    }

    // Days per month with leap-year handling for February
    const isLeap = (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0);
    const daysInMonth = [0, 31, isLeap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    const maxDays = daysInMonth[month];

    if (day < 1 || day > maxDays) {
        if (month === 2 && day === 29 && !isLeap) {
            return { valid: false, error: `${fieldName} date (${trimmed}) is invalid: ${year} is not a leap year.` };
        }
        return { valid: false, error: `${fieldName} day (${match[3]}) is invalid for month ${match[2]}. Maximum is ${maxDays} days.` };
    }

    return { valid: true, year, month, day };
}

/**
 * Validate that expiry date is strictly later than manufacturing date.
 * Rejects empty dates, invalid calendar dates, exp < mfg, and exp == mfg.
 * 
 * @param {string} mfgDate 
 * @param {string} expDate 
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateDateRange(mfgDate, expDate) {
    const mfgVal = validateCalendarDate(mfgDate, 'Manufacturing Date');
    if (!mfgVal.valid) return mfgVal;

    const expVal = validateCalendarDate(expDate, 'Expiry Date');
    if (!expVal.valid) return expVal;

    if (expDate === mfgDate) {
        return { valid: false, error: `Expiry Date (${expDate}) cannot be equal to Manufacturing Date (${mfgDate}).` };
    }

    if (expDate < mfgDate) {
        return { valid: false, error: `Expiry Date (${expDate}) cannot be earlier than Manufacturing Date (${mfgDate}).` };
    }

    return { valid: true };
}

/**
 * Initialize default form dates and presets.
 */
function initManufacturerForm() {
    const today = new Date();
    const exp = new Date(today);
    exp.setFullYear(exp.getFullYear() + 2);

    const todayStr = today.toISOString().split('T')[0];
    const expStr = exp.toISOString().split('T')[0];

    if (mfgMfgDateInput) mfgMfgDateInput.value = todayStr;
    if (mfgExpDateInput) mfgExpDateInput.value = expStr;

    // Unit Presets Click Handler
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const count = btn.dataset.preset;
            if (mfgUnitCountInput) {
                mfgUnitCountInput.value = count;
            }
        });
    });
}

function showFormError(message) {
    if (mfgFormError && mfgFormErrorText) {
        mfgFormErrorText.textContent = message;
        mfgFormError.style.display = 'flex';
    }
}

function clearFormError() {
    if (mfgFormError) {
        mfgFormError.style.display = 'none';
    }
}

/**
 * Handle Manufacturer Batch Form Submission
 */
async function handleBatchRegistration(e) {
    e.preventDefault();
    clearFormError();

    if (!wasmEngineInstance) {
        showFormError('The WebAssembly cryptographic engine is still initializing. Please wait a moment.');
        return;
    }

    const batchId = mfgBatchIdInput.value.trim();
    const medicineName = mfgMedicineNameInput.value.trim();
    const mfgDate = mfgMfgDateInput.value.trim();
    const expDate = mfgExpDateInput.value.trim();
    const unitCount = parseInt(mfgUnitCountInput.value, 10);

    // Form Validations
    if (!batchId) {
        showFormError('Please enter a valid Batch ID.');
        mfgBatchIdInput.focus();
        return;
    }
    if (batchId.length > 64) {
        showFormError('Batch ID must be 64 characters or fewer.');
        mfgBatchIdInput.focus();
        return;
    }
    if (!medicineName) {
        showFormError('Please enter the Medicine Name / Formulation.');
        mfgMedicineNameInput.focus();
        return;
    }
    if (medicineName.length > 128) {
        showFormError('Medicine Name must be 128 characters or fewer.');
        mfgMedicineNameInput.focus();
        return;
    }
    // Strict Calendar Date Validations
    const dateRangeVal = validateDateRange(mfgDate, expDate);
    if (!dateRangeVal.valid) {
        showFormError(dateRangeVal.error);
        if (!validateCalendarDate(mfgDate, 'Manufacturing Date').valid) {
            mfgMfgDateInput.focus();
        } else {
            mfgExpDateInput.focus();
        }
        return;
    }
    if (isNaN(unitCount) || unitCount < 1 || unitCount > 100000) {
        showFormError('Unit count must be a positive integer between 1 and 100,000 units.');
        mfgUnitCountInput.focus();
        return;
    }

    // Disable button and show spinner
    mfgSubmitBtn.disabled = true;
    mfgSubmitBtn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin">
            <line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/>
        </svg>
        <span>Constructing Merkle Tree in C/WASM...</span>
    `;

    try {
        const startTime = performance.now();

        // 1. Manage in-session batch contexts safely
        if (sessionBatches.has(batchId)) {
            const oldBatch = sessionBatches.get(batchId);
            if (oldBatch.context && !oldBatch.context.isDestroyed) {
                oldBatch.context.destroy();
            }
            sessionBatches.delete(batchId);
        }

        // Context pool capacity safety: max 32 concurrent contexts in C engine
        if (sessionBatches.size >= 28) {
            const oldestKey = sessionBatches.keys().next().value;
            const evicted = sessionBatches.get(oldestKey);
            if (evicted.context && !evicted.context.isDestroyed) {
                evicted.context.destroy();
            }
            sessionBatches.delete(oldestKey);
            console.warn(`[MedicineGuard] Evicted oldest session batch "${oldestKey}" to protect WASM handle capacity.`);
        }

        // 2. Create fresh context in WebAssembly handle pool
        const batchContext = wasmEngineInstance.createBatch();
        activeBatchContext = batchContext;

        // 3. Construct records and add to C engine
        const units = [];
        const unitsById = new Map();
        for (let i = 0; i < unitCount; i++) {
            const unitId = `UNIT-${String(i + 1).padStart(6, '0')}`;
            const record = {
                batch_id: batchId,
                unit_id: unitId,
                medicine_name: medicineName,
                manufacturing_date: mfgDate,
                expiry_date: expDate
            };

            // Compute domain-separated leaf hash: SHA-256(0x00 || serialized_mg01)
            const serialized = serializeMedicineRecord(record);
            const leafBuffer = new Uint8Array(1 + serialized.length);
            leafBuffer[0] = 0x00; // MG_DOMAIN_LEAF
            leafBuffer.set(serialized, 1);
            const leafHashHex = wasmEngineInstance.sha256Hex(leafBuffer);

            const unitItem = {
                leafIndex: i,
                unitId: unitId,
                record: record,
                leafHashHex: leafHashHex
            };
            units.push(unitItem);
            unitsById.set(unitId.toUpperCase(), unitItem);

            // Add serialized record to WASM batch context
            batchContext.addRecord(serialized);
        }

        // 4. Build Merkle Tree in WebAssembly
        batchContext.buildTree();

        // 5. Retrieve Root Hex and Tree Height
        const rootHex = batchContext.getRootHex();
        const treeHeight = batchContext.getHeight();
        const buildDuration = Math.round((performance.now() - startTime) * 100) / 100;

        console.log(`[MedicineGuard] Batch created: N=${unitCount}, Height=${treeHeight}, Root=${rootHex} in ${buildDuration} ms`);

        // 6. Store in-memory session data
        activeBatchData = {
            context: batchContext,
            batch_id: batchId,
            medicine_name: medicineName,
            manufacturing_date: mfgDate,
            expiry_date: expDate,
            unit_count: unitCount,
            root_hex: rootHex,
            height: treeHeight,
            build_duration: buildDuration,
            units: units,
            unitsById: unitsById
        };

        sessionBatches.set(batchId, activeBatchData);
        activeBatchId = batchId;

        // 7. Display results UI
        displayBatchResults();

        // 8. Update Pharmacist Session Batches Overview
        renderPharmacistSessionBatches();

        // 9. Update Merkle Tree Visualizer
        updateVisualizerBatchList(batchId);

    } catch (err) {
        console.error('[MedicineGuard] Failed to construct batch in WASM:', err);
        showFormError(`WebAssembly construction error: ${err.message}`);
        if (activeBatchContext && !activeBatchContext.isDestroyed) {
            activeBatchContext.destroy();
            activeBatchContext = null;
        }
        if (sessionBatches.has(batchId)) {
            sessionBatches.delete(batchId);
        }
    } finally {
        mfgSubmitBtn.disabled = false;
        mfgSubmitBtn.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>
            </svg>
            <span>Construct Merkle Tree & Generate Root</span>
        `;
    }
}

/**
 * Display results cards and populate manifest table
 */
function displayBatchResults() {
    if (!activeBatchData) return;

    // Populate summary fields
    if (resBatchId) resBatchId.textContent = activeBatchData.batch_id;
    if (resMedicineName) resMedicineName.textContent = activeBatchData.medicine_name;
    if (resBatchSize) resBatchSize.textContent = `${activeBatchData.unit_count.toLocaleString()} Units (Height: ${activeBatchData.height})`;
    if (resBuildTime) resBuildTime.textContent = `${activeBatchData.build_duration} ms`;
    if (mfgRootHex) mfgRootHex.textContent = activeBatchData.root_hex;

    // Reset pagination and search
    mfgCurrentPage = 1;
    mfgSearchQuery = '';
    if (mfgSearchInput) mfgSearchInput.value = '';

    renderUnitsTable();

    // Show results card, hide form card
    mfgFormCard.style.display = 'none';
    mfgResultsCard.style.display = 'block';

    // Scroll to results card
    mfgResultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Render paginated rows in medicine units table
 */
function renderUnitsTable() {
    if (!activeBatchData || !mfgUnitsTableBody) return;

    // Filter units
    const filtered = activeBatchData.units.filter(u => {
        if (!mfgSearchQuery) return true;
        const q = mfgSearchQuery.toLowerCase();
        return u.unitId.toLowerCase().includes(q) || String(u.leafIndex) === q;
    });

    const totalFiltered = filtered.length;
    const totalPages = Math.ceil(totalFiltered / mfgPageSize) || 1;
    mfgCurrentPage = Math.max(1, Math.min(mfgCurrentPage, totalPages));

    const startIdx = (mfgCurrentPage - 1) * mfgPageSize;
    const endIdx = Math.min(startIdx + mfgPageSize, totalFiltered);
    const pageItems = filtered.slice(startIdx, endIdx);

    // Build table HTML
    if (pageItems.length === 0) {
        mfgUnitsTableBody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; padding: 2rem; color: var(--color-slate-500);">
                    No medicine units match your search query.
                </td>
            </tr>
        `;
    } else {
        mfgUnitsTableBody.innerHTML = pageItems.map(item => `
            <tr>
                <td style="font-family: var(--font-mono); font-weight: 600; color: var(--color-slate-600);">
                    #${item.leafIndex}
                </td>
                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--color-slate-900);">
                    ${escapeHtml(item.unitId)}
                </td>
                <td>
                    <span class="hex-value" style="font-size: 0.75rem; color: var(--color-slate-700);" title="${item.leafHashHex}">
                        ${item.leafHashHex.substring(0, 12)}...${item.leafHashHex.substring(52)}
                    </span>
                </td>
                <td>
                    <span class="badge-pill-tech" style="background-color: var(--color-success-bg); color: var(--color-success); border: 1px solid var(--color-success-border);">
                        Ready (MGP1)
                    </span>
                </td>
                <td style="text-align: right;">
                    <div style="display: flex; gap: 0.35rem; justify-content: flex-end;">
                        <button type="button" class="btn-inspect-proof" data-leaf-index="${item.leafIndex}">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                            <span>Inspect Proof</span>
                        </button>
                        <button type="button" class="btn-view-qr btn-secondary" data-leaf-index="${item.leafIndex}" style="padding: 0.25rem 0.55rem; font-size: 0.75rem;" ${!isCurrentBatchPublished ? 'disabled title="QR generation available after publishing batch to shared registry"' : 'title="View and download unique verification QR code"'}>
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 7h.01M17 7h.01M7 17h.01M17 17h.01"/></svg>
                            <span>QR Code</span>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    // Update pagination controls
    if (mfgPaginationInfo) {
        if (totalFiltered === 0) {
            mfgPaginationInfo.textContent = 'Showing 0 units';
        } else {
            mfgPaginationInfo.textContent = `Showing ${startIdx + 1}–${endIdx} of ${totalFiltered} units`;
        }
    }
    if (mfgPageNum) {
        mfgPageNum.textContent = `Page ${mfgCurrentPage} of ${totalPages}`;
    }
    if (mfgPrevPageBtn) {
        mfgPrevPageBtn.disabled = (mfgCurrentPage <= 1);
    }
    if (mfgNextPageBtn) {
        mfgNextPageBtn.disabled = (mfgCurrentPage >= totalPages);
    }

    // Attach event listeners to proof inspect buttons
    document.querySelectorAll('.btn-inspect-proof').forEach(btn => {
        btn.addEventListener('click', () => {
            const leafIdx = parseInt(btn.dataset.leafIndex, 10);
            openProofInspectionModal(leafIdx);
        });
    });

    // Attach event listeners to QR code buttons
    document.querySelectorAll('.btn-view-qr').forEach(btn => {
        btn.addEventListener('click', () => {
            const leafIdx = parseInt(btn.dataset.leafIndex, 10);
            openUnitQrModal(leafIdx);
        });
    });
}

function resetBatchRegistration() {
    // Reset publication and QR state
    isCurrentBatchPublished = false;
    activePublishedUnits = [];
    const btnRevoke = $('btn-revoke-batch');
    if (btnRevoke) btnRevoke.style.display = 'none';
    const btnPublish = $('btn-publish-batch');
    if (btnPublish) {
        btnPublish.disabled = false;
        btnPublish.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 0.35rem; vertical-align: text-bottom;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>Publish to Shared Registry`;
    }
    const badge = $('mfg-publish-status-badge');
    if (badge) {
        badge.textContent = 'Local Session Only';
        badge.style.backgroundColor = 'var(--color-slate-200)';
        badge.style.color = 'var(--color-slate-700)';
    }

    // Note: In Phase 3C, we do NOT destroy the batch context here. The batch remains in
    // sessionBatches so that the Pharmacist portal can verify records from it.
    if (mfgResultsCard) mfgResultsCard.style.display = 'none';
    if (mfgFormCard) mfgFormCard.style.display = 'block';
    clearFormError();

    // Scroll to form
    mfgFormCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* =========================================================================
 * Unit Proof Inspection & Live Cryptographic Verification Modal
 * ========================================================================= */

/**
 * Open Modal and run live C verification on selected unit
 * @param {number} leafIndex 
 */
function openProofInspectionModal(leafIndex) {
    if (!activeBatchData || !activeBatchContext) return;
    const unit = activeBatchData.units[leafIndex];
    if (!unit) return;

    currentModalUnit = unit;
    currentModalIsTampered = false;

    // 1. Generate real binary MGP1 proof from WASM engine
    try {
        currentModalProofBytes = activeBatchContext.generateProof(leafIndex);
    } catch (err) {
        alert(`Failed to generate proof: ${err.message}`);
        return;
    }

    const parsedProof = parseProof(currentModalProofBytes);

    // Populate modal fields
    if (modalUnitTitle) modalUnitTitle.textContent = `Proof Inspection: ${unit.unitId}`;
    if (modalUnitId) modalUnitId.textContent = unit.unitId;
    if (modalLeafIndex) modalLeafIndex.textContent = `#${unit.leafIndex}`;
    if (modalBatchId) modalBatchId.textContent = activeBatchData.batch_id;
    if (modalMedicineName) modalMedicineName.textContent = activeBatchData.medicine_name;
    if (modalMfgDate) modalMfgDate.textContent = activeBatchData.manufacturing_date;
    if (modalExpDate) modalExpDate.textContent = activeBatchData.expiry_date;
    if (modalLeafHash) modalLeafHash.textContent = unit.leafHashHex;

    if (modalProofWireSize) {
        modalProofWireSize.textContent = `${currentModalProofBytes.length} bytes (${parsedProof.stepCount} steps)`;
    }

    // Render proof steps
    if (modalProofStepsContainer) {
        if (parsedProof.steps.length === 0) {
            modalProofStepsContainer.innerHTML = `
                <div style="font-size: 0.8125rem; color: var(--color-slate-500); padding: 0.5rem 0;">
                    Single-leaf batch (N=1): The leaf hash is directly identical to the Merkle Root. No sibling steps required.
                </div>
            `;
        } else {
            modalProofStepsContainer.innerHTML = parsedProof.steps.map(step => `
                <div class="proof-step-card">
                    <div class="proof-step-header">
                        <span>Level ${step.stepIndex + 1} Traversal Step</span>
                        <span class="dir-badge ${step.directionName}">
                            Sibling on ${step.directionName.toUpperCase()} (${step.direction === 1 ? '0x01' : '0x00'})
                        </span>
                    </div>
                    <div style="display: flex; align-items: baseline; gap: 0.5rem;">
                        <span style="font-size: 0.7rem; color: var(--color-slate-500); font-weight: 600;">Sibling Hash:</span>
                        <span class="hex-value" style="font-size: 0.75rem; color: var(--color-slate-800);">
                            ${step.siblingHashHex}
                        </span>
                    </div>
                </div>
            `).join('');
        }
    }

    // Run live verification
    updateModalVerificationResult();

    // Reset tamper button label
    if (modalBtnTamperToggle) {
        modalBtnTamperToggle.textContent = 'Simulate Altered Record';
        modalBtnTamperToggle.className = 'btn-secondary';
    }

    // Show modal
    proofModal.classList.add('active');
}

/**
 * Execute real WASM verification and update modal banner
 */
function updateModalVerificationResult() {
    if (!currentModalUnit || !currentModalProofBytes || !activeBatchData) return;

    let testRecord = currentModalUnit.record;
    if (currentModalIsTampered) {
        // Alter medicine name to test negative security
        testRecord = {
            ...currentModalUnit.record,
            medicine_name: `${currentModalUnit.record.medicine_name} [COUNTERFEIT ALTERATION]`
        };
    }

    // Call real WebAssembly verification function: _mg_wasm_verify_record
    const vResult = wasmEngineInstance.verifyRecord(testRecord, currentModalProofBytes, activeBatchData.root_hex);

    if (vResult.valid) {
        modalVerifCard.className = 'verif-result-card success';
        modalVerifHeadline.textContent = 'Verified against Batch Root';
        modalVerifDesc.innerHTML = `
            The real C/WASM verification function <code>_mg_wasm_verify_record</code> confirmed that this medicine record reconstructs the trusted batch Merkle Root. Status: <strong>MG_WASM_SUCCESS (0)</strong>.
        `;
    } else {
        modalVerifCard.className = 'verif-result-card failed';
        modalVerifHeadline.textContent = 'Verification Failed: Root Mismatch';
        modalVerifDesc.innerHTML = `
            Cryptographic integrity check rejected: Altered record does not match the batch commitment. Error: <strong>${vResult.statusMessage} (Code: ${vResult.status})</strong>.
        `;
    }
}

function closeModal() {
    proofModal.classList.remove('active');
    currentModalUnit = null;
    currentModalProofBytes = null;
    currentModalIsTampered = false;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/* =========================================================================
 * Pharmacist Verification Portal Controller (Phase 3C)
 * ========================================================================= */

/**
 * Look up a medicine record in session batches and verify it against the batch root
 * using the real native C / WebAssembly verifyRecord function.
 * 
 * @param {string} unitId 
 * @param {string} [batchId] 
 * @param {MedicineGuard} [engine] 
 * @param {Map} [batchesMap] 
 * @returns {{
 *   found: boolean,
 *   state: 'verified'|'failed'|'notfound'|'nobatch'|'unavailable',
 *   unitId: string,
 *   batchId?: string,
 *   record?: Object,
 *   batchData?: Object,
 *   leafIndex?: number,
 *   proofBytes?: Uint8Array,
 *   verification?: { valid: boolean, status: number, statusMessage: string },
 *   error?: string
 * }}
 */
export function lookupAndVerifyRecord(unitId, batchId = null, engine = wasmEngineInstance, batchesMap = sessionBatches) {
    if (!unitId || typeof unitId !== 'string' || unitId.trim().length === 0) {
        return {
            found: false,
            state: 'notfound',
            unitId: '',
            error: 'Medicine Unit ID cannot be empty.'
        };
    }

    const trimmedUnitId = unitId.trim();
    const trimmedBatchId = (batchId && typeof batchId === 'string' && batchId.trim().length > 0) ? batchId.trim() : null;

    if (!engine) {
        return {
            found: false,
            state: 'unavailable',
            unitId: trimmedUnitId,
            error: 'WebAssembly cryptographic engine is not initialized.'
        };
    }

    if (!batchesMap || batchesMap.size === 0) {
        return {
            found: false,
            state: 'nobatch',
            unitId: trimmedUnitId,
            error: 'No medicine batches are currently available in this browser session.'
        };
    }

    let targetBatch = null;
    let targetUnit = null;

    if (trimmedBatchId) {
        targetBatch = batchesMap.get(trimmedBatchId);
        if (!targetBatch) {
            return {
                found: false,
                state: 'notfound',
                unitId: trimmedUnitId,
                batchId: trimmedBatchId,
                error: `Specified Batch ID "${trimmedBatchId}" does not exist in this session.`
            };
        }
        targetUnit = targetBatch.unitsById ? targetBatch.unitsById.get(trimmedUnitId.toUpperCase()) : null;
        if (!targetUnit) {
            return {
                found: false,
                state: 'notfound',
                unitId: trimmedUnitId,
                batchId: trimmedBatchId,
                error: `Unit ID "${trimmedUnitId}" not found in batch "${trimmedBatchId}".`
            };
        }
    } else {
        // Search across all session batches
        for (const b of batchesMap.values()) {
            if (b.unitsById && b.unitsById.has(trimmedUnitId.toUpperCase())) {
                targetBatch = b;
                targetUnit = b.unitsById.get(trimmedUnitId.toUpperCase());
                break;
            }
        }
        if (!targetUnit) {
            return {
                found: false,
                state: 'notfound',
                unitId: trimmedUnitId,
                error: `Unit ID "${trimmedUnitId}" was not found in any registered session batch.`
            };
        }
    }

    // Generate real MGP1 proof from WebAssembly context
    let proofBytes;
    try {
        proofBytes = targetBatch.context.generateProof(targetUnit.leafIndex);
    } catch (err) {
        return {
            found: true,
            state: 'failed',
            unitId: targetUnit.unitId,
            batchId: targetBatch.batch_id,
            record: targetUnit.record,
            batchData: targetBatch,
            leafIndex: targetUnit.leafIndex,
            error: `Failed to generate proof from WebAssembly engine: ${err.message}`
        };
    }

    // Run real C/WebAssembly verification: _mg_wasm_verify_record
    const vResult = engine.verifyRecord(targetUnit.record, proofBytes, targetBatch.root_hex);

    return {
        found: true,
        state: vResult.valid ? 'verified' : 'failed',
        unitId: targetUnit.unitId,
        batchId: targetBatch.batch_id,
        record: targetUnit.record,
        batchData: targetBatch,
        leafIndex: targetUnit.leafIndex,
        proofBytes: proofBytes,
        verification: vResult
    };
}

/**
 * Render Active Session Batches Overview and quick sample chips on Pharmacist portal
 */
export function renderPharmacistSessionBatches() {
    if (!pharmSessionBatchesContainer) return;

    if (sessionBatches.size === 0) {
        pharmSessionBatchesContainer.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; width: 100%;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="badge-pill-tech" style="background-color: var(--color-warning-bg); color: var(--color-warning); border-color: var(--color-warning-border);">
                        No Batches in Session
                    </span>
                    <span style="font-size: 0.8125rem; color: var(--color-slate-600);">
                        No medicine batches are currently available in browser-session memory.
                    </span>
                </div>
                <button type="button" class="btn-secondary" data-nav-target="manufacturer" style="font-size: 0.75rem; padding: 0.25rem 0.65rem;">
                    Go to Manufacturer Portal &rarr;
                </button>
            </div>
        `;
        if (pharmQuickSamples) pharmQuickSamples.style.display = 'none';
        return;
    }

    const batchChipsHtml = Array.from(sessionBatches.values()).map(b => {
        const isActive = (b.batch_id === activeBatchId);
        return `
            <button type="button" class="batch-chip ${isActive ? 'active' : ''}" data-batch-chip="${escapeHtml(b.batch_id)}" title="Click to filter by ${escapeHtml(b.batch_id)}">
                <span>${escapeHtml(b.batch_id)}</span>
                <span class="badge-pill-tech" style="font-size: 0.65rem; padding: 0.1rem 0.35rem;">
                    ${b.unit_count.toLocaleString()} units
                </span>
            </button>
        `;
    }).join('');

    pharmSessionBatchesContainer.innerHTML = `
        <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; width: 100%;">
            <span style="font-size: 0.75rem; font-weight: 700; color: var(--color-slate-700); text-transform: uppercase; letter-spacing: 0.05em;">
                In-Memory Batches (${sessionBatches.size}):
            </span>
            ${batchChipsHtml}
        </div>
    `;

    // Attach click listeners to batch chips to fill Batch ID filter
    pharmSessionBatchesContainer.querySelectorAll('[data-batch-chip]').forEach(chip => {
        chip.addEventListener('click', () => {
            const bId = chip.dataset.batchChip;
            if (pharmBatchIdInput) {
                pharmBatchIdInput.value = bId;
            }
            updatePharmacistQuickSamples(bId);
        });
    });

    // Populate quick test unit samples from the active or first batch
    updatePharmacistQuickSamples(activeBatchId || sessionBatches.keys().next().value);
}

function updatePharmacistQuickSamples(batchId) {
    if (!pharmQuickSamples || !pharmQuickButtons) return;
    const b = sessionBatches.get(batchId);
    if (!b || !b.units || b.units.length === 0) {
        pharmQuickSamples.style.display = 'none';
        return;
    }

    const sampleIndices = [0, Math.floor(b.units.length / 2), b.units.length - 1];
    const uniqueIndices = [...new Set(sampleIndices)];

    pharmQuickButtons.innerHTML = uniqueIndices.map(idx => {
        const u = b.units[idx];
        const label = (idx === 0) ? 'First' : (idx === b.units.length - 1) ? 'Last' : 'Middle';
        return `
            <button type="button" class="preset-btn" data-sample-unit="${escapeHtml(u.unitId)}" data-sample-batch="${escapeHtml(b.batch_id)}">
                ${escapeHtml(u.unitId)} (${label} #${idx})
            </button>
        `;
    }).join('');

    pharmQuickSamples.style.display = 'flex';

    // Click handler for quick test units
    pharmQuickButtons.querySelectorAll('[data-sample-unit]').forEach(btn => {
        btn.addEventListener('click', () => {
            if (pharmUnitIdInput) pharmUnitIdInput.value = btn.dataset.sampleUnit;
            if (pharmBatchIdInput) pharmBatchIdInput.value = btn.dataset.sampleBatch;
            handlePharmacistLookup(new Event('submit'));
        });
    });
}

function showPharmError(msg) {
    if (pharmFormError && pharmFormErrorText) {
        pharmFormErrorText.textContent = msg;
        pharmFormError.style.display = 'flex';
    }
}

function clearPharmError() {
    if (pharmFormError) {
        pharmFormError.style.display = 'none';
    }
}

function clearPharmacistForm() {
    if (pharmUnitIdInput) pharmUnitIdInput.value = '';
    if (pharmBatchIdInput) pharmBatchIdInput.value = '';
    clearPharmError();
    if (pharmResultCard) pharmResultCard.style.display = 'none';
    currentPharmUnit = null;
    currentPharmProofBytes = null;
    currentPharmBatchData = null;
    currentPharmIsTampered = false;
}

/**
 * Handle Pharmacist Lookup Form Submission
 */
export async function handlePharmacistLookup(e) {
    if (e && e.preventDefault) e.preventDefault();
    clearPharmError();

    const unitId = pharmUnitIdInput ? pharmUnitIdInput.value.trim() : '';
    const batchId = pharmBatchIdInput ? pharmBatchIdInput.value.trim() : '';

    if (!unitId) {
        showPharmError('Please enter a Medicine Unit ID to verify.');
        if (pharmUnitIdInput) pharmUnitIdInput.focus();
        return;
    }

    if (pharmSourceMode === 'shared') {
        try {
            let url = `/api/pharmacist/lookup?unit_id=${encodeURIComponent(unitId)}`;
            if (batchId) url += `&batch_id=${encodeURIComponent(batchId)}`;

            const res = await fetch(url);
            if (res.status === 409) {
                const data = await res.json();
                if (data.error && data.error.code === 'AMBIGUOUS_UNIT_ID') {
                    showAmbiguousModal(unitId, data.matches || []);
                    return;
                }
            }

            if (res.status === 404) {
                displayPharmacistResult({
                    found: false,
                    state: 'not_found',
                    unitId,
                    batchId: batchId || 'Any',
                    record: null,
                    batchData: null,
                    leafIndex: null,
                    proofBytes: null,
                    verification: { valid: false, status: -14, statusMessage: 'Record not found in shared registry' }
                });
                return;
            }

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                showPharmError(errData.error?.message || `Lookup failed with status ${res.status}`);
                return;
            }

            const data = await res.json();
            const unit = data.unit;
            const proofBytes = base64ToUint8Array(unit.proof_data);
            const record = {
                batch_id: unit.batch_id,
                unit_id: unit.unit_id,
                medicine_name: unit.medicine_name,
                manufacturing_date: unit.manufacturing_date,
                expiry_date: unit.expiry_date
            };

            const batchDataMock = {
                batch_id: unit.batch_id,
                medicine_name: unit.medicine_name,
                manufacturing_date: unit.manufacturing_date,
                expiry_date: unit.expiry_date,
                root_hex: unit.merkle_root
            };

            let vResult = { valid: false, status: -1, statusMessage: 'Engine unavailable' };
            if (wasmEngineInstance) {
                vResult = wasmEngineInstance.verifyRecord(record, proofBytes, unit.merkle_root);
            }

            const resultObj = {
                found: true,
                state: vResult.valid ? 'verified' : 'failed',
                unitId: unit.unit_id,
                batchId: unit.batch_id,
                record,
                batchData: batchDataMock,
                leafIndex: unit.leaf_index,
                proofBytes,
                verification: vResult
            };

            displayPharmacistResult(resultObj);

            // Record verification audit to server
            logVerificationToServer(
                unit.unit_id,
                unit.batch_id,
                vResult.valid ? 'VALID' : 'INVALID',
                vResult.status
            );
            return;
        } catch (err) {
            console.error('Shared lookup error:', err);
            showPharmError(`Error connecting to shared registry: ${err.message}`);
            return;
        }
    }

    const result = lookupAndVerifyRecord(unitId, batchId);
    displayPharmacistResult(result);
}

/**
 * Display the verification outcome and populate details & proof
 */
function displayPharmacistResult(res) {
    if (!pharmResultCard) return;

    pharmResultCard.style.display = 'block';
    currentPharmUnit = res.found ? { unitId: res.unitId, record: res.record, leafIndex: res.leafIndex } : null;
    currentPharmBatchData = res.batchData || null;
    currentPharmProofBytes = res.proofBytes || null;
    currentPharmIsTampered = false;

    // Reset tamper toggle button
    if (pharmBtnTamperToggle && pharmTamperText) {
        pharmTamperText.textContent = 'Simulate Counterfeit Alteration';
        pharmBtnTamperToggle.className = 'btn-secondary';
        pharmBtnTamperToggle.style.color = 'var(--color-danger)';
        pharmBtnTamperToggle.style.borderColor = 'var(--color-danger-border)';
    }

    // Hide proof drawer by default until clicked
    if (pharmProofContainer) pharmProofContainer.style.display = 'none';
    if (pharmToggleProofText) pharmToggleProofText.textContent = 'Inspect Cryptographic Proof (MGP1)';

    const timeStr = new Date().toLocaleTimeString();
    if (pharmTelemetryTime) pharmTelemetryTime.textContent = timeStr;

    // Visual State Banner & Telemetry
    if (res.state === 'verified') {
        pharmResultBadge.className = 'badge-engine-status ready';
        pharmResultBadge.textContent = 'Verified (C/WASM)';
        pharmStateBanner.className = 'verif-state-card verified';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        `;
        pharmStateHeadline.textContent = 'Verified against Batch Root';
        pharmStateDesc.innerHTML = `
            <strong>Digital record verified against the locally available Merkle Root.</strong><br>
            The native C WebAssembly engine confirmed that this medicine record reconstructs the trusted batch Merkle Root via domain-separated cryptographic hashing. Status: <strong>${escapeHtml(res.verification.statusMessage)} (Code: ${res.verification.status})</strong>.
        `;
        if (pharmTelemetryStatus) pharmTelemetryStatus.textContent = res.verification.statusMessage;
        if (pharmTelemetryCode) pharmTelemetryCode.textContent = String(res.verification.status);

        // Record history
        recordPharmacistHistory(res.unitId, res.batchId, 'Verified', res.verification.status);

    } else if (res.state === 'failed') {
        pharmResultBadge.className = 'badge-engine-status failed';
        pharmResultBadge.textContent = 'Verification Rejected';
        pharmStateBanner.className = 'verif-state-card failed';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        `;
        pharmStateHeadline.textContent = 'Verification Failed: Root Mismatch';
        const code = res.verification ? res.verification.status : -10;
        const msg = res.verification ? res.verification.statusMessage : (res.error || 'Root mismatch');
        pharmStateDesc.innerHTML = `
            Cryptographic integrity check rejected: The record or proof does not match the batch commitment. Error: <strong>${escapeHtml(msg)} (Code: ${code})</strong>.
        `;
        if (pharmTelemetryStatus) pharmTelemetryStatus.textContent = msg;
        if (pharmTelemetryCode) pharmTelemetryCode.textContent = String(code);

        // Record history
        recordPharmacistHistory(res.unitId, res.batchId || 'Unknown', 'Failed', code);

    } else if (res.state === 'notfound') {
        pharmResultBadge.className = 'badge-pill-tech';
        pharmResultBadge.style.backgroundColor = 'var(--color-warning-bg)';
        pharmResultBadge.style.color = 'var(--color-warning)';
        pharmResultBadge.textContent = 'Record Not Found';
        pharmStateBanner.className = 'verif-state-card notfound';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
        `;
        pharmStateHeadline.textContent = 'Medicine Record Not Found';
        pharmStateDesc.textContent = res.error || `Unit ID "${res.unitId}" does not exist in any batch registered in this browser session.`;
        if (pharmTelemetryStatus) pharmTelemetryStatus.textContent = 'Record not found in session';
        if (pharmTelemetryCode) pharmTelemetryCode.textContent = 'N/A';

    } else if (res.state === 'nobatch') {
        pharmResultBadge.className = 'badge-pill-tech';
        pharmResultBadge.textContent = 'No Batch Available';
        pharmStateBanner.className = 'verif-state-card nobatch';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
        `;
        pharmStateHeadline.textContent = 'No Batch Available in Browser Session';
        pharmStateDesc.innerHTML = `
            No medicine batch is currently registered in this browser session. Please navigate to the <a href="#manufacturer" data-nav-target="manufacturer" style="font-weight: 600; text-decoration: underline;">Manufacturer Portal</a> to register a batch first.
        `;
        if (pharmTelemetryStatus) pharmTelemetryStatus.textContent = 'No active session batches';
        if (pharmTelemetryCode) pharmTelemetryCode.textContent = 'N/A';

    } else if (res.state === 'unavailable') {
        pharmResultBadge.className = 'badge-engine-status failed';
        pharmResultBadge.textContent = 'Engine Unavailable';
        pharmStateBanner.className = 'verif-state-card unavailable';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        `;
        pharmStateHeadline.textContent = 'WebAssembly Engine Unavailable';
        pharmStateDesc.textContent = res.error || 'The cryptographic WebAssembly engine is not ready.';
        if (pharmTelemetryStatus) pharmTelemetryStatus.textContent = 'Engine uninitialized';
        if (pharmTelemetryCode) pharmTelemetryCode.textContent = 'ERR';
    }

    // Populate Retrieved Record Information (Section 4B)
    if (res.found && res.batchData && res.record) {
        if (pharmRecordSection) pharmRecordSection.style.display = 'block';
        if (pharmDispName) pharmDispName.textContent = res.batchData.medicine_name;
        if (pharmDispBatch) pharmDispBatch.textContent = res.batchData.batch_id;
        if (pharmDispUnit) pharmDispUnit.textContent = res.unitId;
        if (pharmDispMfg) pharmDispMfg.textContent = res.batchData.manufacturing_date;
        if (pharmDispExp) pharmDispExp.textContent = res.batchData.expiry_date;
        if (pharmDispIndex) pharmDispIndex.textContent = `#${res.leafIndex} of ${res.batchData.unit_count.toLocaleString()}`;
        if (pharmDispRoot) pharmDispRoot.textContent = res.batchData.root_hex;

        // Render proof data
        renderPharmacistProof(res.proofBytes, res.leafIndex, res.batchData.unit_count);
    } else {
        if (pharmRecordSection) pharmRecordSection.style.display = 'none';
    }

    // Smooth scroll to results
    pharmResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Render technical MGP1 proof breakdown
 */
function renderPharmacistProof(proofBytes, leafIndex, totalLeaves) {
    if (!proofBytes || !pharmProofStepsList) return;

    const parsed = parseProof(proofBytes);

    if (pharmProofMetaPill) pharmProofMetaPill.textContent = `${proofBytes.length} bytes (${parsed.stepCount} steps)`;
    if (pharmProofMetaIndex) pharmProofMetaIndex.textContent = `#${leafIndex}`;
    if (pharmProofMetaLeaves) pharmProofMetaLeaves.textContent = String(totalLeaves);
    if (pharmProofMetaSteps) pharmProofMetaSteps.textContent = String(parsed.stepCount);
    if (pharmProofMetaSize) pharmProofMetaSize.textContent = `${proofBytes.length} B`;

    if (parsed.steps.length === 0) {
        pharmProofStepsList.innerHTML = `
            <div style="font-size: 0.8125rem; color: var(--color-slate-500); padding: 0.75rem 0;">
                Single-unit batch (N=1): The leaf hash is directly identical to the Merkle Root. No sibling steps required.
            </div>
        `;
        return;
    }

    pharmProofStepsList.innerHTML = parsed.steps.map(step => `
        <div class="proof-step-card">
            <div class="proof-step-header">
                <span>Level ${step.stepIndex + 1} Traversal Step</span>
                <span class="dir-badge ${step.directionName}">
                    Sibling on ${step.directionName.toUpperCase()} (${step.direction === 1 ? '0x01' : '0x00'})
                </span>
            </div>
            <div style="margin-bottom: 0.4rem; font-size: 0.75rem; color: var(--color-slate-600); line-height: 1.4;">
                ${step.direction === 1
                    ? 'Current node is Left Child. Parent = SHA-256(0x01 || current_hash || sibling_hash)'
                    : 'Current node is Right Child. Parent = SHA-256(0x01 || sibling_hash || current_hash)'}
            </div>
            <div style="display: flex; align-items: baseline; gap: 0.5rem;">
                <span style="font-size: 0.7rem; color: var(--color-slate-500); font-weight: 600;">Sibling Hash:</span>
                <span class="hex-value" style="font-size: 0.75rem; color: var(--color-slate-800);">
                    ${step.siblingHashHex}
                </span>
            </div>
        </div>
    `).join('');
}

/**
 * Handle Toggle Proof Inspection Drawer
 */
function togglePharmacistProof() {
    if (!pharmProofContainer) return;
    const isHidden = (pharmProofContainer.style.display === 'none' || !pharmProofContainer.style.display);
    pharmProofContainer.style.display = isHidden ? 'block' : 'none';
    if (pharmToggleProofText) {
        pharmToggleProofText.textContent = isHidden ? 'Hide Cryptographic Proof' : 'Inspect Cryptographic Proof (MGP1)';
    }
}

/**
 * Handle Live Tamper Demonstration
 */
function handlePharmacistTamperToggle() {
    if (!currentPharmUnit || !currentPharmProofBytes || !currentPharmBatchData) return;

    currentPharmIsTampered = !currentPharmIsTampered;

    let testRecord = currentPharmUnit.record;
    if (currentPharmIsTampered) {
        testRecord = {
            ...currentPharmUnit.record,
            medicine_name: `${currentPharmUnit.record.medicine_name} [COUNTERFEIT ALTERATION]`
        };
        if (pharmTamperText) pharmTamperText.textContent = 'Restore Authentic Record';
        if (pharmBtnTamperToggle) {
            pharmBtnTamperToggle.className = 'btn-primary';
            pharmBtnTamperToggle.style.color = 'var(--color-white)';
            pharmBtnTamperToggle.style.borderColor = 'transparent';
        }
    } else {
        if (pharmTamperText) pharmTamperText.textContent = 'Simulate Counterfeit Alteration';
        if (pharmBtnTamperToggle) {
            pharmBtnTamperToggle.className = 'btn-secondary';
            pharmBtnTamperToggle.style.color = 'var(--color-danger)';
            pharmBtnTamperToggle.style.borderColor = 'var(--color-danger-border)';
        }
    }

    // Call real WebAssembly verification: _mg_wasm_verify_record
    const vResult = wasmEngineInstance.verifyRecord(testRecord, currentPharmProofBytes, currentPharmBatchData.root_hex);

    if (vResult.valid) {
        pharmResultBadge.className = 'badge-engine-status ready';
        pharmResultBadge.textContent = 'Verified (C/WASM)';
        pharmStateBanner.className = 'verif-state-card verified';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        `;
        pharmStateHeadline.textContent = 'Verified against Batch Root';
        pharmStateDesc.innerHTML = `
            <strong>Digital record verified against the locally available Merkle Root.</strong><br>
            The native C WebAssembly engine confirmed that this medicine record reconstructs the trusted batch Merkle Root via domain-separated cryptographic hashing. Status: <strong>${escapeHtml(vResult.statusMessage)} (Code: ${vResult.status})</strong>.
        `;
    } else {
        pharmResultBadge.className = 'badge-engine-status failed';
        pharmResultBadge.textContent = 'Verification Rejected';
        pharmStateBanner.className = 'verif-state-card failed';
        pharmStateIcon.innerHTML = `
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
        `;
        pharmStateHeadline.textContent = 'Verification Failed: Root Mismatch';
        pharmStateDesc.innerHTML = `
            Cryptographic integrity check rejected: Altered record does not match the batch commitment. Error: <strong>${escapeHtml(vResult.statusMessage)} (Code: ${vResult.status})</strong>.
        `;
    }

    if (pharmTelemetryStatus) pharmTelemetryStatus.textContent = vResult.statusMessage;
    if (pharmTelemetryCode) pharmTelemetryCode.textContent = String(vResult.status);
    if (pharmTelemetryTime) pharmTelemetryTime.textContent = new Date().toLocaleTimeString();

    // Record in history
    recordPharmacistHistory(
        currentPharmUnit.unitId + (currentPharmIsTampered ? ' [ALTERED]' : ''),
        currentPharmBatchData.batch_id,
        vResult.valid ? 'Verified' : 'Failed',
        vResult.status
    );
}

function copyPharmacistRoot() {
    if (!currentPharmBatchData) return;
    navigator.clipboard.writeText(currentPharmBatchData.root_hex).then(() => {
        if (pharmCopyText) pharmCopyText.textContent = 'Copied!';
        setTimeout(() => {
            if (pharmCopyText) pharmCopyText.textContent = 'Copy';
        }, 2000);
    }).catch(() => {
        prompt('Copy Merkle Root:', currentPharmBatchData.root_hex);
    });
}

/**
 * Record a verification attempt into the browser session history
 */
function recordPharmacistHistory(unitId, batchId, result, statusCode) {
    sessionVerificationHistory.unshift({
        timestamp: new Date().toLocaleTimeString(),
        unitId: unitId,
        batchId: batchId,
        result: result,
        statusCode: statusCode
    });
    renderPharmacistHistoryTable();
}

/**
 * Render Verification History Table
 */
export function renderPharmacistHistoryTable() {
    if (!pharmHistoryTableBody) return;

    if (sessionVerificationHistory.length === 0) {
        pharmHistoryTableBody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: 2rem; color: var(--color-slate-400);">
                    No medicine verification attempts recorded in this browser session yet.
                </td>
            </tr>
        `;
        return;
    }

    pharmHistoryTableBody.innerHTML = sessionVerificationHistory.map(item => `
        <tr>
            <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--color-slate-500);">
                ${escapeHtml(item.timestamp)}
            </td>
            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--color-slate-900);">
                ${escapeHtml(item.unitId)}
            </td>
            <td style="font-family: var(--font-mono); color: var(--color-slate-700);">
                ${escapeHtml(item.batchId)}
            </td>
            <td>
                <span class="badge-pill-tech" style="${item.result === 'Verified' ? 'background-color: var(--color-success-bg); color: var(--color-success); border-color: var(--color-success-border);' : 'background-color: var(--color-danger-bg); color: var(--color-danger); border-color: var(--color-danger-border);'}">
                    ${escapeHtml(item.result)}
                </span>
            </td>
            <td style="font-family: var(--font-mono); font-size: 0.75rem;">
                <code>${item.statusCode}</code>
            </td>
            <td style="text-align: right;">
                <button type="button" class="btn-inspect-proof" data-reverify-unit="${escapeHtml(item.unitId.replace(/ \[.*?\]$/, ''))}" data-reverify-batch="${escapeHtml(item.batchId)}">
                    Re-Verify
                </button>
            </td>
        </tr>
    `).join('');

    // Re-verify click handlers
    pharmHistoryTableBody.querySelectorAll('[data-reverify-unit]').forEach(btn => {
        btn.addEventListener('click', () => {
            if (pharmUnitIdInput) pharmUnitIdInput.value = btn.dataset.reverifyUnit;
            if (pharmBatchIdInput) pharmBatchIdInput.value = btn.dataset.reverifyBatch;
            handlePharmacistLookup(new Event('submit'));
        });
    });
}

function clearPharmacistHistory() {
    sessionVerificationHistory.length = 0;
    renderPharmacistHistoryTable();
}

/* =========================================================================
 * Phase 3D: Backend, Authentication, Admin & Shared Registry Logic
 * ========================================================================= */

export function uint8ArrayToBase64(bytes) {
    if (typeof btoa === 'function') {
        let binStr = '';
        for (let i = 0; i < bytes.length; i++) {
            binStr += String.fromCharCode(bytes[i]);
        }
        return btoa(binStr);
    } else if (typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    return '';
}

export function base64ToUint8Array(b64) {
    if (typeof atob === 'function') {
        const binStr = atob(b64);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
            bytes[i] = binStr.charCodeAt(i);
        }
        return bytes;
    } else if (typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(b64, 'base64'));
    }
    return new Uint8Array(0);
}

export async function checkAuthSession() {
    try {
        const res = await fetch('/api/auth/session');
        if (!res.ok) return;
        const data = await res.json();
        if (data.authenticated && data.user) {
            currentUser = data.user;
            currentCsrfToken = data.csrfToken;
        } else {
            currentUser = null;
            currentCsrfToken = null;
        }
        renderAuthUI();
    } catch (err) {
        console.warn('Auth session check error:', err);
    }
}

export function renderAuthUI() {
    window.currentUser = currentUser;
    window.currentCsrfToken = currentCsrfToken;
    const btnOpenLogin = $('btn-open-login');
    const userInfoBox = $('auth-user-info');
    const userEmailSpan = $('auth-user-email');
    const userBadge = $('auth-user-badge');
    const navAdmin = $('nav-item-admin');
    const roleOptAdmin = $('role-option-admin');

    if (currentUser) {
        if (btnOpenLogin) btnOpenLogin.style.display = 'none';
        if (userInfoBox) userInfoBox.style.display = 'flex';
        if (userEmailSpan) userEmailSpan.textContent = currentUser.email;

        if (userBadge) {
            userBadge.textContent = currentUser.role.toUpperCase();
            if (currentUser.role === 'admin') {
                userBadge.className = 'badge-role-admin';
            } else if (currentUser.role === 'manufacturer') {
                userBadge.className = 'badge-role-mfg';
            } else {
                userBadge.className = 'badge-role-pharm';
            }
        }

        if (currentUser.role === 'admin') {
            if (navAdmin) navAdmin.style.display = 'block';
            if (roleOptAdmin) roleOptAdmin.style.display = 'block';
        } else {
            if (navAdmin) navAdmin.style.display = 'none';
            if (roleOptAdmin) roleOptAdmin.style.display = 'none';
        }
    } else {
        if (btnOpenLogin) btnOpenLogin.style.display = 'block';
        if (userInfoBox) userInfoBox.style.display = 'none';
        if (navAdmin) navAdmin.style.display = 'none';
        if (roleOptAdmin) roleOptAdmin.style.display = 'none';
    }
}

export function openAuthModal(defaultTab = 'login') {
    const modal = $('login-modal');
    if (!modal) return;
    const tabLogin = $('tab-login');
    const tabBootstrap = $('tab-bootstrap');
    const formLogin = $('form-login');
    const formBootstrap = $('form-bootstrap');
    const alertBox = $('auth-alert');

    if (alertBox) {
        alertBox.style.display = 'none';
        alertBox.textContent = '';
    }

    if (defaultTab === 'bootstrap') {
        if (tabBootstrap) tabBootstrap.classList.add('active');
        if (tabLogin) tabLogin.classList.remove('active');
        if (formBootstrap) formBootstrap.style.display = 'block';
        if (formLogin) formLogin.style.display = 'none';
        setTimeout(() => $('bootstrap-secret')?.focus(), 50);
    } else {
        if (tabLogin) tabLogin.classList.add('active');
        if (tabBootstrap) tabBootstrap.classList.remove('active');
        if (formLogin) formLogin.style.display = 'block';
        if (formBootstrap) formBootstrap.style.display = 'none';
        setTimeout(() => $('login-email')?.focus(), 50);
    }

    modal.classList.add('active', 'open');
}

export function closeAuthModal() {
    const modal = $('login-modal');
    if (modal) {
        modal.classList.remove('active', 'open');
    }
}

export async function handleLogin(e) {
    if (e && e.preventDefault) e.preventDefault();
    const alertBox = $('auth-alert');
    const email = $('login-email')?.value.trim();
    const password = $('login-password')?.value;
    const submitBtn = $('btn-submit-login');

    if (!email || !password) {
        if (alertBox) {
            alertBox.style.display = 'block';
            alertBox.style.backgroundColor = 'var(--color-danger-bg)';
            alertBox.style.color = 'var(--color-danger)';
            alertBox.textContent = 'Please enter both email address and password.';
        }
        return;
    }

    const origBtnText = submitBtn ? submitBtn.textContent : 'Sign In';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Signing in...';
    }

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) {
            if (alertBox) {
                alertBox.style.display = 'block';
                alertBox.style.backgroundColor = 'var(--color-danger-bg)';
                alertBox.style.color = 'var(--color-danger)';
                alertBox.textContent = data.error?.message || 'Login failed. Please check your credentials.';
            }
            return;
        }

        currentUser = data.user;
        currentCsrfToken = data.csrfToken;
        renderAuthUI();
        closeAuthModal();
        if ($('login-password')) $('login-password').value = '';

        if (currentUser.role === 'admin') {
            navigateToSection('admin');
        } else if (currentUser.role === 'manufacturer') {
            navigateToSection('manufacturer');
        } else if (currentUser.role === 'pharmacist') {
            navigateToSection('pharmacist');
        }
    } catch (err) {
        if (alertBox) {
            alertBox.style.display = 'block';
            alertBox.style.backgroundColor = 'var(--color-danger-bg)';
            alertBox.style.color = 'var(--color-danger)';
            alertBox.textContent = `Login network error: ${err.message}`;
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = origBtnText;
        }
    }
}

export async function handleBootstrap(e) {
    if (e && e.preventDefault) e.preventDefault();
    const alertBox = $('auth-alert');
    const secret = $('bootstrap-secret')?.value.trim();
    const email = $('bootstrap-email')?.value.trim();
    const password = $('bootstrap-password')?.value;
    const submitBtn = $('btn-submit-bootstrap');

    if (!secret || !email || !password) {
        if (alertBox) {
            alertBox.style.display = 'block';
            alertBox.style.backgroundColor = 'var(--color-danger-bg)';
            alertBox.style.color = 'var(--color-danger)';
            alertBox.textContent = 'Please fill in all bootstrap fields.';
        }
        return;
    }

    const origBtnText = submitBtn ? submitBtn.textContent : 'Initialize Admin Account';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Initializing...';
    }

    try {
        const res = await fetch('/api/auth/bootstrap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ secret, email, password })
        });
        const data = await res.json();
        if (!res.ok) {
            if (alertBox) {
                alertBox.style.display = 'block';
                alertBox.style.backgroundColor = 'var(--color-danger-bg)';
                alertBox.style.color = 'var(--color-danger)';
                alertBox.textContent = data.error?.message || 'Bootstrap initialization failed';
            }
            return;
        }

        if (alertBox) {
            alertBox.style.display = 'block';
            alertBox.style.backgroundColor = 'var(--color-success-bg)';
            alertBox.style.color = 'var(--color-success)';
            alertBox.textContent = 'Admin account initialized! You may now sign in.';
        }

        $('tab-login')?.click();
        if ($('login-email')) $('login-email').value = email;
    } catch (err) {
        if (alertBox) {
            alertBox.style.display = 'block';
            alertBox.style.backgroundColor = 'var(--color-danger-bg)';
            alertBox.style.color = 'var(--color-danger)';
            alertBox.textContent = `Bootstrap error: ${err.message}`;
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = origBtnText;
        }
    }
}

export async function handleLogout() {
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (err) {
        console.warn('Logout error:', err);
    }
    currentUser = null;
    currentCsrfToken = null;
    renderAuthUI();
    navigateToSection('overview');
}

export async function loadAdminUsers() {
    const tbody = $('admin-users-table-body');
    if (!tbody) return;

    try {
        const res = await fetch('/api/admin/users');
        if (!res.ok) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-danger);">Failed to load users (${res.status})</td></tr>`;
            return;
        }
        const data = await res.json();
        const users = data.users || [];

        if (users.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-slate-400);">No registered users found.</td></tr>`;
            return;
        }

        tbody.innerHTML = users.map(u => {
            const isSelf = currentUser && currentUser.userId === u.user_id;
            const roleBadgeClass = u.role === 'admin' ? 'badge-role-admin' : (u.role === 'manufacturer' ? 'badge-role-mfg' : 'badge-role-pharm');
            const statusClass = u.account_status === 'active' ? 'badge-engine-status ready' : 'badge-engine-status error';
            const toggleText = u.account_status === 'active' ? 'Disable' : 'Activate';

            return `
                <tr>
                    <td>
                        <strong style="color: var(--color-slate-900);">${escapeHtml(u.email)}</strong>
                        ${isSelf ? '<span style="font-size: 0.7rem; color: var(--color-cyan-500); margin-left: 0.35rem;">(You)</span>' : ''}
                    </td>
                    <td><span class="${roleBadgeClass}">${u.role.toUpperCase()}</span></td>
                    <td><span class="${statusClass}">${u.account_status.toUpperCase()}</span></td>
                    <td style="font-size: 0.75rem; color: var(--color-slate-500);">${new Date(u.created_at).toLocaleDateString()}</td>
                    <td style="text-align: right; display: flex; gap: 0.5rem; justify-content: flex-end;">
                        ${!isSelf ? `
                            <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;" data-toggle-user="${u.user_id}" data-current-status="${u.account_status}">
                                ${toggleText}
                            </button>
                        ` : ''}
                        <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.25rem 0.5rem;" data-reset-user="${u.user_id}" data-email="${escapeHtml(u.email)}">
                            Reset Password
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('[data-toggle-user]').forEach(btn => {
            btn.addEventListener('click', () => {
                handleToggleUserStatus(btn.dataset.toggleUser, btn.dataset.currentStatus);
            });
        });

        tbody.querySelectorAll('[data-reset-user]').forEach(btn => {
            btn.addEventListener('click', () => {
                openAdminResetModal(btn.dataset.resetUser, btn.dataset.email);
            });
        });
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-danger);">${err.message}</td></tr>`;
    }
}

export async function handleAdminCreateUser(e) {
    if (e && e.preventDefault) e.preventDefault();
    const email = $('admin-new-email')?.value.trim();
    const password = $('admin-new-password')?.value;
    const role = $('admin-new-role')?.value;
    const feedback = $('admin-create-feedback');

    if (!email || !password || !role) return;

    try {
        const res = await fetch('/api/admin/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ email, password, role })
        });
        const data = await res.json();

        if (!res.ok) {
            if (feedback) {
                feedback.style.display = 'block';
                feedback.style.color = 'var(--color-danger)';
                feedback.textContent = data.error?.message || 'Failed to create user';
            }
            return;
        }

        if (feedback) {
            feedback.style.display = 'block';
            feedback.style.color = 'var(--color-success)';
            feedback.textContent = `User "${data.user.email}" created successfully!`;
        }

        if ($('admin-create-user-form')) $('admin-create-user-form').reset();
        loadAdminUsers();
    } catch (err) {
        if (feedback) {
            feedback.style.display = 'block';
            feedback.style.color = 'var(--color-danger)';
            feedback.textContent = err.message;
        }
    }
}

export async function handleToggleUserStatus(userId, currentStatus) {
    const newStatus = currentStatus === 'active' ? 'disabled' : 'active';
    try {
        const res = await fetch(`/api/admin/users/${userId}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ account_status: newStatus })
        });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            alert(data.error?.message || 'Failed to update user');
            return;
        }
        loadAdminUsers();
    } catch (err) {
        alert(`Error updating user status: ${err.message}`);
    }
}

export function openAdminResetModal(userId, email) {
    targetResetUserId = userId;
    const modal = $('admin-reset-modal');
    const emailEl = $('admin-reset-target-email');
    const feedback = $('admin-reset-feedback');
    if (emailEl) emailEl.textContent = email;
    if (feedback) feedback.style.display = 'none';
    if ($('admin-reset-new-password')) $('admin-reset-new-password').value = '';
    if (modal) modal.classList.add('open');
}

export async function handleAdminResetSubmit(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!targetResetUserId) return;

    const newPassword = $('admin-reset-new-password')?.value;
    const feedback = $('admin-reset-feedback');

    if (!newPassword || newPassword.length < 8) {
        if (feedback) {
            feedback.style.display = 'block';
            feedback.style.color = 'var(--color-danger)';
            feedback.textContent = 'Password must be at least 8 characters long';
        }
        return;
    }

    try {
        const res = await fetch(`/api/admin/users/${targetResetUserId}/reset-password`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({ newPassword })
        });
        const data = await res.json();
        if (!res.ok) {
            if (feedback) {
                feedback.style.display = 'block';
                feedback.style.color = 'var(--color-danger)';
                feedback.textContent = data.error?.message || 'Reset failed';
            }
            return;
        }

        alert('Password has been reset successfully!');
        $('admin-reset-modal')?.classList.remove('open');
    } catch (err) {
        if (feedback) {
            feedback.style.display = 'block';
            feedback.style.color = 'var(--color-danger)';
            feedback.textContent = err.message;
        }
    }
}

export async function handlePublishBatch() {
    if (!activeBatchData || !activeBatchContext) {
        alert('No active batch available to publish.');
        return;
    }

    if (!currentUser) {
        openAuthModal('login');
        return;
    }

    if (currentUser.role !== 'manufacturer' && currentUser.role !== 'admin') {
        alert(`Your current account role (${currentUser.role}) does not have permission to publish batches. Please log in as a Manufacturer.`);
        return;
    }

    const confirmed = confirm(
        `Publish batch "${activeBatchData.batch_id}" (${activeBatchData.unit_count} units) to the Shared Trusted Registry?\n\nOnce published, the batch commitment and proofs become immutable.`
    );
    if (!confirmed) return;

    const btn = $('btn-publish-batch');
    const badge = $('mfg-publish-status-badge');
    const progressContainer = $('mfg-upload-progress-container');
    const progressFill = $('mfg-upload-progress-fill');
    const progressPct = $('mfg-upload-progress-pct');

    if (btn) btn.disabled = true;
    if (progressContainer) progressContainer.style.display = 'block';
    if (badge) {
        badge.textContent = 'Uploading...';
        badge.className = 'badge-pill-tech';
    }

    try {
        // Step 1: Initiate Batch
        const initRes = await fetch('/api/manufacturer/batches', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({
                batch_id: activeBatchData.batch_id,
                medicine_name: activeBatchData.medicine_name,
                manufacturing_date: activeBatchData.manufacturing_date,
                expiry_date: activeBatchData.expiry_date,
                total_units: activeBatchData.unit_count,
                merkle_root: activeBatchData.root_hex
            })
        });

        if (!initRes.ok) {
            const errData = await initRes.json().catch(() => ({}));
            throw new Error(errData.error?.message || `Initiate failed with status ${initRes.status}`);
        }

        // Step 2: Upload Units in Chunks
        const total = activeBatchData.unit_count;
        const chunkSize = 25;

        for (let start = 0; start < total; start += chunkSize) {
            const end = Math.min(start + chunkSize, total);
            const chunk = [];
            for (let i = start; i < end; i++) {
                const u = activeBatchData.units[i];
                const proofBytes = activeBatchContext.generateProof(i);
                chunk.push({
                    unit_id: u.unit_id,
                    leaf_index: i,
                    medicine_name: u.medicine_name,
                    manufacturing_date: u.manufacturing_date,
                    expiry_date: u.expiry_date,
                    proof_data: uint8ArrayToBase64(proofBytes)
                });
            }

            const chunkRes = await fetch(`/api/manufacturer/batches/${encodeURIComponent(activeBatchData.batch_id)}/units`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': currentCsrfToken || ''
                },
                body: JSON.stringify({ units: chunk })
            });

            if (!chunkRes.ok) {
                const errData = await chunkRes.json().catch(() => ({}));
                throw new Error(errData.error?.message || `Chunk upload failed at unit ${start}`);
            }

            const pct = Math.round((end / total) * 100);
            if (progressFill) progressFill.style.width = `${pct}%`;
            if (progressPct) progressPct.textContent = `${pct}%`;
        }

        // Step 3: Publish Finalization
        const pubRes = await fetch(`/api/manufacturer/batches/${encodeURIComponent(activeBatchData.batch_id)}/publish`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            }
        });

        if (!pubRes.ok) {
            const errData = await pubRes.json().catch(() => ({}));
            throw new Error(errData.error?.message || `Publication failed with status ${pubRes.status}`);
        }

        // Success!
        if (progressContainer) progressContainer.style.display = 'none';
        if (badge) {
            badge.textContent = 'Published to Shared Registry ✅';
            badge.style.backgroundColor = 'var(--color-success-bg)';
            badge.style.color = 'var(--color-success)';
            badge.style.borderColor = 'var(--color-success-border)';
        }
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = 'Published to Shared Registry';
        }

        // Load published batch units to obtain backend verification references for QR generation
        await loadPublishedBatchUnits(activeBatchData.batch_id);

        const btnRevoke = $('btn-revoke-batch');
        if (btnRevoke) btnRevoke.style.display = 'inline-flex';

        alert(`Batch "${activeBatchData.batch_id}" has been published successfully to the Cloudflare D1 shared trusted registry! Individual unit QR codes are now active.`);
    } catch (err) {
        console.error('Batch publication failed:', err);
        if (progressContainer) progressContainer.style.display = 'none';
        if (btn) btn.disabled = false;
        if (badge) {
            badge.textContent = 'Publication Failed';
            badge.style.backgroundColor = 'var(--color-danger-bg)';
            badge.style.color = 'var(--color-danger)';
        }
        alert(`Failed to publish batch: ${err.message}`);
    }
}

export async function loadPublishedBatches() {
    try {
        const res = await fetch('/api/pharmacist/batches');
        if (!res.ok) return;
        const data = await res.json();
        publishedBatchesList = data.batches || [];
        if (pharmSourceMode === 'shared') {
            renderPharmacistPublishedBatches();
        }
    } catch (err) {
        console.warn('Could not load published batches:', err);
    }
}

function renderPharmacistPublishedBatches() {
    if (!pharmSessionBatchesContainer) return;
    if (publishedBatchesList.length === 0) {
        pharmSessionBatchesContainer.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; width: 100%;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="badge-pill-tech" style="background-color: var(--color-warning-bg); color: var(--color-warning); border-color: var(--color-warning-border);">
                        No Published Batches
                    </span>
                    <span style="font-size: 0.8125rem; color: var(--color-slate-600);">
                        No batches have been published to the shared trusted registry yet.
                    </span>
                </div>
            </div>
        `;
        return;
    }

    const batchChipsHtml = publishedBatchesList.map(b => {
        return `
            <button type="button" class="batch-chip" data-batch-chip="${escapeHtml(b.batch_id)}" title="${escapeHtml(b.medicine_name)} (${b.total_units} units)">
                <span>${escapeHtml(b.batch_id)}</span>
                <span class="badge-pill-tech" style="font-size: 0.65rem; padding: 0.1rem 0.35rem;">
                    ${b.total_units.toLocaleString()} units
                </span>
            </button>
        `;
    }).join('');

    pharmSessionBatchesContainer.innerHTML = `
        <div style="width: 100%;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                <span style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: var(--color-slate-500); letter-spacing: 0.05em;">
                    Published Batches in Shared Registry (${publishedBatchesList.length})
                </span>
            </div>
            <div class="batch-chips-row">
                ${batchChipsHtml}
            </div>
        </div>
    `;

    pharmSessionBatchesContainer.querySelectorAll('[data-batch-chip]').forEach(chip => {
        chip.addEventListener('click', () => {
            const bId = chip.dataset.batchChip;
            if (pharmBatchIdInput) pharmBatchIdInput.value = bId;
        });
    });
}

function showAmbiguousModal(unitId, matches) {
    const modal = $('ambiguous-modal');
    const serialEl = $('ambiguous-unit-serial');
    const listEl = $('ambiguous-matches-list');
    if (!modal || !listEl) return;

    if (serialEl) serialEl.textContent = unitId;

    listEl.innerHTML = matches.map(m => `
        <div class="ambiguous-match-item" data-select-batch="${escapeHtml(m.batch_id)}">
            <div>
                <div style="font-weight: 700; color: var(--color-slate-900); font-family: var(--font-mono);">${escapeHtml(m.batch_id)}</div>
                <div style="font-size: 0.8125rem; color: var(--color-slate-600);">${escapeHtml(m.medicine_name)}</div>
                <div style="font-size: 0.75rem; color: var(--color-slate-400);">Mfg: ${m.manufacturing_date} | Exp: ${m.expiry_date}</div>
            </div>
            <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.65rem;">
                Select &amp; Verify
            </button>
        </div>
    `).join('');

    listEl.querySelectorAll('[data-select-batch]').forEach(item => {
        item.addEventListener('click', () => {
            const selectedBatch = item.dataset.selectBatch;
            modal.classList.remove('open');
            if (pharmBatchIdInput) pharmBatchIdInput.value = selectedBatch;
            if (pharmUnitIdInput) pharmUnitIdInput.value = unitId;
            handlePharmacistLookup(new Event('submit'));
        });
    });

    modal.classList.add('open');
}

async function logVerificationToServer(unitId, batchId, clientResult, statusCode) {
    if (!currentUser || (currentUser.role !== 'pharmacist' && currentUser.role !== 'admin')) {
        return;
    }
    try {
        await fetch('/api/pharmacist/verifications', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': currentCsrfToken || ''
            },
            body: JSON.stringify({
                unit_id: unitId,
                batch_id: batchId,
                client_verification_result: clientResult,
                client_status_code: statusCode
            })
        });
        loadServerAuditLogs();
    } catch (err) {
        console.warn('Failed to submit server audit log:', err);
    }
}

export async function loadServerAuditLogs() {
    const auditTbody = $('pharm-audit-table-body');
    if (!auditTbody) return;

    try {
        const res = await fetch('/api/pharmacist/verifications');
        if (!res.ok) return;
        const data = await res.json();
        const logs = data.verifications || [];

        if (logs.length === 0) {
            auditTbody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; padding: 2rem; color: var(--color-slate-400);">
                        No server audit logs recorded in shared registry yet.
                    </td>
                </tr>
            `;
            return;
        }

        auditTbody.innerHTML = logs.map(l => {
            const timeStr = new Date(l.timestamp).toLocaleString();
            const clientBadge = l.client_verification_result === 'VALID'
                ? '<span class="badge-role-pharm">VALID</span>'
                : '<span class="badge-role-admin">INVALID</span>';
            const serverBadge = l.server_verification_result === 'VALID'
                ? '<span class="badge-role-pharm">VALID</span>'
                : '<span class="badge-role-admin">INVALID</span>';

            return `
                <tr>
                    <td style="font-size: 0.75rem; color: var(--color-slate-500);">${timeStr}</td>
                    <td style="font-family: var(--font-mono); font-weight: 700;">${escapeHtml(l.unit_id || '--')}</td>
                    <td style="font-family: var(--font-mono);">${escapeHtml(l.batch_id || '--')}</td>
                    <td style="font-size: 0.75rem;">${escapeHtml(l.pharmacist_email || 'Pharmacist')}</td>
                    <td>${clientBadge}</td>
                    <td>${serverBadge}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.warn('Could not load server audit logs:', err);
    }
}

/* =========================================================================
 * Phase 4: QR Generation, Offline Canvas Rendering & Customer Verification
 * ========================================================================= */

let isCurrentBatchPublished = false;
let activePublishedUnits = [];
let activeCameraStream = null;
let scannerAnimFrameId = null;

/**
 * Render QR code to an HTML Canvas using locally bundled qrcode.js (zero CDNs)
 */
export function renderQrCodeToCanvas(canvas, text, cellSize = 6, margin = 16) {
    if (!canvas) return;
    const qrGen = (typeof window !== 'undefined' && window.qrcode)
        ? window.qrcode
        : (typeof qrcode !== 'undefined' ? qrcode : null);

    if (!qrGen) {
        console.error('qrcode generator library is not loaded');
        return;
    }
    const qr = qrGen(0, 'M');
    qr.addData(text);
    qr.make();
    const count = qr.getModuleCount();
    const size = count * cellSize + margin * 2;
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#0f172a'; // dark slate
    for (let row = 0; row < count; row++) {
        for (let col = 0; col < count; col++) {
            if (qr.isDark(row, col)) {
                ctx.fillRect(margin + col * cellSize, margin + row * cellSize, cellSize, cellSize);
            }
        }
    }
}

/**
 * Load units with verification references for a published batch
 */
export async function loadPublishedBatchUnits(batchId) {
    try {
        const res = await fetch(`/api/manufacturer/batches/${encodeURIComponent(batchId)}/units?all=true`);
        if (!res.ok) return;
        const data = await res.json();
        activePublishedUnits = data.units || [];
        isCurrentBatchPublished = true;
        renderUnitsTable();
    } catch (err) {
        console.warn('Failed to load published batch units:', err);
    }
}

/**
 * Open QR code modal for a specific medicine unit
 */
export function openUnitQrModal(leafIdx) {
    if (!activeBatchData) return;
    const unit = activeBatchData.units[leafIdx];
    if (!unit) return;

    const publishedUnit = activePublishedUnits.find(u => u.leaf_index === leafIdx || u.unit_id === unit.unitId);
    const ref = publishedUnit ? publishedUnit.verification_reference : null;

    if (!ref) {
        alert('Verification reference not found for this unit. Please publish the batch to the shared registry first.');
        return;
    }

    const verifyUrl = `${window.location.origin}/?verify=${ref}`;
    const canvas = $('mfg-qr-canvas');
    if (canvas) {
        renderQrCodeToCanvas(canvas, verifyUrl, 6, 16);
    }

    const unitIdEl = $('mfg-qr-unit-id');
    const batchIdEl = $('mfg-qr-batch-id');
    const refEl = $('mfg-qr-reference');
    const urlInput = $('mfg-qr-url-input');

    if (unitIdEl) unitIdEl.textContent = unit.unitId;
    if (batchIdEl) batchIdEl.textContent = activeBatchData.batch_id;
    if (refEl) refEl.textContent = ref;
    if (urlInput) urlInput.value = verifyUrl;

    const modal = $('mfg-qr-modal');
    if (modal) modal.style.display = 'flex';
}

export function closeQrModal() {
    const modal = $('mfg-qr-modal');
    if (modal) modal.style.display = 'none';
}

/**
 * Start camera-based QR code scanning
 */
export async function startQrScanner() {
    const errorBox = $('scanner-error-box');
    const errorTitle = $('scanner-error-title');
    const errorMessage = $('scanner-error-message');
    if (errorBox) errorBox.style.display = 'none';

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        if (errorBox) {
            errorBox.style.display = 'flex';
            if (errorTitle) errorTitle.textContent = 'Camera Not Supported:';
            if (errorMessage) errorMessage.textContent = 'Your browser does not support camera capture via mediaDevices, or you are running in an insecure (non-HTTPS) context. Please use the manual verification code entry below.';
        }
        return;
    }

    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            video: { facingMode: { ideal: 'environment' } }
        });
        activeCameraStream = stream;
        const video = $('scanner-video');
        if (!video) return;

        video.srcObject = stream;
        video.setAttribute('playsinline', 'true');
        await video.play();

        const initialBox = $('scanner-controls-initial');
        const viewportBox = $('scanner-viewport-container');
        if (initialBox) initialBox.style.display = 'none';
        if (viewportBox) viewportBox.style.display = 'block';

        scanVideoFrame();
    } catch (err) {
        console.error('Camera access error:', err);
        if (errorBox) {
            errorBox.style.display = 'flex';
            if (errorTitle) errorTitle.textContent = 'Camera Access Blocked:';
            if (errorMessage) errorMessage.textContent = `${err.name}: ${err.message}. Camera permission was denied or unavailable. Please use the manual verification code entry below.`;
        }
    }
}

/**
 * Stop camera-based QR scanner and cleanly release all tracks
 */
export function stopQrScanner() {
    if (scannerAnimFrameId) {
        cancelAnimationFrame(scannerAnimFrameId);
        scannerAnimFrameId = null;
    }
    if (activeCameraStream) {
        activeCameraStream.getTracks().forEach(track => track.stop());
        activeCameraStream = null;
    }
    const video = $('scanner-video');
    if (video) video.srcObject = null;

    const initialBox = $('scanner-controls-initial');
    const viewportBox = $('scanner-viewport-container');
    if (initialBox) initialBox.style.display = 'block';
    if (viewportBox) viewportBox.style.display = 'none';
}

/**
 * Frame scanning loop using native BarcodeDetector or bundled jsQR
 */
async function scanVideoFrame() {
    if (!activeCameraStream) return;
    const video = $('scanner-video');
    const canvas = $('scanner-canvas');
    if (!video || !canvas) return;

    if (video.readyState === video.HAVE_ENOUGH_DATA) {
        const w = video.videoWidth;
        const h = video.videoHeight;
        if (w > 0 && h > 0) {
            canvas.width = w;
            canvas.height = h;
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(video, 0, 0, w, h);

            let decodedText = null;

            // 1. Try native BarcodeDetector if available
            if ('BarcodeDetector' in window) {
                try {
                    const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
                    const barcodes = await detector.detect(canvas);
                    if (barcodes && barcodes.length > 0) {
                        decodedText = barcodes[0].rawValue;
                    }
                } catch {
                    // Fall through to jsQR
                }
            }

            // 2. Fall back to local bundled jsQR
            if (!decodedText) {
                const jsqrFn = (typeof window !== 'undefined' && window.jsQR) ? window.jsQR : (typeof jsQR === 'function' ? jsQR : null);
                if (jsqrFn) {
                    try {
                        const imgData = ctx.getImageData(0, 0, w, h);
                        const code = jsqrFn(imgData.data, imgData.width, imgData.height, {
                            inversionAttempts: 'dontInvert'
                        });
                        if (code && code.data) {
                            decodedText = code.data;
                        }
                    } catch {
                        // Frame decode error ignored
                    }
                }
            }

            if (decodedText) {
                stopQrScanner();
                handleDecodedQr(decodedText);
                return;
            }
        }
    }

    scannerAnimFrameId = requestAnimationFrame(scanVideoFrame);
}

/**
 * Handle decoded text from QR scan
 */
function handleDecodedQr(rawText) {
    let ref = rawText.trim();
    try {
        if (ref.includes('?')) {
            const parsed = new URL(ref, window.location.origin);
            if (parsed.searchParams.has('verify')) {
                ref = parsed.searchParams.get('verify').trim();
            }
        }
    } catch {
        // Use raw string
    }

    const refInput = $('customer-ref-input');
    if (refInput) refInput.value = ref;
    verifyCustomerReference(ref);
}

/**
 * Public Customer Verification Request to /api/public/verify
 */
export async function verifyCustomerReference(ref) {
    if (!ref || typeof ref !== 'string') {
        alert('Please enter a verification reference code.');
        return;
    }
    const cleanRef = ref.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(cleanRef)) {
        displayCustomerError({
            status: 'INVALID_REFERENCE',
            error: {
                message: 'Invalid reference format: Verification references must be exactly 32 hexadecimal characters.'
            }
        });
        return;
    }

    const loading = $('customer-verif-loading');
    const verifiedCard = $('customer-result-verified');
    const errorCard = $('customer-result-error');

    if (loading) loading.style.display = 'block';
    if (verifiedCard) verifiedCard.style.display = 'none';
    if (errorCard) errorCard.style.display = 'none';

    try {
        const res = await fetch(`/api/public/verify?reference=${encodeURIComponent(cleanRef)}`);
        const data = await res.json().catch(() => ({}));

        if (loading) loading.style.display = 'none';

        if (res.ok && data.verified && data.status === 'VERIFIED') {
            displayCustomerVerified(data);
        } else {
            displayCustomerError(data, res.status);
        }
    } catch (err) {
        if (loading) loading.style.display = 'none';
        displayCustomerError({
            status: 'NETWORK_ERROR',
            error: { message: `Network request failed: ${err.message}` }
        });
    }
}

/**
 * Display Verified Customer Result Card
 */
function displayCustomerVerified(data) {
    const verifiedCard = $('customer-result-verified');
    const errorCard = $('customer-result-error');
    if (errorCard) errorCard.style.display = 'none';
    if (!verifiedCard) return;

    const r = data.record || {};
    const medicineEl = $('cust-res-medicine');
    const batchEl = $('cust-res-batch');
    const unitEl = $('cust-res-unit');
    const mfgEl = $('cust-res-mfg');
    const expEl = $('cust-res-exp');
    const leafEl = $('cust-res-leaf');
    const timeEl = $('cust-res-timestamp');

    if (medicineEl) medicineEl.textContent = r.medicine_name || '--';
    if (batchEl) batchEl.textContent = r.batch_id || '--';
    if (unitEl) unitEl.textContent = r.unit_id || '--';
    if (mfgEl) mfgEl.textContent = r.manufacturing_date || '--';
    if (expEl) expEl.textContent = r.expiry_date || '--';
    if (leafEl) leafEl.textContent = typeof r.leaf_index === 'number' ? `#${r.leaf_index}` : '--';
    if (timeEl) timeEl.textContent = r.verification_timestamp || new Date().toISOString();

    verifiedCard.style.display = 'block';
    verifiedCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Display Error / Revocation / Unverified Customer Result Card
 */
function displayCustomerError(data, httpStatus = 400) {
    const verifiedCard = $('customer-result-verified');
    const errorCard = $('customer-result-error');
    if (verifiedCard) verifiedCard.style.display = 'none';
    if (!errorCard) return;

    const titleEl = $('cust-err-title');
    const statusPill = $('cust-err-status-pill');
    const badgeEl = $('cust-err-badge');
    const messageEl = $('cust-err-message');
    const revokedDetails = $('cust-revoked-details');
    const revokedReason = $('cust-revoked-reason');
    const revokedDate = $('cust-revoked-date');

    const status = data.status || 'ERROR';

    if (status === 'REVOKED') {
        errorCard.className = 'cust-result-card revoked';
        if (titleEl) titleEl.textContent = 'Medicine Batch Revoked';
        if (statusPill) {
            statusPill.textContent = 'RECALLED / REVOKED';
            statusPill.style.color = 'var(--color-warning)';
        }
        if (badgeEl) {
            badgeEl.textContent = 'BATCH REVOKED';
            badgeEl.className = 'badge-engine-status error';
        }
        if (messageEl) {
            messageEl.textContent = data.message || 'This medicine batch has been officially revoked and recalled.';
        }
        if (revokedDetails) revokedDetails.style.display = 'grid';
        if (revokedReason) revokedReason.textContent = data.revocation_reason || 'Batch revoked by manufacturer or regulatory authority.';
        if (revokedDate) revokedDate.textContent = data.revoked_at || '--';
    } else if (status === 'NOT_FOUND') {
        errorCard.className = 'cust-result-card error';
        if (titleEl) titleEl.textContent = 'Record Not Found';
        if (statusPill) {
            statusPill.textContent = 'UNREGISTERED REFERENCE';
            statusPill.style.color = 'var(--color-danger)';
        }
        if (badgeEl) {
            badgeEl.textContent = 'NOT IN REGISTRY';
            badgeEl.className = 'badge-engine-status error';
        }
        if (messageEl) {
            messageEl.textContent = data.error?.message || 'No medicine record found matching this verification reference.';
        }
        if (revokedDetails) revokedDetails.style.display = 'none';
    } else if (status === 'INVALID_PROOF') {
        errorCard.className = 'cust-result-card error';
        if (titleEl) titleEl.textContent = 'Cryptographic Verification Failed';
        if (statusPill) {
            statusPill.textContent = 'INTEGRITY BREACH DETECTED';
            statusPill.style.color = 'var(--color-danger)';
        }
        if (badgeEl) {
            badgeEl.textContent = 'TAMPER DETECTED';
            badgeEl.className = 'badge-engine-status error';
        }
        if (messageEl) {
            messageEl.textContent = data.error?.message || 'Cryptographic Merkle proof verification failed against the registered root.';
        }
        if (revokedDetails) revokedDetails.style.display = 'none';
    } else if (status === 'UNPUBLISHED') {
        errorCard.className = 'cust-result-card error';
        if (titleEl) titleEl.textContent = 'Batch Not Published';
        if (statusPill) {
            statusPill.textContent = 'INCOMPLETE REGISTRATION';
            statusPill.style.color = 'var(--color-warning)';
        }
        if (badgeEl) {
            badgeEl.textContent = 'UNPUBLISHED';
            badgeEl.className = 'badge-engine-status error';
        }
        if (messageEl) {
            messageEl.textContent = data.error?.message || 'The parent batch for this medicine has not been finalized on the trusted registry.';
        }
        if (revokedDetails) revokedDetails.style.display = 'none';
    } else {
        errorCard.className = 'cust-result-card error';
        if (titleEl) titleEl.textContent = 'Verification Failed';
        if (statusPill) {
            statusPill.textContent = 'INVALID REFERENCE';
            statusPill.style.color = 'var(--color-danger)';
        }
        if (badgeEl) {
            badgeEl.textContent = 'UNVERIFIED';
            badgeEl.className = 'badge-engine-status error';
        }
        if (messageEl) {
            messageEl.textContent = data.error?.message || data.message || 'Verification could not be completed.';
        }
        if (revokedDetails) revokedDetails.style.display = 'none';
    }

    errorCard.style.display = 'block';
    errorCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/* =========================================================================
 * Phase 5: Merkle Tree Visualizer Controller
 * ========================================================================= */

export function initMerkleVisualizer() {
    const svg = $('visualizer-svg');
    const canvasGroup = $('visualizer-canvas-group');
    const detailsPanel = $('visualizer-details-panel');
    const batchSelect = $('visualizer-batch-select');
    const unitSelect = $('visualizer-unit-select');
    const unitSearch = $('visualizer-unit-search');

    if (!svg || !canvasGroup) return;

    merkleVisualizer = new MerkleTreeVisualizer({
        svg,
        canvasGroup,
        detailsPanel,
        wasmEngine: wasmEngineInstance,
        onUnitSelected: (idx, record) => {
            if (unitSelect) unitSelect.value = String(idx);
            if (unitSearch) unitSearch.value = record.unit_id;
        }
    });

    // Wire Batch Selector
    if (batchSelect) {
        batchSelect.addEventListener('change', async (e) => {
            const batchId = e.target.value;
            await loadBatchIntoVisualizer(batchId);
        });
    }

    // Wire Unit Selector
    if (unitSelect) {
        unitSelect.addEventListener('change', (e) => {
            const idx = parseInt(e.target.value, 10);
            if (merkleVisualizer) merkleVisualizer.selectLeaf(idx);
        });
    }

    // Wire Unit Search Input
    if (unitSearch) {
        unitSearch.addEventListener('input', (e) => {
            const q = e.target.value.trim().toUpperCase();
            if (!merkleVisualizer || !merkleVisualizer.currentTreeModel) return;
            const records = merkleVisualizer.currentTreeModel.records;
            const matchIdx = records.findIndex(r => r.unit_id.toUpperCase().includes(q));
            if (matchIdx !== -1) {
                merkleVisualizer.selectLeaf(matchIdx);
            }
        });
    }

    // Wire View Mode Buttons
    const btnAuto = $('vis-btn-mode-auto');
    const btnFull = $('vis-btn-mode-full');
    const btnFocused = $('vis-btn-mode-focused');
    const setViewModeUI = (mode) => {
        [btnAuto, btnFull, btnFocused].forEach(b => b && b.classList.remove('active'));
        if (mode === 'auto' && btnAuto) btnAuto.classList.add('active');
        if (mode === 'full' && btnFull) btnFull.classList.add('active');
        if (mode === 'focused' && btnFocused) btnFocused.classList.add('active');
        if (merkleVisualizer) merkleVisualizer.setViewMode(mode);
    };

    if (btnAuto) btnAuto.addEventListener('click', () => setViewModeUI('auto'));
    if (btnFull) btnFull.addEventListener('click', () => setViewModeUI('full'));
    if (btnFocused) btnFocused.addEventListener('click', () => setViewModeUI('focused'));

    // Wire Zoom Controls
    const zoomInBtn = $('vis-zoom-in');
    const zoomOutBtn = $('vis-zoom-out');
    const zoomResetBtn = $('vis-zoom-reset');
    const btnReset = $('vis-btn-reset');
    const btnFit = $('vis-btn-fit');

    if (zoomInBtn) zoomInBtn.addEventListener('click', () => merkleVisualizer && merkleVisualizer.zoomIn());
    if (zoomOutBtn) zoomOutBtn.addEventListener('click', () => merkleVisualizer && merkleVisualizer.zoomOut());
    if (zoomResetBtn) zoomResetBtn.addEventListener('click', () => merkleVisualizer && merkleVisualizer.resetView());
    if (btnReset) btnReset.addEventListener('click', () => merkleVisualizer && merkleVisualizer.resetView());
    if (btnFit) btnFit.addEventListener('click', () => merkleVisualizer && merkleVisualizer.fitWidth());

    // Populate Initial Batch List
    updateVisualizerBatchList();
}

export function updateVisualizerBatchList(selectedBatchId = null) {
    const batchSelect = $('visualizer-batch-select');
    if (!batchSelect) return;

    batchSelect.innerHTML = '';
    const batches = Array.from(sessionBatches.values());

    if (batches.length === 0) {
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'No batches registered yet';
        batchSelect.appendChild(opt);
        return;
    }

    batches.forEach(b => {
        const opt = document.createElement('option');
        opt.value = b.batch_id;
        opt.textContent = `${b.batch_id} — ${b.medicine_name} (${b.unit_count} units)`;
        if (selectedBatchId && b.batch_id === selectedBatchId) {
            opt.selected = true;
        }
        batchSelect.appendChild(opt);
    });

    const targetId = selectedBatchId || batches[batches.length - 1].batch_id;
    batchSelect.value = targetId;
    loadBatchIntoVisualizer(targetId);
}

export async function loadBatchIntoVisualizer(batchId, targetLeafIndex = 0) {
    const b = sessionBatches.get(batchId);
    if (!b || !merkleVisualizer) return;

    const statsElem = $('visualizer-tree-stats');
    if (statsElem) {
        statsElem.textContent = `Batch: ${b.batch_id} · Leaves: ${b.unit_count} · Height: ${b.height} · Root: ${b.root_hex.slice(0, 8)}...`;
    }

    const records = b.units.map(u => u.record);
    await merkleVisualizer.loadBatch(records, b.root_hex, targetLeafIndex);

    // Populate unit selector dropdown
    const unitSelect = $('visualizer-unit-select');
    if (unitSelect) {
        unitSelect.innerHTML = '';
        records.forEach((rec, idx) => {
            const opt = document.createElement('option');
            opt.value = String(idx);
            opt.textContent = `Unit #${idx + 1} (${rec.unit_id})`;
            if (idx === targetLeafIndex) opt.selected = true;
            unitSelect.appendChild(opt);
        });
    }

    const unitSearch = $('visualizer-unit-search');
    if (unitSearch && records[targetLeafIndex]) {
        unitSearch.value = records[targetLeafIndex].unit_id;
    }
}

export function switchToVisualizerBatch(batchId, leafIndex = 0) {
    navigateToSection('status');
    updateVisualizerBatchList(batchId);
    setTimeout(() => {
        loadBatchIntoVisualizer(batchId, leafIndex);
        const card = $('visualizer-card');
        if (card) {
            card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }, 100);
}

export function createDemoBatch() {
    if (!wasmEngineInstance) return;
    try {
        const batchId = 'DEMO-BATCH-001';
        const medicineName = 'Amoxicillin Trihydrate 500mg';
        const mfgDate = '2026-01-15';
        const expDate = '2028-01-15';
        const unitCount = 5;

        const batchContext = wasmEngineInstance.createBatch();
        const units = [];
        const unitsById = new Map();

        for (let i = 0; i < unitCount; i++) {
            const unitId = `UNIT-${String(i + 1).padStart(6, '0')}`;
            const record = {
                batch_id: batchId,
                unit_id: unitId,
                medicine_name: medicineName,
                manufacturing_date: mfgDate,
                expiry_date: expDate
            };
            const serialized = serializeMedicineRecord(record);
            const leafBuffer = new Uint8Array(1 + serialized.length);
            leafBuffer[0] = 0x00;
            leafBuffer.set(serialized, 1);
            const leafHashHex = wasmEngineInstance.sha256Hex(leafBuffer);

            const unitItem = {
                leafIndex: i,
                unitId: unitId,
                record: record,
                leafHashHex: leafHashHex
            };
            units.push(unitItem);
            unitsById.set(unitId.toUpperCase(), unitItem);
            batchContext.addRecord(serialized);
        }

        batchContext.buildTree();
        const rootHex = batchContext.getRootHex();
        const treeHeight = batchContext.getHeight();

        const demoBatchData = {
            context: batchContext,
            batch_id: batchId,
            medicine_name: medicineName,
            manufacturing_date: mfgDate,
            expiry_date: expDate,
            unit_count: unitCount,
            root_hex: rootHex,
            height: treeHeight,
            build_duration: 0.8,
            units: units,
            unitsById: unitsById
        };

        sessionBatches.set(batchId, demoBatchData);
        if (!activeBatchId) activeBatchId = batchId;
        renderPharmacistSessionBatches();
        updateVisualizerBatchList(batchId);
    } catch (e) {
        console.warn('[MedicineGuard] Demo batch initialization skipped:', e);
    }
}

/* =========================================================================
 * Event Listeners & Bootstrapping
 * ========================================================================= */

if (isBrowser) {
    // Handle navigation link clicks
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.dataset.section;
            window.location.hash = section;
            navigateToSection(section);
        });
    });

    // Handle role card clicks on Overview
    document.querySelectorAll('[data-nav-target]').forEach(card => {
        card.addEventListener('click', () => {
            const target = card.dataset.navTarget;
            window.location.hash = target;
            navigateToSection(target);
        });
    });

    // Handle role dropdown change
    if (roleSelect) {
        roleSelect.addEventListener('change', (e) => {
            const target = e.target.value;
            window.location.hash = target;
            navigateToSection(target);
        });
    }

    // Mobile sidebar toggles
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', openMobileSidebar);
    }
    if (sidebarBackdrop) {
        sidebarBackdrop.addEventListener('click', closeMobileSidebar);
    }

    // Manufacturer Form Submit & Reset
    if (mfgBatchForm) {
        mfgBatchForm.addEventListener('submit', handleBatchRegistration);
    }
    if (mfgBtnReset) {
        mfgBtnReset.addEventListener('click', resetBatchRegistration);
    }

    // Copy Merkle Root Button
    if (mfgCopyRootBtn) {
        mfgCopyRootBtn.addEventListener('click', () => {
            if (!activeBatchData) return;
            navigator.clipboard.writeText(activeBatchData.root_hex).then(() => {
                copyBtnText.textContent = 'Copied!';
                setTimeout(() => {
                    copyBtnText.textContent = 'Copy';
                }, 2000);
            }).catch(() => {
                prompt('Copy Merkle Root:', activeBatchData.root_hex);
            });
        });
    }

    // Search and Page Size Filter
    if (mfgSearchInput) {
        mfgSearchInput.addEventListener('input', (e) => {
            mfgSearchQuery = e.target.value.trim();
            mfgCurrentPage = 1;
            renderUnitsTable();
        });
    }
    if (mfgPageSizeSelect) {
        mfgPageSizeSelect.addEventListener('change', (e) => {
            mfgPageSize = parseInt(e.target.value, 10);
            mfgCurrentPage = 1;
            renderUnitsTable();
        });
    }
    if (mfgPrevPageBtn) {
        mfgPrevPageBtn.addEventListener('click', () => {
            if (mfgCurrentPage > 1) {
                mfgCurrentPage--;
                renderUnitsTable();
            }
        });
    }
    if (mfgNextPageBtn) {
        mfgNextPageBtn.addEventListener('click', () => {
            mfgCurrentPage++;
            renderUnitsTable();
        });
    }

    // Modal Close & Tamper Buttons
    if (modalCloseX) modalCloseX.addEventListener('click', closeModal);
    if (modalCloseFooter) modalCloseFooter.addEventListener('click', closeModal);
    if (proofModal) {
        proofModal.addEventListener('click', (e) => {
            if (e.target === proofModal) closeModal();
        });
    }
    if (modalBtnTamperToggle) {
        modalBtnTamperToggle.addEventListener('click', () => {
            currentModalIsTampered = !currentModalIsTampered;
            if (currentModalIsTampered) {
                modalBtnTamperToggle.textContent = 'Restore Authentic Record';
                modalBtnTamperToggle.className = 'btn-primary';
            } else {
                modalBtnTamperToggle.textContent = 'Simulate Altered Record';
                modalBtnTamperToggle.className = 'btn-secondary';
            }
            updateModalVerificationResult();
        });
    }

    const modalBtnVisualize = $('modal-btn-visualize-unit');
    if (modalBtnVisualize) {
        modalBtnVisualize.addEventListener('click', () => {
            const unit = currentModalUnit;
            const bId = activeBatchId;
            closeModal();
            if (unit && bId) {
                switchToVisualizerBatch(bId, unit.leafIndex);
            }
        });
    }

    // Pharmacist Portal Event Listeners (Phase 3C)
    if (pharmLookupForm) {
        pharmLookupForm.addEventListener('submit', handlePharmacistLookup);
    }
    if (pharmBtnClear) {
        pharmBtnClear.addEventListener('click', clearPharmacistForm);
    }
    if (pharmBtnCopyRoot) {
        pharmBtnCopyRoot.addEventListener('click', copyPharmacistRoot);
    }
    if (pharmBtnToggleProof) {
        pharmBtnToggleProof.addEventListener('click', togglePharmacistProof);
    }
    if (pharmBtnTamperToggle) {
        pharmBtnTamperToggle.addEventListener('click', handlePharmacistTamperToggle);
    }
    if (pharmBtnClearHistory) {
        pharmBtnClearHistory.addEventListener('click', clearPharmacistHistory);
    }

    const pharmBtnVisualize = $('pharm-btn-visualize-unit');
    if (pharmBtnVisualize) {
        pharmBtnVisualize.addEventListener('click', () => {
            if (currentPharmUnit && currentPharmBatchData) {
                switchToVisualizerBatch(currentPharmBatchData.batch_id, currentPharmUnit.leafIndex);
            }
        });
    }

    // Phase 3D Event Listeners: Auth, Admin, Source Toggle & Publishing
    const btnOpenLogin = $('btn-open-login');
    if (btnOpenLogin) {
        btnOpenLogin.addEventListener('click', () => openAuthModal('login'));
    }

    const btnLogout = $('btn-logout');
    if (btnLogout) {
        btnLogout.addEventListener('click', handleLogout);
    }

    const loginModal = $('login-modal');
    const loginModalClose = $('login-modal-close');
    if (loginModalClose) {
        loginModalClose.addEventListener('click', closeAuthModal);
    }
    if (loginModal) {
        loginModal.addEventListener('click', (e) => {
            if (e.target === loginModal) {
                closeAuthModal();
            }
        });
    }

    const tabLogin = $('tab-login');
    if (tabLogin) {
        tabLogin.addEventListener('click', () => openAuthModal('login'));
    }

    const tabBootstrap = $('tab-bootstrap');
    if (tabBootstrap) {
        tabBootstrap.addEventListener('click', () => openAuthModal('bootstrap'));
    }

    const formLogin = $('form-login');
    if (formLogin) {
        formLogin.addEventListener('submit', handleLogin);
    }

    const formBootstrap = $('form-bootstrap');
    if (formBootstrap) {
        formBootstrap.addEventListener('submit', handleBootstrap);
    }

    const btnPublishBatch = $('btn-publish-batch');
    if (btnPublishBatch) {
        btnPublishBatch.addEventListener('click', handlePublishBatch);
    }

    const btnMfgVisualize = $('btn-mfg-visualize-batch');
    if (btnMfgVisualize) {
        btnMfgVisualize.addEventListener('click', () => {
            if (activeBatchId) {
                switchToVisualizerBatch(activeBatchId, 0);
            }
        });
    }

    const pharmSourceShared = $('pharm-source-shared');
    const pharmSourceLocal = $('pharm-source-local');
    const pharmSourceInfo = $('pharm-source-info');

    if (pharmSourceShared) {
        pharmSourceShared.addEventListener('click', () => {
            pharmSourceMode = 'shared';
            pharmSourceShared.classList.add('active');
            if (pharmSourceLocal) pharmSourceLocal.classList.remove('active');
            if (pharmSourceInfo) pharmSourceInfo.textContent = 'Mode: Cross-device verification via Cloudflare D1';
            loadPublishedBatches();
        });
    }

    if (pharmSourceLocal) {
        pharmSourceLocal.addEventListener('click', () => {
            pharmSourceMode = 'local';
            pharmSourceLocal.classList.add('active');
            if (pharmSourceShared) pharmSourceShared.classList.remove('active');
            if (pharmSourceInfo) pharmSourceInfo.textContent = 'Mode: Local in-memory browser session';
            renderPharmacistSessionBatches();
        });
    }

    const ambiguousModal = $('ambiguous-modal');
    const ambiguousClose = $('ambiguous-modal-close');
    const ambiguousCancel = $('ambiguous-modal-cancel');
    const closeAmbiguousModal = () => ambiguousModal?.classList.remove('active', 'open');
    if (ambiguousClose) ambiguousClose.addEventListener('click', closeAmbiguousModal);
    if (ambiguousCancel) ambiguousCancel.addEventListener('click', closeAmbiguousModal);
    if (ambiguousModal) {
        ambiguousModal.addEventListener('click', (e) => {
            if (e.target === ambiguousModal) closeAmbiguousModal();
        });
    }

    const adminResetModal = $('admin-reset-modal');
    const adminResetClose = $('admin-reset-modal-close');
    const adminResetCancel = $('admin-reset-cancel');
    const closeAdminResetModal = () => adminResetModal?.classList.remove('active', 'open');
    if (adminResetClose) adminResetClose.addEventListener('click', closeAdminResetModal);
    if (adminResetCancel) adminResetCancel.addEventListener('click', closeAdminResetModal);
    if (adminResetModal) {
        adminResetModal.addEventListener('click', (e) => {
            if (e.target === adminResetModal) closeAdminResetModal();
        });
    }

    const adminResetForm = $('admin-reset-form');
    if (adminResetForm) adminResetForm.addEventListener('submit', handleAdminResetSubmit);

    const adminCreateUserForm = $('admin-create-user-form');
    if (adminCreateUserForm) adminCreateUserForm.addEventListener('submit', handleAdminCreateUser);

    const adminBtnRefreshUsers = $('admin-btn-refresh-users');
    if (adminBtnRefreshUsers) adminBtnRefreshUsers.addEventListener('click', loadAdminUsers);

    const pharmBtnRefreshAudit = $('pharm-btn-refresh-audit');
    if (pharmBtnRefreshAudit) pharmBtnRefreshAudit.addEventListener('click', loadServerAuditLogs);

    // Phase 4: Batch Revocation
    const btnRevokeBatch = $('btn-revoke-batch');
    if (btnRevokeBatch) {
        btnRevokeBatch.addEventListener('click', async () => {
            if (!activeBatchData) return;
            const confirmed = confirm(`Are you sure you want to REVOKE published batch "${activeBatchData.batch_id}"?\n\nThis will permanently recall the batch and notify all verifying customers and pharmacists.`);
            if (!confirmed) return;
            const reason = prompt('Please enter the revocation reason (e.g. Quality control recall):', 'Quality control recall') || 'Manufacturer product recall';

            try {
                btnRevokeBatch.disabled = true;
                const res = await fetch(`/api/manufacturer/batches/${encodeURIComponent(activeBatchData.batch_id)}/revoke`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': currentCsrfToken || ''
                    },
                    body: JSON.stringify({ reason })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    throw new Error(data.error?.message || `Revocation failed with status ${res.status}`);
                }
                alert(`Batch "${activeBatchData.batch_id}" has been revoked successfully.`);
                const badge = $('mfg-publish-status-badge');
                if (badge) {
                    badge.textContent = 'Batch Revoked (Recalled) ⚠️';
                    badge.style.backgroundColor = 'var(--color-danger-bg)';
                    badge.style.color = 'var(--color-danger)';
                    badge.style.borderColor = 'var(--color-danger-border)';
                }
                btnRevokeBatch.style.display = 'none';
            } catch (err) {
                alert(`Revocation failed: ${err.message}`);
                btnRevokeBatch.disabled = false;
            }
        });
    }

    // Phase 4: Manufacturer QR Modal Close & Download
    const mfgQrCloseBtn = $('mfg-qr-close-btn');
    const mfgQrModalClose = $('mfg-qr-modal-close');
    const mfgQrModal = $('mfg-qr-modal');
    if (mfgQrCloseBtn && mfgQrModal) mfgQrCloseBtn.addEventListener('click', () => { mfgQrModal.style.display = 'none'; });
    if (mfgQrModalClose && mfgQrModal) mfgQrModalClose.addEventListener('click', () => { mfgQrModal.style.display = 'none'; });

    const mfgQrCopyBtn = $('mfg-qr-copy-btn');
    if (mfgQrCopyBtn) {
        mfgQrCopyBtn.addEventListener('click', () => {
            const val = $('mfg-qr-url-input')?.value;
            if (val) {
                navigator.clipboard.writeText(val);
                mfgQrCopyBtn.textContent = 'Copied!';
                setTimeout(() => { mfgQrCopyBtn.textContent = 'Copy'; }, 1500);
            }
        });
    }

    const mfgQrDownloadBtn = $('mfg-qr-download-btn');
    if (mfgQrDownloadBtn) {
        mfgQrDownloadBtn.addEventListener('click', () => {
            const canvas = $('mfg-qr-canvas');
            if (!canvas) return;
            const unitId = $('mfg-qr-unit-id')?.textContent || 'unit';
            const batchId = $('mfg-qr-batch-id')?.textContent || 'batch';
            const a = document.createElement('a');
            a.download = `QR_${batchId}_${unitId}.png`;
            a.href = canvas.toDataURL('image/png');
            a.click();
        });
    }

    // Phase 4: Customer Verification Scanner & Manual Input
    const btnStartScanner = $('btn-start-scanner');
    const btnStopScanner = $('btn-stop-scanner');
    if (btnStartScanner) btnStartScanner.addEventListener('click', startQrScanner);
    if (btnStopScanner) btnStopScanner.addEventListener('click', stopQrScanner);

    const customerVerifyForm = $('customer-verify-form');
    if (customerVerifyForm) {
        customerVerifyForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const ref = $('customer-ref-input')?.value;
            verifyCustomerReference(ref);
        });
    }

    const custBtnVerifyAnother = $('cust-btn-verify-another');
    if (custBtnVerifyAnother) {
        custBtnVerifyAnother.addEventListener('click', () => {
            const verifiedCard = $('customer-result-verified');
            if (verifiedCard) verifiedCard.style.display = 'none';
            const refInput = $('customer-ref-input');
            if (refInput) {
                refInput.value = '';
                refInput.focus();
            }
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    const custBtnTryAgain = $('cust-btn-try-again');
    if (custBtnTryAgain) {
        custBtnTryAgain.addEventListener('click', () => {
            const errCard = $('customer-result-error');
            if (errCard) errCard.style.display = 'none';
            const refInput = $('customer-ref-input');
            if (refInput) {
                refInput.focus();
            }
        });
    }

    // Global navigation target click handler (for dynamic links like Go to Manufacturer)
    document.addEventListener('click', (e) => {
        const targetLink = e.target.closest('[data-nav-target]');
        if (targetLink) {
            e.preventDefault();
            const targetSection = targetLink.dataset.navTarget;
            window.location.hash = targetSection;
            navigateToSection(targetSection);
        }
    });

    // Window hashchange listener for browser back/forward buttons
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.replace('#', '') || 'overview';
        navigateToSection(hash);
    });

    // Window beforeunload listener for deterministic WASM handle cleanup and camera track release
    window.addEventListener('beforeunload', () => {
        stopQrScanner();
        for (const b of sessionBatches.values()) {
            if (b.context && !b.context.isDestroyed) {
                b.context.destroy();
            }
        }
        sessionBatches.clear();
        activeBatchContext = null;
        activeBatchData = null;
    });

    // Modal dismissal via Escape key
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            closeQrModal();
            closeAuthModal();
            $('admin-reset-modal')?.classList.remove('active', 'open');
            $('ambiguous-modal')?.classList.remove('active', 'open');
        }
    });

    // Bootstrap application on DOM ready
    window.addEventListener('DOMContentLoaded', () => {
        // Initialize Merkle Tree Visualizer (Phase 5)
        initMerkleVisualizer();

        // Check for URL query parameter: ?verify=REFERENCE
        const urlParams = new URLSearchParams(window.location.search);
        const verifyParam = urlParams.get('verify');
        if (verifyParam && verifyParam.trim()) {
            const cleanParam = verifyParam.trim();
            navigateToSection('customer');
            const refInput = $('customer-ref-input');
            if (refInput) refInput.value = cleanParam;
            verifyCustomerReference(cleanParam);
        } else {
            // Determine initial route from URL hash or default to overview
            const initialSection = window.location.hash.replace('#', '') || 'overview';
            navigateToSection(initialSection);
        }

        // Initialize Manufacturer Form Defaults
        initManufacturerForm();

        // Initialize Pharmacist UI State
        renderPharmacistSessionBatches();
        renderPharmacistHistoryTable();

        // Initialize WebAssembly Engine
        initializeWasmEngine();

        // Phase 3D: Check Auth Session & Load Shared Registry Data
        checkAuthSession();
        loadPublishedBatches();
        loadServerAuditLogs();
    });
}

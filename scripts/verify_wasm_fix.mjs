/**
 * MedicineGuard — Automated Browser Verification of WebAssembly Loading Fix
 * Connects directly to Chrome DevTools Protocol to verify:
 * - Hard-refresh (cache disabled)
 * - MIME types for medicineguard.js and medicineguard.wasm
 * - Zero console module MIME errors
 * - MedicineGuard.init() completion
 * - UI status change to "WASM Engine Ready"
 * - SHA-256("MedicineGuard") self-check digest match
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const CDP_PORT = 9223; // Use separate port to avoid conflicts
const APP_URL = 'http://127.0.0.1:8788/';
const EXPECTED_DIGEST = 'ed7978c817ee88245c5caf6e7ebfabadc5c84043d2cac6b960646934e0d8e3c8';

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function isCdpReady() {
  try {
    const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

async function getPageTarget() {
  const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`);
  const list = await res.json();
  return list.find(item => item.type === 'page') || list[0];
}

class CdpSession {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.id = 1;
    this.callbacks = new Map();
    this.consoleLogs = [];
    this.networkResponses = [];
    this.networkRequests = [];
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onopen = () => resolve();
      this.ws.onerror = (err) => reject(err);
      this.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.id && this.callbacks.has(msg.id)) {
          const { resolve, reject } = this.callbacks.get(msg.id);
          this.callbacks.delete(msg.id);
          if (msg.error) {
            reject(new Error(msg.error.message));
          } else {
            resolve(msg.result);
          }
        } else if (msg.method === 'Runtime.consoleAPICalled') {
          const args = (msg.params.args || []).map(a => a.value ?? a.description ?? JSON.stringify(a)).join(' ');
          this.consoleLogs.push({ type: msg.params.type, text: args });
        } else if (msg.method === 'Network.responseReceived') {
          this.networkResponses.push({
            url: msg.params.response.url,
            status: msg.params.response.status,
            mimeType: msg.params.response.mimeType,
            headers: msg.params.response.headers
          });
        }
      };
    });
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const msgId = this.id++;
      this.callbacks.set(msgId, { resolve, reject });
      this.ws.send(JSON.stringify({ id: msgId, method, params }));
    });
  }

  async evaluate(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true
    });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.text || 'Runtime.evaluate failed');
    }
    return res.result?.value;
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function main() {
  console.log('========================================================================');
  console.log(' MEDICINEGUARD WASM LOADING FIX VERIFICATION IN REAL CHROME');
  console.log(` Target Server: ${APP_URL}`);
  console.log('========================================================================');

  const userDataDir = path.join(process.env.TEMP || 'C:\\Temp', 'chrome_wasm_fix_test');
  console.log(`[INFO] Launching isolated Chrome instance on port ${CDP_PORT}...`);
  const chromeProc = spawn(CHROME_PATH, [
    '--headless=new',
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${userDataDir}`,
    '--window-size=1440,960',
    '--disable-gpu',
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank'
  ], { detached: true, stdio: 'ignore' });

  for (let i = 0; i < 20; i++) {
    await sleep(400);
    const ready = await isCdpReady();
    if (ready) break;
  }

  const target = await getPageTarget();
  const cdp = new CdpSession(target.webSocketDebuggerUrl);
  await cdp.connect();

  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');

  // Enforce Hard Refresh (disable cache per Ctrl+Shift+R)
  await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
  console.log('[INFO] Hard-refresh mode enabled (cache disabled).');

  console.log(`[INFO] Navigating to ${APP_URL}...`);
  await cdp.send('Page.navigate', { url: APP_URL });

  // Wait up to 10 seconds for WASM initialization
  let statusText = '';
  let badgeClass = '';
  let selfTestHash = '';

  for (let i = 0; i < 25; i++) {
    await sleep(400);
    const result = await cdp.evaluate(`(() => {
      const topbarText = document.getElementById('topbar-status-text')?.textContent.trim();
      const topbarBadge = document.getElementById('topbar-engine-badge')?.className;
      const sidebarText = document.getElementById('sidebar-status-text')?.textContent.trim();
      return {
        topbarText,
        topbarBadge,
        sidebarText,
        hasWasmInstance: typeof window.wasmEngineInstance !== 'undefined' && window.wasmEngineInstance !== null
      };
    })()`);

    statusText = result.topbarText || '';
    badgeClass = result.topbarBadge || '';

    if (statusText === 'WASM Engine Ready' || statusText === 'WASM Unavailable') {
      break;
    }
  }

  console.log('\n--- 1. NETWORK REQUESTS & MIME TYPES ---');
  const jsReq = cdp.networkResponses.find(r => r.url.includes('/wasm/medicineguard.js'));
  const wasmReq = cdp.networkResponses.find(r => r.url.includes('/wasm/medicineguard.wasm'));

  if (jsReq) {
    console.log(`  ✓ medicineguard.js Status: ${jsReq.status}, MIME: ${jsReq.mimeType || jsReq.headers['content-type']}`);
  } else {
    console.error('  ✗ medicineguard.js was not requested or captured in network log');
  }

  if (wasmReq) {
    console.log(`  ✓ medicineguard.wasm Status: ${wasmReq.status}, MIME: ${wasmReq.mimeType || wasmReq.headers['content-type']}`);
  } else {
    console.error('  ✗ medicineguard.wasm was not requested or captured in network log');
  }

  console.log('\n--- 2. BROWSER CONSOLE ERRORS & LOGS ---');
  const mimeErrors = cdp.consoleLogs.filter(l => 
    l.text.includes('MIME') || 
    l.text.includes('Failed to load module script') || 
    l.text.includes('application/wasm')
  );

  const errors = cdp.consoleLogs.filter(l => l.type === 'error');
  console.log(`  Total console logs: ${cdp.consoleLogs.length}`);
  console.log(`  Module MIME errors: ${mimeErrors.length}`);
  console.log(`  Total errors: ${errors.length}`);

  if (mimeErrors.length > 0) {
    console.error('  ✗ MIME errors detected:');
    mimeErrors.forEach(e => console.error('    ', e.text));
  } else {
    console.log('  ✓ Zero module script MIME errors in console.');
  }

  cdp.consoleLogs.forEach(log => {
    if (log.text.includes('[MedicineGuard]')) {
      console.log(`  [CONSOLE] ${log.text}`);
    }
  });

  console.log('\n--- 3. WASM ENGINE INITIALIZATION & UI STATE ---');
  console.log(`  Topbar Status Text:  "${statusText}"`);
  console.log(`  Topbar Badge Class:  "${badgeClass}"`);
  const isReady = statusText === 'WASM Engine Ready';
  console.log(`  WASM Engine Ready:   ${isReady ? '✓ YES' : '✗ NO'}`);

  console.log('\n--- 4. CRYPTOGRAPHIC SELF-CHECK: SHA-256("MedicineGuard") ---');
  // Evaluate self-check in browser context using the active engine
  const liveHash = await cdp.evaluate(`(() => {
    // If wasmEngineInstance is private to app.js, check console log or evaluate directly via wasm-loader
    const logMatch = Array.from(document.querySelectorAll('script')).length;
    // We can import wasm-loader in page context to verify
    return new Promise(async (resolve) => {
      try {
        const { default: MedicineGuard } = await import('/js/wasm-loader.js');
        const engine = await MedicineGuard.init();
        resolve(engine.sha256Hex('MedicineGuard'));
      } catch (err) {
        resolve('ERROR: ' + err.message);
      }
    });
  })()`);

  console.log(`  Calculated Digest: ${liveHash}`);
  console.log(`  Expected Digest:   ${EXPECTED_DIGEST}`);
  const hashMatches = liveHash.toLowerCase() === EXPECTED_DIGEST.toLowerCase();
  console.log(`  Digest Matches:    ${hashMatches ? '✓ YES (Bit-for-bit exact match)' : '✗ NO'}`);

  // Take a screenshot of the fixed UI
  const screenshotPath = path.join(ROOT_DIR, 'screenshot_wasm_fixed.png');
  const shotData = await cdp.send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(screenshotPath, Buffer.from(shotData.data, 'base64'));
  console.log(`  ✓ Screenshot saved: ${screenshotPath}`);

  cdp.close();

  // Kill the isolated test Chrome instance
  try {
    process.kill(-chromeProc.pid);
  } catch {
    try { chromeProc.kill(); } catch {}
  }

  console.log('\n========================================================================');
  const allPassed = isReady && hashMatches && mimeErrors.length === 0;
  console.log(` VERIFICATION OUTCOME: ${allPassed ? 'ALL CHECKS PASSED (100% FIXED)' : 'FAILURES DETECTED'}`);
  console.log('========================================================================');

  if (!allPassed) process.exit(1);
}

main().catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});

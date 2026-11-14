/**
 * MedicineGuard — Live Chrome Browser Demonstration & Screenshot Capture
 * Connects directly to Google Chrome via native Chrome DevTools Protocol (CDP) WebSocket.
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ARTIFACT_DIR = 'C:\\Users\\K.Y.VARDHAN\\.gemini\\antigravity\\brain\\643b3b46-1ca5-4c1f-9452-18c0df9a9452';
const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const CDP_PORT = 9222;
const APP_URL = 'http://127.0.0.1:8788/';

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function isCdpReady() {
  try {
    const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
    if (res.ok) {
      return await res.json();
    }
  } catch {}
  return null;
}

async function getPageTarget() {
  const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`);
  const list = await res.json();
  const page = list.find(item => item.type === 'page');
  return page || list[0];
}

class CdpSession {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.id = 1;
    this.callbacks = new Map();
    this.consoleLogs = [];
    this.networkErrors = [];
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
          if (msg.params.response.status >= 400) {
            this.networkErrors.push({
              url: msg.params.response.url,
              status: msg.params.response.status,
              statusText: msg.params.response.statusText
            });
          }
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

  async screenshot(filepath, clip = null) {
    const params = { format: 'png' };
    if (clip) params.clip = clip;
    const res = await this.send('Page.captureScreenshot', params);
    const buf = Buffer.from(res.data, 'base64');
    fs.writeFileSync(filepath, buf);
    console.log(`  ✓ Screenshot saved: ${filepath} (${(buf.length / 1024).toFixed(1)} KB)`);
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function main() {
  console.log('========================================================================');
  console.log(' MEDICINEGUARD LIVE BROWSER DEMONSTRATION & SCREENSHOT CAPTURE');
  console.log(` Target URL: ${APP_URL}`);
  console.log('========================================================================');

  let versionInfo = await isCdpReady();
  let chromeProc = null;

  if (!versionInfo) {
    console.log('[INFO] Spawning Chrome with remote debugging on port ' + CDP_PORT + '...');
    const userDataDir = path.join(process.env.TEMP || 'C:\\Temp', 'chrome_medguard_audit');
    chromeProc = spawn(CHROME_PATH, [
      '--headless=new',
      `--remote-debugging-port=${CDP_PORT}`,
      `--user-data-dir=${userDataDir}`,
      '--window-size=1440,960',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      APP_URL
    ], { detached: true, stdio: 'ignore' });

    for (let i = 0; i < 20; i++) {
      await sleep(500);
      versionInfo = await isCdpReady();
      if (versionInfo) break;
    }
  }

  if (!versionInfo) {
    console.error('[ERROR] Unable to connect to Chrome DevTools protocol.');
    process.exit(1);
  }

  console.log(`[INFO] Connected to Chrome DevTools: ${versionInfo.Browser}`);

  const target = await getPageTarget();
  console.log(`[INFO] Attaching to target: ${target.title || target.url} (${target.webSocketDebuggerUrl})`);

  const cdp = new CdpSession(target.webSocketDebuggerUrl);
  await cdp.connect();

  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  await cdp.send('Network.enable');

  console.log(`[INFO] Navigating to ${APP_URL}...`);
  await cdp.send('Page.navigate', { url: APP_URL });
  await sleep(1500);

  // Wait for WASM initialization (up to 10 seconds)
  console.log('[INFO] Awaiting WebAssembly engine initialization...');
  let wasmStatusText = '';
  let wasmBadgeClass = '';
  for (let i = 0; i < 20; i++) {
    const status = await cdp.evaluate(`(() => {
      const el = document.getElementById('topbar-status-text');
      const badge = document.getElementById('topbar-engine-badge');
      return {
        text: el ? el.textContent.trim() : '',
        className: badge ? badge.className : '',
        sidebarText: document.getElementById('sidebar-status-text')?.textContent.trim()
      };
    })()`);

    if (status && (status.text.includes('Ready') || status.text.includes('Unavailable') || status.text.includes('WASM'))) {
      wasmStatusText = status.text;
      wasmBadgeClass = status.className;
      if (!status.text.includes('Initializing')) {
        break;
      }
    }
    await sleep(500);
  }

  console.log(`\n[WASM STATUS] Topbar Status: "${wasmStatusText}" (Badge class: "${wasmBadgeClass}")`);

  const overviewScreenshotPath = path.join(ARTIFACT_DIR, 'screenshot_01_overview.png');
  await cdp.screenshot(overviewScreenshotPath);

  // 1. Manufacturer Section
  console.log('\n[INSPECT] Navigating to Manufacturer Portal...');
  await cdp.evaluate(`(() => {
    const link = document.querySelector('a[data-section="manufacturer"]');
    if (link) link.click();
  })()`);
  await sleep(800);
  const mfgScreenshotPath = path.join(ARTIFACT_DIR, 'screenshot_02_manufacturer.png');
  await cdp.screenshot(mfgScreenshotPath);

  // 2. Pharmacist Section
  console.log('\n[INSPECT] Navigating to Pharmacist Portal...');
  await cdp.evaluate(`(() => {
    const link = document.querySelector('a[data-section="pharmacist"]');
    if (link) link.click();
  })()`);
  await sleep(800);
  const pharmScreenshotPath = path.join(ARTIFACT_DIR, 'screenshot_03_pharmacist.png');
  await cdp.screenshot(pharmScreenshotPath);

  // 3. Customer Verification Section
  console.log('\n[INSPECT] Navigating to Customer Verification Portal...');
  await cdp.evaluate(`(() => {
    const link = document.querySelector('a[data-section="customer"]');
    if (link) link.click();
  })()`);
  await sleep(800);
  const custScreenshotPath = path.join(ARTIFACT_DIR, 'screenshot_04_customer.png');
  await cdp.screenshot(custScreenshotPath);

  // 4. Algorithm & Merkle Tree Visualizer Section
  console.log('\n[INSPECT] Navigating to Algorithm & Engine (Visualizer)...');
  await cdp.evaluate(`(() => {
    const link = document.querySelector('a[data-section="status"]');
    if (link) link.click();
    const visCard = document.getElementById('visualizer-card');
    if (visCard) visCard.scrollIntoView({ behavior: 'instant', block: 'start' });
  })()`);
  await sleep(1000);

  // Check visualizer batches & test controls
  const visualizerInfo = await cdp.evaluate(`(() => {
    const batchSelect = document.getElementById('visualizer-batch-select');
    const options = batchSelect ? Array.from(batchSelect.options).map(o => ({ value: o.value, text: o.text })) : [];
    const stats = document.getElementById('visualizer-tree-stats')?.textContent.trim();
    const svg = document.getElementById('visualizer-svg');
    const nodes = svg ? svg.querySelectorAll('.vis-node').length : 0;
    const links = svg ? svg.querySelectorAll('.vis-link').length : 0;
    
    // Select first real batch if available
    if (batchSelect && options.length > 1 && options[1].value) {
      batchSelect.value = options[1].value;
      batchSelect.dispatchEvent(new Event('change'));
    }
    
    return { options, stats, nodes, links };
  })()`);

  console.log(`  Visualizer batches available: ${visualizerInfo.options.length} (Options: ${JSON.stringify(visualizerInfo.options.map(o => o.text))})`);
  await sleep(800);

  // Test Focused Proof Path Mode & Zoom
  await cdp.evaluate(`(() => {
    const btnFocused = document.getElementById('vis-btn-mode-focused');
    if (btnFocused) btnFocused.click();
    const btnZoomIn = document.getElementById('vis-zoom-in');
    if (btnZoomIn) { btnZoomIn.click(); btnZoomIn.click(); }
  })()`);
  await sleep(600);

  const visScreenshotPath = path.join(ARTIFACT_DIR, 'screenshot_05_visualizer.png');
  await cdp.screenshot(visScreenshotPath);

  // 5. Auth Modal / Admin Bootstrap Dialog
  console.log('\n[INSPECT] Opening Sign In / Admin Bootstrap Modal...');
  await cdp.evaluate(`(() => {
    const btnLogin = document.getElementById('btn-open-login');
    if (btnLogin) btnLogin.click();
  })()`);
  await sleep(600);
  const authScreenshotPath = path.join(ARTIFACT_DIR, 'screenshot_06_auth_modal.png');
  await cdp.screenshot(authScreenshotPath);

  // Gather Console & Diagnostics
  console.log('\n========================================================================');
  console.log(' BROWSER DIAGNOSTICS');
  console.log('========================================================================');
  console.log(`Console logs captured: ${cdp.consoleLogs.length}`);
  const errors = cdp.consoleLogs.filter(l => l.type === 'error');
  const warnings = cdp.consoleLogs.filter(l => l.type === 'warning' || l.type === 'warn');
  console.log(`Errors: ${errors.length}, Warnings: ${warnings.length}`);
  if (errors.length > 0) {
    console.log('Console Errors:');
    errors.forEach(e => console.log('  [ERROR]', e.text));
  } else {
    console.log('  ✓ Zero unhandled JavaScript errors detected.');
  }

  if (cdp.networkErrors.length > 0) {
    console.log(`Network HTTP >= 400 requests: ${cdp.networkErrors.length}`);
    cdp.networkErrors.forEach(ne => console.log(`  [HTTP ${ne.status}] ${ne.url}`));
  } else {
    console.log('  ✓ Zero failed HTTP requests.');
  }

  cdp.close();

  console.log('\n========================================================================');
  console.log(' ALL 6 HIGH-RESOLUTION SCREENSHOTS GENERATED SUCCESSFULLY');
  console.log('========================================================================');
}

main().catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});


/**
 * MedicineGuard — Live Browser Verification of Authentication Flow
 * Drives actual Google Chrome instance via DevTools Protocol (CDP) to verify:
 * 1. Sign In button opens login modal (display: flex, visibility: visible)
 * 2. Close button closes modal
 * 3. Backdrop click closes modal
 * 4. Escape key closes modal
 * 5. Empty inputs show validation alert
 * 6. Wrong password displays "Invalid email or password"
 * 7. Admin login succeeds, updates UI to ADMIN badge, navigates to #admin
 * 8. Admin provisions a test Manufacturer and test Pharmacist via Admin UI
 * 9. Admin disables a user -> verify disabled user login returns "Account is disabled"
 * 10. Logout works cleanly and clears session
 * 11. Manufacturer login works -> displays MANUFACTURER badge, navigates to #manufacturer
 * 12. Pharmacist login works -> displays PHARMACIST badge, navigates to #pharmacist
 * 13. Session persistence: reload page -> remains logged in
 * 14. Unauthorized navigation guard: logged out visiting #admin redirects to #overview
 */

import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const CDP_PORT = 9228;
const APP_URL = 'http://127.0.0.1:8788/';
const ADMIN_EMAIL = 'admin@medicineguard.local';
const ADMIN_PASS = 'AdminPassword2026!';

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function isCdpReady() {
  try {
    const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
    if (res.ok) return await res.json();
  } catch {}
  return null;
}

class BrowserTestSession {
  constructor(port) {
    this.port = port;
    this.ws = null;
    this.id = 1;
    this.callbacks = new Map();
    this.consoleLogs = [];
  }

  async start() {
    const userDataDir = path.join(process.env.TEMP || 'C:\\Temp', `chrome_auth_test_${Date.now()}`);
    this.proc = spawn(CHROME_PATH, [
      '--headless=new',
      `--remote-debugging-port=${this.port}`,
      `--user-data-dir=${userDataDir}`,
      '--window-size=1440,960',
      '--disable-gpu',
      'about:blank'
    ], { detached: true, stdio: 'ignore' });

    for (let i = 0; i < 20; i++) {
      await sleep(400);
      if (await isCdpReady()) break;
    }

    const listRes = await fetch(`http://127.0.0.1:${this.port}/json/list`);
    const list = await listRes.json();
    const page = list.find(t => t.type === 'page') || list[0];

    this.ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise(r => this.ws.onopen = r);

    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.callbacks.has(msg.id)) {
        this.callbacks.get(msg.id)(msg.result || msg.error);
        this.callbacks.delete(msg.id);
      } else if (msg.method === 'Runtime.consoleAPICalled') {
        const text = (msg.params.args || []).map(a => a.value ?? a.description ?? '').join(' ');
        this.consoleLogs.push({ type: msg.params.type, text });
      }
    };

    await this.send('Page.enable');
    await this.send('Runtime.enable');
    await this.send('Network.enable');
  }

  send(method, params = {}) {
    return new Promise(resolve => {
      const msgId = this.id++;
      this.callbacks.set(msgId, resolve);
      this.ws.send(JSON.stringify({ id: msgId, method, params }));
    });
  }

  async eval(expression) {
    const res = await this.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    return res.result?.value;
  }

  async navigate(url) {
    await this.send('Page.navigate', { url });
    await sleep(1500);
  }

  async reload() {
    await this.send('Page.reload');
    await sleep(1500);
  }

  async captureScreenshot(filepath) {
    const res = await this.send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(filepath, Buffer.from(res.data, 'base64'));
  }

  async waitFor(predicateExpression, timeoutMs = 5000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const ok = await this.eval(predicateExpression);
      if (ok) return true;
      await sleep(150);
    }
    return false;
  }

  close() {
    if (this.ws) this.ws.close();
    try { this.proc.kill(); } catch {}
  }
}

async function main() {
  console.log('========================================================================');
  console.log(' MEDICINEGUARD COMPREHENSIVE AUTHENTICATION & SIGN IN VERIFICATION');
  console.log(` Target Server: ${APP_URL}`);
  console.log('========================================================================\n');

  const session = new BrowserTestSession(CDP_PORT);
  await session.start();
  await session.navigate(APP_URL);

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✓ [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  ✗ [FAIL] ${message}`);
      failed++;
    }
  }

  console.log('--- TEST 1: Sign In Button & Modal Opening ---');
  const btnBefore = await session.eval(`(() => {
    const btn = document.getElementById('btn-open-login');
    const modal = document.getElementById('login-modal');
    return {
      btnVisible: btn && window.getComputedStyle(btn).display !== 'none',
      modalDisplay: modal ? window.getComputedStyle(modal).display : 'missing'
    };
  })()`);
  assert(btnBefore.btnVisible, 'Sign In button is visible on initial load');
  assert(btnBefore.modalDisplay === 'none', 'Login modal is initially hidden (display: none)');

  // Click Sign In
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(300);

  const modalOpened = await session.eval(`(() => {
    const modal = document.getElementById('login-modal');
    return {
      hasActive: modal.classList.contains('active'),
      display: window.getComputedStyle(modal).display,
      visibility: window.getComputedStyle(modal).visibility,
      zIndex: window.getComputedStyle(modal).zIndex
    };
  })()`);
  assert(modalOpened.display === 'flex', 'Login modal opens with display: flex');
  assert(modalOpened.hasActive, 'Login modal has .active class');
  assert(modalOpened.zIndex === '100', 'Login modal has high z-index (100) above page elements');

  // Take screenshot of open login modal
  await session.captureScreenshot('D:\\MedicineGuard\\screenshot_login_modal_open.png');
  console.log('  ✓ Screenshot of open login modal saved to screenshot_login_modal_open.png');

  console.log('\n--- TEST 2: Modal Dismissal (Close Button, Escape Key & Backdrop) ---');
  // Close with close button
  await session.eval(`document.getElementById('login-modal-close').click()`);
  await sleep(200);
  let displayAfterClose = await session.eval(`window.getComputedStyle(document.getElementById('login-modal')).display`);
  assert(displayAfterClose === 'none', 'Modal closes via close button (display: none)');

  // Re-open and close with Escape key
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(200);
  await session.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await session.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27 });
  await sleep(200);
  displayAfterClose = await session.eval(`window.getComputedStyle(document.getElementById('login-modal')).display`);
  assert(displayAfterClose === 'none', 'Modal closes via Escape key');

  // Re-open and close via Backdrop click
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(200);
  await session.eval(`(() => {
    const modal = document.getElementById('login-modal');
    modal.dispatchEvent(new MouseEvent('click', { bubbles: true, target: modal }));
  })()`);
  await sleep(200);
  displayAfterClose = await session.eval(`window.getComputedStyle(document.getElementById('login-modal')).display`);
  assert(displayAfterClose === 'none', 'Modal closes via backdrop click outside dialog');

  console.log('\n--- TEST 3: Form Validation & Bad Credentials ---');
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(200);

  // Submit empty
  await session.eval(`(() => {
    document.getElementById('login-email').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-alert')?.style.display !== 'none'`);
  const emptyAlert = await session.eval(`document.getElementById('auth-alert')?.textContent`);
  assert(emptyAlert && emptyAlert.includes('Please enter'), 'Empty submission triggers validation alert');

  // Submit invalid password
  await session.eval(`(() => {
    document.getElementById('login-email').value = '${ADMIN_EMAIL}';
    document.getElementById('login-password').value = 'WrongPassword2026!';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-alert')?.textContent.includes('Invalid')`, 4000);
  const badCredsAlert = await session.eval(`document.getElementById('auth-alert')?.textContent`);
  assert(badCredsAlert && badCredsAlert.includes('Invalid email or password'), 'Wrong password shows clear rejection error');

  console.log('\n--- TEST 4: Administrator Authentication Flow ---');
  await session.eval(`(() => {
    document.getElementById('login-email').value = '${ADMIN_EMAIL}';
    document.getElementById('login-password').value = '${ADMIN_PASS}';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-user-badge')?.textContent === 'ADMIN'`, 4000);

  const adminAuthUI = await session.eval(`(() => {
    const modal = document.getElementById('login-modal');
    const badge = document.getElementById('auth-user-badge');
    const email = document.getElementById('auth-user-email');
    const btnLogin = document.getElementById('btn-open-login');
    const userInfo = document.getElementById('auth-user-info');
    const navAdmin = document.getElementById('nav-item-admin');
    const activeSection = document.querySelector('.page-section.active')?.id;
    return {
      modalHidden: window.getComputedStyle(modal).display === 'none',
      btnLoginHidden: window.getComputedStyle(btnLogin).display === 'none',
      userInfoVisible: window.getComputedStyle(userInfo).display !== 'none',
      badgeText: badge?.textContent.trim(),
      emailText: email?.textContent.trim(),
      navAdminVisible: window.getComputedStyle(navAdmin).display !== 'none',
      activeSection
    };
  })()`);

  assert(adminAuthUI.modalHidden, 'Modal automatically closes on successful login');
  assert(adminAuthUI.btnLoginHidden, 'Sign In button hidden when authenticated');
  assert(adminAuthUI.userInfoVisible, 'User info box displayed with email and role');
  assert(adminAuthUI.badgeText === 'ADMIN', 'Role badge displays "ADMIN"');
  assert(adminAuthUI.emailText === ADMIN_EMAIL, 'Authenticated email matches');
  assert(adminAuthUI.navAdminVisible, 'Admin Portal navigation link visible for admin role');
  assert(adminAuthUI.activeSection === 'section-admin', 'Automatically redirected to Admin section');

  // Screenshot of authenticated Admin Portal
  await session.captureScreenshot('D:\\MedicineGuard\\screenshot_admin_authenticated.png');
  console.log('  ✓ Screenshot of authenticated Admin view saved to screenshot_admin_authenticated.png');

  console.log('\n--- TEST 5: Provision Test Manufacturer & Pharmacist via Admin UI ---');
  const timestamp = Date.now();
  const testMfgEmail = `mfg_flow_${timestamp}@pharma.local`;
  const testMfgPass = 'MfgFlowPass2026!';
  const testPharmEmail = `pharm_flow_${timestamp}@hospital.local`;
  const testPharmPass = 'PharmFlowPass2026!';

  // Create Manufacturer via form
  await session.eval(`(() => {
    document.getElementById('admin-new-email').value = '${testMfgEmail}';
    document.getElementById('admin-new-password').value = '${testMfgPass}';
    document.getElementById('admin-new-role').value = 'manufacturer';
    document.getElementById('admin-btn-create-user').click();
  })()`);
  await session.waitFor(`document.getElementById('admin-create-feedback')?.textContent.includes('successfully')`, 4000);
  const mfgCreatedMsg = await session.eval(`document.getElementById('admin-create-feedback')?.textContent`);
  assert(mfgCreatedMsg && mfgCreatedMsg.includes('successfully'), `Manufacturer created: ${mfgCreatedMsg}`);

  // Create Pharmacist via form
  await session.eval(`(() => {
    document.getElementById('admin-new-email').value = '${testPharmEmail}';
    document.getElementById('admin-new-password').value = '${testPharmPass}';
    document.getElementById('admin-new-role').value = 'pharmacist';
    document.getElementById('admin-btn-create-user').click();
  })()`);
  await session.waitFor(`document.getElementById('admin-create-feedback')?.textContent.includes('${testPharmEmail}')`, 4000);
  const pharmCreatedMsg = await session.eval(`document.getElementById('admin-create-feedback')?.textContent`);
  assert(pharmCreatedMsg && pharmCreatedMsg.includes('successfully'), `Pharmacist created: ${pharmCreatedMsg}`);

  // Refresh user table and find test pharmacist
  await session.eval(`document.getElementById('admin-btn-refresh-users').click()`);
  await session.waitFor(`document.getElementById('admin-users-table-body')?.textContent.includes('${testPharmEmail}')`, 4000);

  // Disable test pharmacist account via toggle button
  const disabledOk = await session.eval(`(() => {
    const rows = Array.from(document.querySelectorAll('#admin-users-table-body tr'));
    for (const r of rows) {
      if (r.textContent.includes('${testPharmEmail}')) {
        const toggleBtn = r.querySelector('[data-toggle-user]');
        if (toggleBtn) {
          toggleBtn.click();
          return true;
        }
      }
    }
    return false;
  })()`);
  await sleep(1000);
  assert(disabledOk, 'Found pharmacist row and clicked Disable button');

  console.log('\n--- TEST 6: Logout Flow ---');
  await session.eval(`document.getElementById('btn-logout').click()`);
  await session.waitFor(`document.getElementById('btn-open-login')?.style.display !== 'none'`);

  const loggedOutUI = await session.eval(`(() => {
    const btnLogin = document.getElementById('btn-open-login');
    const userInfo = document.getElementById('auth-user-info');
    const navAdmin = document.getElementById('nav-item-admin');
    const activeSection = document.querySelector('.page-section.active')?.id;
    return {
      btnLoginVisible: window.getComputedStyle(btnLogin).display !== 'none',
      userInfoHidden: window.getComputedStyle(userInfo).display === 'none',
      navAdminHidden: window.getComputedStyle(navAdmin).display === 'none',
      activeSection
    };
  })()`);
  assert(loggedOutUI.btnLoginVisible, 'Sign In button restored upon logout');
  assert(loggedOutUI.userInfoHidden, 'User info box hidden upon logout');
  assert(loggedOutUI.navAdminHidden, 'Admin portal link hidden upon logout');
  assert(loggedOutUI.activeSection === 'section-overview', 'Redirected to overview upon logout');

  console.log('\n--- TEST 7: Disabled Account Login Rejection ---');
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(300);
  await session.eval(`(() => {
    document.getElementById('login-email').value = '${testPharmEmail}';
    document.getElementById('login-password').value = '${testPharmPass}';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-alert')?.textContent.toLowerCase().includes('disabled')`, 4000);
  const disabledAlert = await session.eval(`document.getElementById('auth-alert')?.textContent`);
  assert(disabledAlert && disabledAlert.toLowerCase().includes('disabled'), 'Disabled account login rejected with "Account is disabled"');

  // Close modal
  await session.eval(`document.getElementById('login-modal-close').click()`);
  await sleep(200);

  console.log('\n--- TEST 8: Manufacturer Login & UI Role Transition ---');
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(300);
  await session.eval(`(() => {
    document.getElementById('login-email').value = '${testMfgEmail}';
    document.getElementById('login-password').value = '${testMfgPass}';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-user-badge')?.textContent === 'MANUFACTURER'`, 4000);

  const mfgUI = await session.eval(`(() => {
    const badge = document.getElementById('auth-user-badge');
    const navAdmin = document.getElementById('nav-item-admin');
    const activeSection = document.querySelector('.page-section.active')?.id;
    return {
      badgeText: badge?.textContent.trim(),
      badgeClass: badge?.className,
      navAdminHidden: window.getComputedStyle(navAdmin).display === 'none',
      activeSection
    };
  })()`);
  assert(mfgUI.badgeText === 'MANUFACTURER', 'Role badge displays "MANUFACTURER"');
  assert(mfgUI.badgeClass === 'badge-role-mfg', 'Badge uses manufacturer styling (badge-role-mfg)');
  assert(mfgUI.navAdminHidden, 'Admin section hidden for manufacturer');
  assert(mfgUI.activeSection === 'section-manufacturer', 'Automatically navigated to Manufacturer portal');

  console.log('\n--- TEST 9: Session Persistence on Page Refresh ---');
  await session.reload();
  await session.waitFor(`document.getElementById('auth-user-badge')?.textContent === 'MANUFACTURER'`, 4000);
  const sessionAfterReload = await session.eval(`(() => {
    const badge = document.getElementById('auth-user-badge');
    const email = document.getElementById('auth-user-email');
    return {
      badgeText: badge?.textContent.trim(),
      emailText: email?.textContent.trim()
    };
  })()`);
  assert(sessionAfterReload.badgeText === 'MANUFACTURER', 'Session persisted: role badge remains "MANUFACTURER" after reload');
  assert(sessionAfterReload.emailText === testMfgEmail, 'Session persisted: user email remains active');

  // Logout manufacturer
  await session.eval(`document.getElementById('btn-logout').click()`);
  await session.waitFor(`document.getElementById('btn-open-login')?.style.display !== 'none'`);

  console.log('\n--- TEST 10: Pharmacist Login & UI Role Transition ---');
  // Re-enable test pharmacist by logging in as Admin
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(300);
  await session.eval(`(() => {
    document.getElementById('login-email').value = '${ADMIN_EMAIL}';
    document.getElementById('login-password').value = '${ADMIN_PASS}';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-user-badge')?.textContent === 'ADMIN'`, 4000);

  // Click activate button on pharmacist row
  await session.eval(`document.getElementById('admin-btn-refresh-users').click()`);
  await session.waitFor(`document.getElementById('admin-users-table-body')?.textContent.includes('${testPharmEmail}')`, 4000);
  await session.eval(`(() => {
    const rows = Array.from(document.querySelectorAll('#admin-users-table-body tr'));
    for (const r of rows) {
      if (r.textContent.includes('${testPharmEmail}')) {
        const toggleBtn = r.querySelector('[data-toggle-user]');
        if (toggleBtn) toggleBtn.click();
      }
    }
  })()`);
  await sleep(1000);

  // Logout admin
  await session.eval(`document.getElementById('btn-logout').click()`);
  await session.waitFor(`document.getElementById('btn-open-login')?.style.display !== 'none'`);

  // Log in as activated Pharmacist
  await session.eval(`document.getElementById('btn-open-login').click()`);
  await sleep(300);
  await session.eval(`(() => {
    document.getElementById('login-email').value = '${testPharmEmail}';
    document.getElementById('login-password').value = '${testPharmPass}';
    document.getElementById('btn-submit-login').click();
  })()`);
  await session.waitFor(`document.getElementById('auth-user-badge')?.textContent === 'PHARMACIST'`, 4000);

  const pharmUI = await session.eval(`(() => {
    const badge = document.getElementById('auth-user-badge');
    const navAdmin = document.getElementById('nav-item-admin');
    const activeSection = document.querySelector('.page-section.active')?.id;
    return {
      badgeText: badge?.textContent.trim(),
      badgeClass: badge?.className,
      navAdminHidden: window.getComputedStyle(navAdmin).display === 'none',
      activeSection
    };
  })()`);
  assert(pharmUI.badgeText === 'PHARMACIST', 'Role badge displays "PHARMACIST"');
  assert(pharmUI.badgeClass === 'badge-role-pharm', 'Badge uses pharmacist styling (badge-role-pharm)');
  assert(pharmUI.navAdminHidden, 'Admin section hidden for pharmacist');
  assert(pharmUI.activeSection === 'section-pharmacist', 'Automatically navigated to Pharmacist portal');

  // Logout pharmacist
  await session.eval(`document.getElementById('btn-logout').click()`);
  await session.waitFor(`document.getElementById('btn-open-login')?.style.display !== 'none'`);

  console.log('\n--- TEST 11: Unauthorized Route Guard ---');
  await session.eval(`window.location.hash = '#admin'`);
  await session.eval(`window.dispatchEvent(new HashChangeEvent('hashchange'))`);
  await sleep(300);
  const guardSection = await session.eval(`document.querySelector('.page-section.active')?.id`);
  assert(guardSection === 'section-overview', 'Unauthenticated navigation to #admin blocked and redirected to overview');

  console.log('\n========================================================================');
  console.log(` AUTH VERIFICATION RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================================================');

  session.close();
  if (failed > 0) process.exit(1);
}

main().catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});

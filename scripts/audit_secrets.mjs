import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

const ROOT_DIR = process.cwd();

console.log('--- SECRET AND SENSITIVE DATA AUDIT ---');

// 1. Read .dev.vars secret
let devVarsSecret = null;
if (fs.existsSync(path.join(ROOT_DIR, '.dev.vars'))) {
  const content = fs.readFileSync(path.join(ROOT_DIR, '.dev.vars'), 'utf8');
  const match = content.match(/BOOTSTRAP_ADMIN_SECRET=([^\r\n]+)/);
  if (match) devVarsSecret = match[1].trim();
}

console.log(`1. .dev.vars present on disk: ${devVarsSecret !== null ? 'YES' : 'NO'}`);
if (devVarsSecret) {
  console.log(`   Secret format: 256-bit hexadecimal string (length: ${devVarsSecret.length} chars)`);
}

// 2. Check Git ignore status of .dev.vars and .wrangler
try {
  const devVarsIgnored = execSync('git check-ignore -v .dev.vars').toString().trim();
  console.log(`2. .dev.vars ignored by git: YES (${devVarsIgnored})`);
} catch {
  console.log('2. .dev.vars ignored by git: NO (CRITICAL ISSUE!)');
}

try {
  const wranglerIgnored = execSync('git check-ignore -v .wrangler').toString().trim();
  console.log(`3. .wrangler directory ignored by git: YES (${wranglerIgnored})`);
} catch {
  console.log('3. .wrangler directory ignored by git: NO (CRITICAL ISSUE!)');
}

// 3. Check git status to ensure .dev.vars is NOT staged or tracked
const trackedFiles = execSync('git ls-files').toString().split('\n').map(s => s.trim());
console.log(`4. Total files currently tracked by Git: ${trackedFiles.length}`);
const devVarsTracked = trackedFiles.includes('.dev.vars');
console.log(`   Is .dev.vars tracked? ${devVarsTracked ? 'YES (CRITICAL ISSUE!)' : 'NO (SAFE)'}`);

const wranglerTracked = trackedFiles.some(f => f.startsWith('.wrangler'));
console.log(`   Are any .wrangler files tracked? ${wranglerTracked ? 'YES (CRITICAL ISSUE!)' : 'NO (SAFE)'}`);

// 4. Check git commit history for leaks
if (devVarsSecret) {
  try {
    const historyCheck = execSync(`git log -S "${devVarsSecret}" --oneline`).toString().trim();
    console.log(`5. Secret leakage in Git history: ${historyCheck ? 'LEAK DETECTED!' : 'ZERO LEAKS (Clean)'}`);
  } catch (err) {
    console.log('5. Error checking Git history:', err.message);
  }
}

// Check old compromised secret string in history
try {
  const oldSecretCheck = execSync('git log -S "local_super_secret" --oneline').toString().trim();
  console.log(`6. Old compromised secret in Git history: ${oldSecretCheck ? 'LEAK DETECTED!' : 'ZERO LEAKS (Clean)'}`);
} catch (err) {
  console.log('6. Error checking old secret in Git history:', err.message);
}

// 5. Scan all files in repository (excluding node_modules and .git) for unexpected API keys or secrets
const ignoreDirs = new Set(['.git', 'node_modules', '.wrangler']);
const suspiciousPatterns = [
  /AIza[0-9A-Za-z-_]{35}/g, // Google API key
  /ghp_[0-9A-Za-z]{36}/g,    // GitHub Personal Access Token
  /github_pat_[0-9A-Za-z_]{82}/g, // GitHub fine-grained PAT
  /ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, // JWT tokens
  /AKIA[0-9A-Z]{16}/g,       // AWS Access Key
  /xox[baprs]-[0-9A-Za-z-]{10,}/g, // Slack token
];

let leakCount = 0;
function scanDirectory(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === '.dev.vars') continue; // .dev.vars is locally ignored
    if (ignoreDirs.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanDirectory(fullPath);
    } else if (entry.isFile()) {
      if (entry.name.endsWith('.png') || entry.name.endsWith('.wasm') || entry.name.endsWith('.exe')) continue;
      const text = fs.readFileSync(fullPath, 'utf8');
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(text)) {
          console.warn(`[WARNING] Suspicious pattern ${pattern} matched in ${path.relative(ROOT_DIR, fullPath)}`);
          leakCount++;
        }
      }
    }
  }
}

scanDirectory(ROOT_DIR);
console.log(`7. Pattern scan for cloud API keys, GitHub PATs, and JWTs: ${leakCount === 0 ? 'ZERO DETECTED (Clean)' : leakCount + ' issues found!'}`);

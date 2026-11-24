const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const PLUGIN_SLUG = 'webcare-pro-security';
const PACKAGE_DIR = path.join(DIST_DIR, PLUGIN_SLUG);
const ZIP_FILE = path.join(ROOT_DIR, `${PLUGIN_SLUG}.zip`);

console.log('--- Packaging WebCare Pro Security & Firewall for WordPress.org ---');

// 0. Pre-Flight Manifest Uniformity Verification
execSync(`node "${path.join(__dirname, 'verify-manifests.js')}"`, { stdio: 'inherit' });

// 1. Clean dist directory and previous zip
if (fs.existsSync(DIST_DIR)) {
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
}
fs.mkdirSync(PACKAGE_DIR, { recursive: true });

if (fs.existsSync(ZIP_FILE)) {
  fs.unlinkSync(ZIP_FILE);
}

// 2. Define files and folders to include
const includeFiles = [
  'webcare-pro-security.php',
  'readme.txt',
  'uninstall.php',
];

const includeDirs = [
  'assets',
  'build',
  'includes',
  'languages',
];

// Helper to copy directory recursively, strictly ignoring dotfiles and dev files
function copyDirRecursive(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    // Strictly skip all hidden files/dirs (starting with '.')
    if (entry.name.startsWith('.')) {
      continue;
    }
    // Skip dev files, tests, map files if any
    const forbiddenNames = [
      'tests',
      'node_modules',
      'scratch',
      '.agents',
      '.gemini',
      'AGENTS.md',
      'compose.yaml',
      'phpunit.xml',
      'webcare_v325_production_signoff_plan.md',
    ];
    if (forbiddenNames.includes(entry.name) || entry.name.endsWith('.map')) {
      continue;
    }
    // WordPress.org Directory Assets Rule:
    // icon-*.png and banner-*.png belong only in the w.org SVN /assets root, NOT inside the plugin zip package
    if (src.includes('assets') && (/^icon-\d+x\d+\.png$/i.test(entry.name) || /^banner-\d+x\d+\.png$/i.test(entry.name))) {
      continue;
    }

    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDirRecursive(srcPath, destPath);
    } else {
      if (entry.name.endsWith('.asset.php')) {
        let content = fs.readFileSync(srcPath, 'utf8');
        if (content.charCodeAt(0) === 0xFEFF) {
          content = content.slice(1);
        }
        if (!content.includes('ABSPATH')) {
          content = content.replace(/^<\?php\s*/i, "<?php\nif ( ! defined( 'ABSPATH' ) ) {\n\texit;\n}\n\n");
        }
        fs.writeFileSync(destPath, content, { encoding: 'utf8' });
        fs.writeFileSync(srcPath, content, { encoding: 'utf8' });
      } else {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  }
}

// 3. Copy files
for (const file of includeFiles) {
  const src = path.join(ROOT_DIR, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, path.join(PACKAGE_DIR, file));
    console.log(`[Copied] ${file}`);
  } else {
    console.warn(`[Warning] Missing file: ${file}`);
  }
}

// 4. Copy folders
for (const dir of includeDirs) {
  const src = path.join(ROOT_DIR, dir);
  if (fs.existsSync(src)) {
    copyDirRecursive(src, path.join(PACKAGE_DIR, dir));
    console.log(`[Copied] ${dir}/`);
  } else {
    console.warn(`[Warning] Missing directory: ${dir}`);
  }
}

// 4.1 Generate Cryptographic Baseline Manifest for Plugin Self-Defense
console.log('\n--- Generating Cryptographic Self-Defense Manifest ---');
const crypto = require('crypto');

function computeManifestFiles(baseDir, currentDir = '') {
  let results = {};
  const entries = fs.readdirSync(path.join(baseDir, currentDir), { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    const rel = currentDir ? path.join(currentDir, entry.name) : entry.name;
    const full = path.join(baseDir, rel);
    if (entry.isDirectory()) {
      Object.assign(results, computeManifestFiles(baseDir, rel));
    } else {
      // Don't hash the manifest itself or zip archives
      if (rel.replace(/\\/g, '/') === 'includes/System/plugin-manifest.json' || rel.endsWith('.zip')) {
        continue;
      }
      const fileBuffer = fs.readFileSync(full);
      const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
      const normalizedKey = rel.replace(/\\/g, '/');
      results[normalizedKey] = {
        sha256: hash,
        size: fileBuffer.length,
      };
    }
  }
  return results;
}

const manifestData = {
  version: require(path.join(ROOT_DIR, 'package.json')).version || '1.20.0',
  generated_at: new Date().toISOString(),
  algorithm: 'sha256',
  files: computeManifestFiles(PACKAGE_DIR),
};

const manifestPath = path.join(PACKAGE_DIR, 'includes', 'System', 'plugin-manifest.json');
fs.writeFileSync(manifestPath, JSON.stringify(manifestData, null, 2), 'utf8');
// Also save into root source directory so it is present during development & docker copy
const rootManifestPath = path.join(ROOT_DIR, 'includes', 'System', 'plugin-manifest.json');
fs.writeFileSync(rootManifestPath, JSON.stringify(manifestData, null, 2), 'utf8');

console.log(`✓ Generated official manifest with ${Object.keys(manifestData.files).length} tracked files.`);

// 5. Verification checks
console.log('\n--- Running Validation Checks on Staged Package ---');

function scanForDotfiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith('.')) {
      throw new Error(`Forbidden hidden file found: ${path.join(dir, entry.name)}`);
    }
    if (entry.isDirectory()) {
      scanForDotfiles(path.join(dir, entry.name));
    }
  }
}
scanForDotfiles(PACKAGE_DIR);
console.log('✓ No hidden files found (clean of .gitignore, .git, etc.)');

// Verify languages folder is not empty
const langFiles = fs.readdirSync(path.join(PACKAGE_DIR, 'languages'));
if (langFiles.length === 0) {
  throw new Error('languages/ directory cannot be empty!');
}
console.log('✓ languages/ directory contains files:', langFiles.join(', '));

// Verify forbidden functions in staged files
function scanForForbiddenFunctions(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanForForbiddenFunctions(full);
    } else if (entry.name.endsWith('.php')) {
      const content = fs.readFileSync(full, 'utf8');
      // Strip comments and string literals to only check executable PHP function calls
      const executableCode = content
        .replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '')
        .replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, '');
      if (/\bstr_rot13\s*\(/i.test(executableCode)) {
        throw new Error(`Forbidden function str_rot13() found in: ${full}`);
      }
    }
  }
}
scanForForbiddenFunctions(PACKAGE_DIR);
console.log('✓ No forbidden functions (str_rot13) found');

// Verify WEBCAREPROSCAN_TESTING is never defined in release package
function scanForForbiddenConstants(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanForForbiddenConstants(full);
    } else if (entry.name.endsWith('.php')) {
      const content = fs.readFileSync(full, 'utf8');
      if (/define\s*\(\s*['"]WEBCAREPROSCAN_TESTING['"]/i.test(content)) {
        throw new Error(`Forbidden testing constant defined in production package: ${full}`);
      }
    }
  }
}
scanForForbiddenConstants(PACKAGE_DIR);
console.log('✓ No WEBCAREPROSCAN_TESTING constant defined in package');

// Verify unexpected root markdown files
const rootEntries = fs.readdirSync(PACKAGE_DIR);
for (const entry of rootEntries) {
  if (entry.endsWith('.md') && !['README.md', 'CHANGELOG.md'].includes(entry)) {
    throw new Error(`Unexpected markdown file in root: ${entry}`);
  }
}
console.log('✓ Root directory clean of unexpected markdown files');

// Verify Text Domain in webcare-pro-security.php
const mainPluginContent = fs.readFileSync(path.join(PACKAGE_DIR, 'webcare-pro-security.php'), 'utf8');
if (!/Text Domain:\s*webcare-pro-security/.test(mainPluginContent)) {
  throw new Error('Text Domain header does not match slug: webcare-pro-security');
}
console.log('✓ Text Domain header verified as webcare-pro-security');

// 6. Create ZIP archive with strict Unix permissions (0755 dirs, 0644 files)
console.log('\n--- Generating Release Archive with Unix Permissions ---');
const AdmZip = require('adm-zip');
const zip = new AdmZip();

function addFolderToZip(folderPath, zipPrefix) {
  const items = fs.readdirSync(folderPath);
  for (const item of items) {
    const fullPath = path.join(folderPath, item);
    const relZipPath = zipPrefix ? `${zipPrefix}/${item}` : item;
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      zip.addFile(`${relZipPath}/`, Buffer.alloc(0));
      addFolderToZip(fullPath, relZipPath);
    } else {
      zip.addLocalFile(fullPath, zipPrefix);
    }
  }
}

addFolderToZip(PACKAGE_DIR, PLUGIN_SLUG);

// Force standard Unix file attributes across all archive entries
for (const entry of zip.getEntries()) {
  if (entry.isDirectory) {
    // 0040755: Directory (0040000) with rwxr-xr-x (0755)
    entry.attr = ((0o040755 << 16) | 0x10) >>> 0;
  } else {
    // 0100644: Regular file (0100000) with rw-r--r-- (0644)
    entry.attr = (0o100644 << 16) >>> 0;
  }
}

zip.writeZip(ZIP_FILE);
console.log(`✓ Created: ${ZIP_FILE} (Strict Unix permissions: 0755 dirs, 0644 files)`);

// 6B. Automated post-package verification check: Ensure no forbidden dev/test paths exist in the zip
console.log('\n--- Running Automated Post-Package Zip Inspection ---');
const verifyZip = new AdmZip(ZIP_FILE);
const forbiddenPatterns = [
  /\/tests\//i,
  /\/src\//i,
  /\.map$/i,
  /phpunit\.xml/i,
  /compose\.yaml/i,
  /AGENTS\.md/i,
  /\/\.agents\//i,
  /composer\.json/i,
  /package\.json/i,
];

for (const entry of verifyZip.getEntries()) {
  const entryName = entry.entryName;
  for (const pattern of forbiddenPatterns) {
    if (pattern.test(entryName)) {
      throw new Error(`Forbidden file or directory detected in release archive: ${entryName}`);
    }
  }
}
console.log('✓ Release archive verified 100% clean of tests, source files, sourcemaps, and dev files.');

// Clean up staging folder
fs.rmSync(DIST_DIR, { recursive: true, force: true });
console.log('\n--- Staging directory cleaned up. Package is ready for WordPress.org upload! ---');

// 7. Update version.json with current release metadata
const versionJsonPath = path.join(ROOT_DIR, 'version.json');
try {
  let vData = {};
  if (fs.existsSync(versionJsonPath)) {
    vData = JSON.parse(fs.readFileSync(versionJsonPath, 'utf8'));
  }
  const currentVersion = manifestData.version;
  vData.version = currentVersion;
  vData.download_url = `https://raw.githubusercontent.com/WebCarePro/webcare-pro-security/main/${PLUGIN_SLUG}.zip`;
  vData.manifest_url = `https://raw.githubusercontent.com/WebCarePro/webcare-pro-security/main/includes/System/plugin-manifest.json`;
  vData.released_at = new Date().toISOString().split('T')[0];
  fs.writeFileSync(versionJsonPath, JSON.stringify(vData, null, 2), 'utf8');
  console.log(`✓ Synchronized version.json for version ${currentVersion}`);
} catch (e) {
  console.warn(`[Warning] Could not update version.json: ${e.message}`);
}


const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const tar = require('tar');

// Detect Platform and Architecture
const platform = process.env.TARGET_PLATFORM || process.platform; // darwin, linux, win32
const arch = process.env.TARGET_ARCH || process.arch; // arm64, x64

const PLATFORM_MAP = {
  'darwin-arm64': 'mac-arm64',
  'darwin-x64': 'mac-x64',
  'linux-x64': 'linux-x64',
  'win32-x64': 'win-x64'
};

const currentTarget = `${platform}-${arch}`;
const remoteSubDir = PLATFORM_MAP[currentTarget] || 'mac-arm64';

console.log(`[System] Identity: ${currentTarget} -> Mapping to: ${remoteSubDir}`);

const TARGETS = {
  tor: {
    url: `https://raw.githubusercontent.com/KYC-rip/wallet-binaries/main/${remoteSubDir}/tor-bundle.tar.gz`,
    hash: {
      'mac-arm64': '40ae11c3ec51d5d83d3208df6681e2142bd3cda1032d340e36fb0ee77d2cb818',
      'mac-x64': '0300f1a60d0a1925e98d7666a7dc9101d0c7b5dafbe195e876d865f1358bfebf',
      'linux-x64': 'c421c7990e4a17df8269d680bdb8860d3cf1c77911ff5be5a874eb22ae08cc1c',
      'win-x64': '3defe0489e5979568239114e97b2a421b91d430032a273dd278b4af06b9329a9'
    }[remoteSubDir] || '40ae11c3ec51d5d83d3208df6681e2142bd3cda1032d340e36fb0ee77d2cb818',
    folder: 'tor-bundle'
  },
  rpc: {
    url: `https://raw.githubusercontent.com/KYC-rip/wallet-binaries/main/${remoteSubDir}/monero-rpc.tar.gz`,
    hash: {
      'mac-arm64': '0dbbab8147e3c6523c60ce5a62d35e3899606c727b7a2752c492f5fa8d07b3db',
      'mac-x64': 'fbd617be574886d275c47428bcf4bed9242b00695018fbe788e4860083e6ad8a',
      'linux-x64': '2c5e8f97d44bad338513a02b43fee919f93ac7bedfd1611dbb411b8731d3ddc7',
      'win-x64': '4d8c6280b5315dfd336d21292e3d66b781102c38bce58063701592dd82f4e872'
    }[remoteSubDir] || '0dbbab8147e3c6523c60ce5a62d35e3899606c727b7a2752c492f5fa8d07b3db',
    folder: 'rpc-core'
  },
  // FCMP++/CARROT beta stressnet wallet-rpc (seraphis-migration build).
  // OPTIONAL: missing artifacts must never fail a mainnet build -- the
  // capability manifest simply hides stressnet mode on this platform.
  // 'TBD' hash = binaries not yet published for that platform.
  rpcStressnet: {
    url: `https://raw.githubusercontent.com/KYC-rip/wallet-binaries/main/${remoteSubDir}/monero-rpc-stressnet.tar.gz`,
    hash: {
      'mac-arm64': 'TBD',
      'mac-x64': 'TBD',
      'linux-x64': 'TBD',
      'win-x64': 'TBD'
    }[remoteSubDir] || 'TBD',
    folder: 'rpc-stressnet',
    optional: true
  },
};

const BIN_DIR = path.join(__dirname, '../resources/bin');
async function downloadAndExtractTarGz(name, url, expectedTarHash, destSubDir) {
  console.log(`\n[Armory] Processing: ${name}`);

  // Ensure binary directory exists before any FS operations
  if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });

  const destFolder = path.join(BIN_DIR, destSubDir);
  const tempTarFile = path.join(BIN_DIR, `temp_${Date.now()}.tar.gz`);
  const lockFilePath = path.join(destFolder, '.version.lock');

  const tempFiles = fs.readdirSync(BIN_DIR).filter(file => file.startsWith('temp_') && file.endsWith('.tar.gz'));
  tempFiles.forEach(file => fs.unlinkSync(path.join(BIN_DIR, file)));

  // 🛡️ Cache Hit Detection
  if (fs.existsSync(destFolder) && fs.existsSync(lockFilePath)) {
    const cachedHash = fs.readFileSync(lockFilePath, 'utf-8').trim();
    if (cachedHash === expectedTarHash) {
      console.log(`  [HIT] Cache verified for ${name}. Skipping download.`);
      return;
    } else {
      console.log(`  [MISS] Version mismatch. Cleaning up old files...`);
    }
  }

  // Ensure destination folder exists and is clean
  if (fs.existsSync(destFolder)) fs.rmSync(destFolder, { recursive: true, force: true });
  fs.mkdirSync(destFolder, { recursive: true });

  try {
    console.log(`  [DOWNLOADING] Fetching tarball from: ${url}`);

    await new Promise((resolve, reject) => {
      const download = (downloadUrl) => {
        https.get(downloadUrl, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            return download(res.headers.location);
          }
          if (res.statusCode !== 200) {
            return reject(new Error(`Failed to download: ${res.statusCode}`));
          }

          const writer = fs.createWriteStream(tempTarFile);
          res.pipe(writer);
          writer.on('finish', resolve);
          writer.on('error', reject);
        }).on('error', reject);
      };
      download(url);
    });

    console.log(`  [AUDIT] Calculating SHA256...`);
    const downloadedHash = await calculateHash(tempTarFile);
    if (downloadedHash !== expectedTarHash) {
      throw new Error(`Hash mismatch! Expected: ${expectedTarHash}, Got: ${downloadedHash}`);
    }

    console.log(`  [EXTRACTING] Unpacking files...`);
    await tar.x({ file: tempTarFile, cwd: destFolder });

    if (process.platform === 'darwin') {
      const { execSync } = require('child_process');
      try {
        console.log(`  [SECURITY] Bypassing macOS Gatekeeper quarantine...`);
        execSync(`xattr -cr "${destFolder}"`);
      } catch (xattrErr) {
        console.warn(`  [WARNING] Failed to remove quarantine attribute: ${xattrErr.message}`);
      }
    }

    // 🔒 Write the lockfile for future cache hits
    fs.writeFileSync(lockFilePath, expectedTarHash, 'utf-8');

    fs.unlinkSync(tempTarFile);
    console.log(`  [SUCCESS] ${name} deployed.`);

  } catch (error) {
    if (fs.existsSync(tempTarFile)) fs.unlinkSync(tempTarFile);
    throw new Error(`Deployment failed: ${error.message}`);
  }
}

// Helper functions
function calculateHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// ---------------------------------------------------------
// 🚀 Initialization Sequence
// ---------------------------------------------------------
async function main() {
  console.log(`=== 💀 KYC.RIP Hardcore Build Sequence Initiated ===`);

  try {
    // Concurrent Assembly
    await Promise.all([
      downloadAndExtractTarGz('Tor Obfuscated Bundle', TARGETS.tor.url, TARGETS.tor.hash, TARGETS.tor.folder),
      downloadAndExtractTarGz('Monero Lone Wolf Engine', TARGETS.rpc.url, TARGETS.rpc.hash, TARGETS.rpc.folder)
    ]);

    // Optional stressnet engine: tolerate-missing, record capability
    let stressnet = false;
    if (TARGETS.rpcStressnet.hash !== 'TBD') {
      try {
        await downloadAndExtractTarGz('FCMP++ Stressnet Engine', TARGETS.rpcStressnet.url, TARGETS.rpcStressnet.hash, TARGETS.rpcStressnet.folder);
        stressnet = true;
      } catch (err) {
        console.warn(`  [OPTIONAL] Stressnet engine unavailable for ${remoteSubDir} (${err.message}). Feature will be hidden.`);
      }
    } else {
      console.warn(`  [OPTIONAL] Stressnet binaries not yet published for ${remoteSubDir}. Feature will be hidden.`);
    }
    fs.writeFileSync(path.join(BIN_DIR, 'capabilities.json'), JSON.stringify({ stressnet }), 'utf8');

    console.log(`\n=== 🟢 Armory assembled. Ready for React rendering layer! ===\n`);
  } catch (err) {
    console.error(`\n🔴 Critical Build Error:`, err.message);
    process.exit(1);
  }
}

main();
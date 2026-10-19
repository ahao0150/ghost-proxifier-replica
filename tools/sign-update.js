#!/usr/bin/env node
// Sign an update manifest with the replica's ECDSA P-256 keys.
// Usage: node tools/sign-update.js update/personal.json
// Produces personal.json.sig: { cert, certSig, sig } (base64).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const manifestPath = process.argv[2];
if (!manifestPath) {
  console.error('usage: node tools/sign-update.js <personal.json>');
  process.exit(1);
}
const root = path.join(__dirname, '..');
const manifest = fs.readFileSync(manifestPath); // raw bytes, do not re-serialize
const appKey = fs.readFileSync(path.join(root, 'update', 'app-key.pem'));
const appCert = fs.readFileSync(path.join(root, 'update', 'app-cert.der'));
const rootKey = fs.readFileSync(path.join(root, 'update', 'root-key.pem'));

let json;
try {
  json = JSON.parse(manifest.toString('utf8'));
} catch (e) {
  console.error('manifest is not valid JSON:', e.message);
  process.exit(1);
}
for (const k of ['sku', 'version', 'url', 'size', 'sha256']) {
  if (!(k in json)) {
    console.error(`manifest missing field: ${k}`);
    process.exit(1);
  }
}
if (!/^[a-f0-9]{64}$/.test(String(json.sha256))) {
  console.error('sha256 must be 64 lowercase hex characters');
  process.exit(1);
}

const sig = crypto.sign('sha256', manifest, appKey).toString('base64');
const certSig = crypto.sign('sha256', appCert, rootKey).toString('base64');
const out = {
  cert: appCert.toString('base64'),
  certSig,
  sig,
};
fs.writeFileSync(manifestPath + '.sig', JSON.stringify(out));
console.log('signed:', manifestPath + '.sig');

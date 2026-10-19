// Build a local signed update manifest for testing.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const zip = path.resolve(__dirname, '..', 'update', 'test-package.zip');
const manifestPath = path.resolve(__dirname, '..', 'update', 'personal.json');
const data = fs.readFileSync(zip);
const manifest = {
  sku: 'personal',
  version: process.argv[2] || '1.0.1',
  url: zip,
  size: data.length,
  sha256: crypto.createHash('sha256').update(data).digest('hex'),
  notesUrl: 'https://example.com/releases',
};
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
console.log(JSON.stringify(manifest, null, 2));

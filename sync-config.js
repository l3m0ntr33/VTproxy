#!/usr/bin/env node
/**
 * Sync configuration across all project files
 * Run this whenever you update app.config.json
 */

const fs = require('fs');
const path = require('path');

// Load shared config
const config = JSON.parse(fs.readFileSync('app.config.json', 'utf8'));

console.log('🔄 Syncing configuration...\n');

// 1. Update package.json
const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
packageJson.name = config.name;
packageJson.version = config.version;
packageJson.description = `Client-side ${config.description} with Tauri desktop app support`;
packageJson.author = config.author;
packageJson.license = config.license;
fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2) + '\n');
console.log('✅ Updated package.json');

// 2. Update package-lock.json (sync version and name)
if (fs.existsSync('package-lock.json')) {
  const packageLock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
  packageLock.name = config.name;
  packageLock.version = config.version;
  // Also update in packages section if it exists
  if (packageLock.packages && packageLock.packages['']) {
    packageLock.packages[''].name = config.name;
    packageLock.packages[''].version = config.version;
  }
  fs.writeFileSync('package-lock.json', JSON.stringify(packageLock, null, 2) + '\n');
  console.log('✅ Updated package-lock.json');
}

// 3. Update Cargo.toml
let cargoToml = fs.readFileSync('src-tauri/Cargo.toml', 'utf8');
cargoToml = cargoToml.replace(/^name = ".*"$/m, `name = "${config.name}"`);
cargoToml = cargoToml.replace(/^version = ".*"$/m, `version = "${config.version}"`);
cargoToml = cargoToml.replace(/^description = ".*"$/m, `description = "VTproxy - ${config.description}"`);
cargoToml = cargoToml.replace(/^authors = \[.*\]$/m, `authors = ["${config.author}"]`);
cargoToml = cargoToml.replace(/^license = ".*"$/m, `license = "${config.license}"`);
fs.writeFileSync('src-tauri/Cargo.toml', cargoToml);
console.log('✅ Updated Cargo.toml');

// 4. Update tauri.conf.json
const tauriConf = JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json', 'utf8'));
tauriConf.package.productName = config.productName;
tauriConf.package.version = config.version;
tauriConf.tauri.bundle.identifier = config.identifier;
tauriConf.tauri.bundle.copyright = config.copyright;
tauriConf.tauri.bundle.category = config.category;
tauriConf.tauri.bundle.shortDescription = config.shortDescription;
tauriConf.tauri.bundle.longDescription = config.longDescription;
tauriConf.tauri.windows[0].title = config.windowTitle;
fs.writeFileSync('src-tauri/tauri.conf.json', JSON.stringify(tauriConf, null, 2) + '\n');
console.log('✅ Updated tauri.conf.json');

console.log('\n✨ Configuration synced successfully!\n');
console.log('📝 To update values, edit app.config.json and run: npm run sync-config\n');

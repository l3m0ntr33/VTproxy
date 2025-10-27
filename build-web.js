#!/usr/bin/env node
// Build script - copies web assets to dist folder
// Cross-platform compatible (Windows, Linux, macOS)

const fs = require('fs');
const path = require('path');

console.log('📦 Preparing web assets for build...');

const distDir = path.join(__dirname, 'dist');

// Remove old dist directory if it exists
if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
}

// Create dist directory
fs.mkdirSync(distDir, { recursive: true });

// Helper function to copy files or directories
function copyRecursive(src, dest) {
    const stats = fs.statSync(src);
    
    if (stats.isDirectory()) {
        // Create directory if it doesn't exist
        if (!fs.existsSync(dest)) {
            fs.mkdirSync(dest, { recursive: true });
        }
        
        // Copy all contents
        const items = fs.readdirSync(src);
        items.forEach(item => {
            const srcPath = path.join(src, item);
            const destPath = path.join(dest, item);
            copyRecursive(srcPath, destPath);
        });
    } else {
        // Copy file
        fs.copyFileSync(src, dest);
    }
}

// Copy web assets
const assetsToCopy = [
    { src: 'css', dest: path.join(distDir, 'css') },
    { src: 'js', dest: path.join(distDir, 'js') },
    { src: 'index.html', dest: path.join(distDir, 'index.html') },
    { src: 'result.html', dest: path.join(distDir, 'result.html') },
    { src: 'cert_blason.webp', dest: path.join(distDir, 'cert_blason.webp') }
];

assetsToCopy.forEach(({ src, dest }) => {
    const srcPath = path.join(__dirname, src);
    if (fs.existsSync(srcPath)) {
        copyRecursive(srcPath, dest);
        console.log(`✓ Copied ${src}`);
    } else {
        console.warn(`⚠ Warning: ${src} not found, skipping...`);
    }
});

console.log('✅ Web assets ready in dist/');

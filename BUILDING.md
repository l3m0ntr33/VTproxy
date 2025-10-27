# Building VTproxy from Source

A comprehensive step-by-step guide for building VTproxy desktop app on **Ubuntu** and **Windows**.

---

## 📖 Table of Contents

- [Ubuntu Build Guide](#-ubuntu-build-guide)
- [Windows Build Guide](#-windows-build-guide)
- [After Building](#-after-building)
- [Troubleshooting](#-troubleshooting)
- [Advanced Topics](#-advanced-topics)

---

# 🐧 Ubuntu Build Guide

## Step 1: Install Prerequisites

### 1.1 Update System
```bash
sudo apt update
sudo apt upgrade -y
```

### 1.2 Install Rust

```bash
# Download and install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# When prompted, choose option 1 (default installation)
# After installation completes:
source "$HOME/.cargo/env"

# Verify installation
rustc --version
cargo --version
```

You should see something like:
```
rustc 1.75.0 (or newer)
cargo 1.75.0 (or newer)
```

### 1.3 Install Node.js and npm

**Option A: Using apt (simpler, might be older version)**
```bash
sudo apt install -y nodejs npm
node --version
npm --version
```

**Option B: Using nvm (recommended, latest version)**
```bash
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Reload shell configuration
source ~/.bashrc

# Install latest LTS Node.js
nvm install --lts

# Verify
node --version
npm --version
```

### 1.4 Install Tauri System Dependencies

These libraries are required for Tauri to build:

```bash
sudo apt install -y \
    libgtk-3-dev \
    libwebkit2gtk-4.0-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    build-essential \
    curl \
    wget \
    file
```

**Verify installation:**
```bash
pkg-config --modversion gtk+-3.0
# Should show GTK version (e.g., 3.24.33)
```

---

## Step 2: Get the Source Code

### Option A: Using Git (Recommended)
```bash
# Install git if not already installed
sudo apt install -y git

# Clone the repository
git clone https://github.com/l3m0ntr33/VTproxy.git
cd VTproxy
```

### Option B: Download ZIP
```bash
# Download and extract
wget https://github.com/l3m0ntr33/VTproxy/archive/refs/heads/main.zip
unzip main.zip
cd VTproxy-main
```

---

## Step 3: Install Dependencies

```bash
# Make sure you're in the VTproxy directory
cd VTproxy  # or VTproxy-main if you downloaded ZIP

# Install npm dependencies
npm install
```

This will install Tauri CLI and other required packages. Takes about 1-2 minutes.

---

## Step 4: Build the Desktop App

### Development Build (for testing)

```bash
# Start development server with hot-reload
npm run dev
```

**What happens:**
- First build takes **5-10 minutes** (Rust compilation)
- A window will open with VTproxy running
- Changes to code will auto-reload
- Press `Ctrl+C` to stop

### Production Build (for distribution)

```bash
# Build optimized release version
npm run build
```

**What happens:**
- Takes **5-10 minutes** to compile
- Creates installable packages
- No console output in final app

**Find your built apps at:**
```bash
# AppImage (portable, no installation needed)
src-tauri/target/release/bundle/appimage/vtproxy_0.0.1_amd64.AppImage

# DEB package (for Ubuntu/Debian)
src-tauri/target/release/bundle/deb/vtproxy_0.0.1_amd64.deb

# RPM package (for Fedora/RedHat)
src-tauri/target/release/bundle/rpm/vtproxy-0.0.1-1.x86_64.rpm
```

---

## Step 5: Run Your Built App

### Option A: Run AppImage (No Installation)
```bash
# Make it executable
chmod +x src-tauri/target/release/bundle/appimage/vtproxy_*.AppImage

# Run it
./src-tauri/target/release/bundle/appimage/vtproxy_*.AppImage
```

### Option B: Install DEB Package
```bash
# Install system-wide
sudo dpkg -i src-tauri/target/release/bundle/deb/vtproxy_*.deb

# Run from anywhere
vtproxy

# Or find it in your application menu
```

### Option C: Run from Source (Development)
```bash
# Run without building installer
npm run dev
```

---

# 🪟 Windows Build Guide

## Step 1: Install Prerequisites

### 1.1 Install Microsoft Visual Studio C++ Build Tools

Tauri requires Microsoft C++ build tools.

**Download and Install:**
1. Visit: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Download "Build Tools for Visual Studio 2022"
3. Run the installer
4. Select "Desktop development with C++"
5. Click Install (requires ~7 GB disk space)
6. Restart computer after installation

### 1.2 Install Rust

**Download Rust:**
1. Visit: https://rustup.rs/
2. Download `rustup-init.exe`
3. Run the installer
4. Choose option 1 (default installation)
5. Wait for installation to complete

**Verify installation:**
```powershell
# Open PowerShell and check:
rustc --version
cargo --version
```

You should see version numbers like `rustc 1.75.0`.

### 1.3 Install Node.js

**Download Node.js:**
1. Visit: https://nodejs.org/
2. Download "LTS" version (e.g., Node.js 20.x)
3. Run the installer
4. Accept all defaults
5. Finish installation

**Verify installation:**
```powershell
# Open PowerShell (or Command Prompt) and check:
node --version
npm --version
```

You should see version numbers like `v20.11.0` and `10.2.4`.

### 1.4 Install Git (Optional but Recommended)

**Download Git:**
1. Visit: https://git-scm.com/download/win
2. Download the installer
3. Run installer with default options

**Verify:**
```powershell
git --version
```

---

## Step 2: Get the Source Code

### Option A: Using Git
```powershell
# Open PowerShell in your desired folder (e.g., Documents)
cd $HOME\Documents

# Clone repository
git clone https://github.com/l3m0ntr33/VTproxy.git
cd VTproxy
```

### Option B: Download ZIP
1. Visit: https://github.com/l3m0ntr33/VTproxy
2. Click "Code" → "Download ZIP"
3. Extract to a folder (e.g., `C:\Users\YourName\Documents\VTproxy`)
4. Open PowerShell in that folder:
   ```powershell
   cd $HOME\Documents\VTproxy
   ```

---

## Step 3: Install Dependencies

```powershell
# Make sure you're in the VTproxy directory
cd VTproxy  # Adjust path if needed

# Install npm dependencies
npm install
```

**If you get an error** about execution policy:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
npm install
```

This installs Tauri CLI and dependencies. Takes 1-2 minutes.

---

## Step 4: Build the Desktop App

### Development Build (for testing)

```powershell
# Start development server with hot-reload
npm run dev
```

**What happens:**
- First build takes **10-15 minutes** on Windows (Rust compilation is slower)
- A window opens with VTproxy running
- Console will show build progress
- Press `Ctrl+C` to stop

**Common first-time issues:**
- Windows Defender may scan files (slows down build)
- Antivirus may quarantine executables (add exception for `VTproxy` folder)

### Production Build (for distribution)

```powershell
# Build optimized release version
npm run build
```

**What happens:**
- Takes **10-15 minutes** to compile
- Creates Windows installers
- Final build is optimized and small

**Find your built apps at:**
```powershell
# MSI installer
src-tauri\target\release\bundle\msi\vtproxy_0.0.1_x64_en-US.msi

# EXE installer  
src-tauri\target\release\bundle\nsis\vtproxy_0.0.1_x64-setup.exe

# Standalone executable
src-tauri\target\release\vtproxy.exe
```

---

## Step 5: Run Your Built App

### Option A: Install MSI
```powershell
# Double-click the MSI file or run:
.\src-tauri\target\release\bundle\msi\vtproxy_*_x64_en-US.msi

# Then find "VTproxy" in Start Menu
```

### Option B: Run Standalone EXE
```powershell
# Run directly without installation
.\src-tauri\target\release\vtproxy.exe
```

### Option C: Run from Source (Development)
```powershell
npm run dev
```

---

# 🎉 After Building

## Using Your Built App

1. **Launch the app**
2. **Click the API key button** (top-right)
3. **Paste your VirusTotal API key** from https://www.virustotal.com/gui/my-apikey
4. **Start searching!**

## Sharing Your Build

You can share the built installers with others:

**Ubuntu/Linux:**
- Share `.AppImage` file (works on most distros without installation)
- Share `.deb` file (for Debian/Ubuntu users)

**Windows:**
- Share `.msi` or `.exe` installer
- Users can install with one click

**File sizes:**
- Linux AppImage: ~73 MB
- Linux .deb: ~4 MB (compressed)
- Windows .msi: ~5-8 MB
- Windows .exe: ~5-8 MB

Much smaller than Electron apps!

---

# 🐛 Troubleshooting

## Ubuntu Issues

### Error: "cargo not found"
```bash
# Reload Rust environment
source "$HOME/.cargo/env"

# Add to ~/.bashrc to make permanent:
echo 'source "$HOME/.cargo/env"' >> ~/.bashrc
```

### Error: "failed to run custom build command for ..."
```bash
# Missing system libraries, reinstall them:
sudo apt install -y libgtk-3-dev libwebkit2gtk-4.0-dev \
    libayatana-appindicator3-dev librsvg2-dev build-essential
```

### Error: "No package 'webkit2gtk-4.0' found"
```bash
# Install webkit separately:
sudo apt install -y libwebkit2gtk-4.0-dev
```

### Build takes forever / hangs
- First build is always slow (5-10 mins)
- Check RAM usage: Rust compilation needs ~2GB RAM
- Try closing other applications

### App builds but won't start
```bash
# Check for errors:
RUST_BACKTRACE=1 ./src-tauri/target/release/vtproxy

# Or run from bundle:
./src-tauri/target/release/bundle/appimage/vtproxy_*.AppImage
```

---

## Windows Issues

### Error: "link.exe not found"
**Solution:** Install Visual Studio C++ Build Tools (see Step 1.1)

### Error: "npm install" fails with permission error
```powershell
# Run PowerShell as Administrator, then:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Error: "rustc not found"
**Solution:** Restart PowerShell/Command Prompt after installing Rust

### Build extremely slow (>20 minutes)
- Disable Windows Defender real-time protection temporarily
- Add VTproxy folder to antivirus exclusions
- Close other applications (Rust compilation needs RAM)

### App won't start / "Windows protected your PC"
- Click "More info" → "Run anyway"
- Or: Right-click `.exe` → Properties → Unblock → Apply

### Error: "unable to get local issuer certificate"
```powershell
# Behind corporate firewall? Set up proxy:
npm config set strict-ssl false
npm install
```

---

## Common Issues (Both Platforms)

### "npm install" fails
```bash
# Clear npm cache and retry:
npm cache clean --force
rm -rf node_modules package-lock.json  # or del /s on Windows
npm install
```

### First build takes very long
- **This is normal!** First Rust build compiles hundreds of dependencies
- Ubuntu: ~5-10 minutes
- Windows: ~10-15 minutes  
- Subsequent builds are much faster (1-2 minutes)

### Hot-reload not working in dev mode
- Save files explicitly in your editor
- Restart dev server: `Ctrl+C` then `npm run dev`

### Out of disk space
- Rust builds need ~2-3 GB
- Clean old builds: `cargo clean` (in src-tauri directory)

---

# 🔧 Advanced Topics

## Updating Version Number

Edit `app.config.json`:
```json
{
  "version": "0.0.2",
  ...
}
```

Then sync to all files:
```bash
npm run sync-config
npm run build
```

## Build Sizes

Control bundle size in `src-tauri/Cargo.toml`:

```toml
[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Link-time optimization
codegen-units = 1   # Better optimization
strip = true        # Remove debug symbols
```

## Custom Build Features

Skip certain bundle formats:

**Ubuntu - Build only AppImage:**
```bash
# Edit src-tauri/tauri.conf.json
# Set "targets": ["appimage"]
npm run build
```

**Windows - Build only MSI:**
```bash
# Edit src-tauri/tauri.conf.json  
# Set "targets": ["msi"]
npm run build
```

## Cross-Platform Builds

To build for multiple platforms automatically, use GitHub Actions:

1. Push code to GitHub
2. Create a tag: `git tag v0.0.1 && git push origin v0.0.1`
3. GitHub Actions builds Windows + Linux + macOS automatically
4. Find installers in GitHub Releases

See `.github/workflows/release.yml` for configuration.

---

## Code Structure

```
VTproxy/
├── index.html              # Main page
├── result.html             # Results page
├── css/                    # Stylesheets
│   ├── main.css
│   ├── components.css
│   └── responsive.css
├── js/                     # JavaScript (ES6 modules)
│   ├── main.js            # Entry point
│   ├── api/               # API calls
│   ├── ui/                # UI components
│   └── utils/             # Utilities
├── src-tauri/             # Rust backend
│   ├── src/
│   │   └── main.rs       # Tauri backend code
│   ├── Cargo.toml        # Rust dependencies
│   └── tauri.conf.json   # Tauri configuration
├── package.json           # Node dependencies
└── app.config.json        # Centralized config
```

## Development Workflow

1. **Make changes** to HTML/CSS/JS files
2. **Test in browser**: `python3 -m http.server 8000`
3. **Test in desktop**: `npm run dev`
4. **Build release**: `npm run build`
5. **Test installers** before distributing

---

## 📚 Additional Resources

- **Tauri Documentation**: https://tauri.app/
- **Rust Book**: https://doc.rust-lang.org/book/
- **VirusTotal API Docs**: https://docs.virustotal.com/reference/overview
- **Project Issues**: https://github.com/l3m0ntr33/VTproxy/issues

---

## 🤝 Contributing

Want to contribute? Great!

1. Fork the repository
2. Build and test locally (follow this guide)
3. Make your changes
4. Test thoroughly (browser + desktop)
5. Update version in `app.config.json`
6. Run `npm run sync-config`
7. Submit a Pull Request

---

**Happy building! 🚀**

If you encounter issues not covered here, please [open an issue](https://github.com/l3m0ntr33/VTproxy/issues) on GitHub.

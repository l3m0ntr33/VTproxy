# VTproxy 🛡️

> **BETA VERSION** - Early release, features and functionality may change

A lightweight VirusTotal interface that helps you **preserve your precious Intelligence search quota** while analyzing files, URLs, domains, and IPs.

## 🎯 Why VTproxy?

### The Problem with VirusTotal's Web Interface

VirusTotal's **Intelligence search** is a powerful premium feature, but it comes with a **limited monthly quota** (typically 10-20 searches/month depending on your subscription). 

**The issue:** Every time you use the VT website's search bar — even for simple lookups like a single domain, file hash, URL, or IP — **it consumes 1 Intelligence search quota**. This happens whether you're doing a basic lookup or an advanced query with [VT Intelligence modifiers](https://raw.githubusercontent.com/Neo23x0/vti-dorks/refs/heads/master/README.md).

This is wasteful when you just want to check a single indicator without using advanced search features.

### The VTproxy Solution

**VTproxy lets you perform simple lookups using your API quota instead of Intelligence search quota:**

- ✅ **Direct VT links** option to open results in VirusTotal without any quota consumption
- ✅ **Preserve Intelligence searches** for when you really need advanced queries
- ✅ **Use your abundant API quota** (much higher daily limit, especially with premium)
- ✅ **Get detailed API responses** with technical data sometimes not shown on the VT website

**Three deployment options:**

- **🌐 Hosted Version** - [Try it now](https://research.cert.orangecyberdefense.com/vt_proxy) hosted by Orange Cyberdefense CERT
  - No installation needed, works anywhere
  - Direct VT links only (no API calls due to CORS)
  - **Zero quota consumption**
- **💻 Desktop App** - Native application with no CORS restrictions
  - Full API access and VT direct links
  - Works offline, native performance
- **🏠 Browser Version (Localhost)** - Run locally on your machine
  - Full API access and VT direct links
  - Requires local web server

**Additional benefits:**
- 🔒 **Privacy-first**: API key stored locally, never leaves your device
- 🎨 **Modern dark UI** with clean design and responsive layout
- ⚡ **Fast & lightweight**: Desktop app is only ~5MB!

Perfect for security analysts, researchers, and anyone who regularly checks indicators without wanting to waste their Intelligence search quota.

## ✨ Key Features

### 🎨 User Experience
- **🔍 Smart Input Detection** - Automatically detects if you're searching for a file hash, URL, domain, or IP
- **🌙 Modern Dark Theme** - Easy on the eyes with custom orange accents
- **📱 Fully Responsive** - Works seamlessly on desktop, tablet, and mobile
- **⚡ Fast & Lightweight** - No build process, instant loading, static files
- **🔒 Privacy First** - Your API key is stored locally and never leaves your device
- **⌨️ Keyboard Shortcuts** - Press Enter to search or open directly in VirusTotal
- **💾 Flexible Deployment** - Hosted version, desktop app, or run locally

## 🚀 Quick Start

### Option 1: 🌐 Use Hosted Version (Easiest)

**Just click and go:** [https://research.cert.orangecyberdefense.com/vt_proxy](https://research.cert.orangecyberdefense.com/vt_proxy)

- ✅ No installation needed
- ✅ Works on any device
- ⚠️ **Limitation:** Direct VT links only (no API calls due to CORS)
- ✅ **Zero quota consumption**

---

### Option 2: 💻 Download Desktop App

**Full features with API access!**

Download the app for your operating system from [GitHub Releases](https://github.com/l3m0ntr33/VTproxy/releases):

**Linux:**
```bash
# Download the AppImage or .deb from releases
chmod +x vtproxy_*.AppImage
./vtproxy_*.AppImage

# Or install .deb
sudo dpkg -i vtproxy_*.deb
vtproxy
```

**Windows:**
```bash
# Download the .msi or .exe installer from releases
# Double-click to install and run
```

**macOS:**
```bash
# Download the .dmg from releases
# Drag to Applications folder
```

✅ Full API access + Direct VT links
✅ No CORS restrictions

---

### Option 3: 🏠 Run Locally (For Developers)

**Clone the repository and start a local web server:**

```bash
# Clone the repo
git clone https://github.com/l3m0ntr33/VTproxy.git
cd VTproxy
```

**Linux/macOS:**
```bash
# Using Python
python3 -m http.server 8000

# Or using PHP
php -S localhost:8000
```

**Windows:**
```powershell
# Using Python
python -m http.server 8000

# Or using npm http-server
npx http-server -p 8000
```

Then open: **http://localhost:8000**

✅ Full API access + Direct VT links
⚠️ Only works on localhost

---

### 🔑 Configure Your API Key (Options 2 & 3)

1. Get your VirusTotal API key from [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
2. In VTproxy, click the **🔑 API key** button (top-right corner)
3. Paste your API key and click **Save**

**That's it!** Start searching for files, URLs, domains, or IP addresses.

> 💡 **Note:** Option 1 (hosted version) doesn't need an API key - it uses direct VT links only.

> 🔨 **Want to build from source?** See [BUILDING.md](BUILDING.md) for development instructions.

## 🔒 Privacy & Security

- ✅ **No backend server** - Runs entirely in your browser
- ✅ **No telemetry** - We don't track or collect any data
- ✅ **Local storage only** - Your API key stays on your device
- ✅ **Open source** - Audit the code yourself
- ✅ **Direct API calls** - Communication only with VirusTotal

⚠️ **Note:** Anyone with access to your browser's localStorage can see your stored API key. Use browser profiles or incognito mode if sharing your device.

## 📊 API Rate Limits

Your rate limits depend on your VirusTotal account type:

**Free Account:**
- 4 requests per minute
- 500 requests per day
- ⚠️ **Limited features**: Some API endpoints are restricted to premium users only

**Premium Account:**
- Higher limits based on your plan
- ✅ **Full access**: All API endpoints and advanced features available
- See [VirusTotal pricing](https://www.virustotal.com/gui/services-overview) for details

> 💡 **Note:** If you have a free API key, some VTproxy features may not work as they require premium API endpoints (e.g., certain relationship data, advanced analysis). The core functionality (file/URL/domain/IP lookups) works with free accounts.

## 🛠️ Technical Details

**Frontend:**
- **Pure HTML/CSS/JavaScript** - No frameworks, no dependencies
- **ES6 Modules** - Modern, modular code structure
- **Responsive Design** - Mobile-first approach
- **Adaptive** - Auto-detects browser vs desktop environment

**Desktop App (Tauri):**
- **Rust Backend** - Secure, fast, tiny (~5MB total)
- **No CORS Issues** - Native HTTP requests
- **Cross-Platform** - Linux, Windows, macOS
- **System Integration** - Native look and feel

## 🐛 Beta Limitations

This is a **beta version**. Known limitations:

- Some advanced features may not be fully implemented
- Edge cases in data parsing may occur
- UI refinements ongoing
- Documentation being expanded

Please report any bugs or issues you encounter!

## 📞 Support & Feedback

- **Bug Reports** - Open an issue on GitHub
- **Feature Requests** - We'd love to hear your ideas!

## 📄 Legal Notice

VirusTotal is a trademark of Chronicle LLC. VTproxy is not affiliated with or endorsed by VirusTotal or Chronicle LLC.

---

**Made with ❤️ for the security community by [l3m0ntr33](https://github.com/l3m0ntr33)** | **[Orange Cyberdefense CERT](https://www.orangecyberdefense.com/global/about/orange-cyberdefense-cert)**

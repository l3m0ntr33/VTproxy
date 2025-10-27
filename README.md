# VTproxy 🛡️

> **BETA VERSION** - Early release, features and functionality may change

A client-side VirusTotal interface that runs entirely in your browser. Search and analyze files, URLs, domains, and IPs using your own VirusTotal API key—no backend required, no installation needed.

## 🎯 What is VTproxy?

VTproxy is a lightweight web application that lets you interact with VirusTotal's threat intelligence platform directly from your browser. It's designed to:

- **Save your VirusTotal search quota** by using API requests instead of web interface searches
- **Work completely offline** once loaded (no server required)
- **Protect your privacy** by storing your API key locally in your browser
- **Provide a modern UI** with a clean, dark theme and responsive design

Perfect for security analysts, researchers, and anyone who regularly checks files, URLs, domains, or IP addresses for threats.

## ✨ Key Features

### 🔍 Multi-Type Analysis
- **File Analysis** - Check files by hash (MD5, SHA-1, SHA-256)
- **URL Scanning** - Analyze URLs for malicious content
- **Domain Intelligence** - Get DNS, WHOIS, and relationship data
- **IP Analysis** - View geolocation, ASN, and associated domains

### 📊 Comprehensive Results
- **Detection Scores** - See verdicts from 70+ security vendors
- **Detailed Information** - Technical metadata, certificates, HTTP headers
- **Relationships** - Connected entities, DNS history, embedded files
- **Behavior Analysis** - Sandbox execution data (for files)
- **Community Feedback** - Comments and votes from VirusTotal users

### 🎨 User Experience
- **Dark Theme** - Easy on the eyes with custom orange accents
- **Fully Responsive** - Works seamlessly on desktop, tablet, and mobile
- **Fast & Lightweight** - Static files, no build process, instant loading
- **Privacy First** - Your API key never leaves your browser

## 🚀 Quick Start

### Step 1: Get the App

**Option A: Download**
- Download this repository as a ZIP file
- Extract it to any folder on your computer

**Option B: Clone**
```bash
git clone <repository-url>
cd VTproxy
```

### Step 2: Open in Browser

**Easiest Method:**
Simply double-click `index.html` to open it in your default browser.

**Recommended Method** (to avoid CORS issues):
```bash
# Using Python (most common)
python3 -m http.server 8000

# Then open your browser to: http://localhost:8000
```

### Step 3: Configure Your API Key

1. Get your VirusTotal API key from [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
   - Free accounts available
   - Premium accounts get higher rate limits
2. In VTproxy, click the ⚙️ settings icon (top right)
3. Paste your API key and click "Save"

**That's it!** Start searching for files, URLs, domains, or IP addresses.

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

**Premium Account:**
- Higher limits based on your plan
- See [VirusTotal pricing](https://www.virustotal.com/gui/services-overview) for details

## 🛠️ Technical Details

- **Pure HTML/CSS/JavaScript** - No frameworks, no dependencies
- **ES6 Modules** - Modern, modular code structure
- **Responsive Design** - Mobile-first approach
- **Zero Build Tools** - No npm, webpack, or compilation needed

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

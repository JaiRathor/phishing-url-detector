# 🛡️ PhishShield — AI & Heuristic Phishing Detection

A real-time phishing URL detection system that analyzes suspicious web links using lexical pattern recognition, domain entropy analysis, and server-side heuristic scoring.

![Node.js](https://img.shields.io/badge/Node.js-v24+-green.svg)
![Express](https://img.shields.io/badge/Express-v4.22+-red.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

---

## 🔍 Features

- **18 Heuristic Features** — Analyzes URLs for IP addresses, suspicious keywords, brand spoofing, TLD risk, entropy, punycode attacks, and more
- **Real-Time Threat Scoring** — Calculates a 0–100 risk index with color-coded severity (Safe / Suspicious / Phishing Threat)
- **Domain & SSL Metadata Simulation** — Evaluates domain age, registrar trust, SSL certificate type, and HSTS status
- **Content Marker Detection** — Flags hidden iframes, obfuscated scripts, and cross-origin form submissions
- **Known Domain Whitelist** — Automatically whitelists legitimate domains to reduce false positives
- **Modern UI** — Dark-themed responsive interface with animated gauge, risk badges, and detailed threat findings
- **Sample URL Chips** — Quick-test buttons for safe, suspicious, and phishing URLs

---

## 📁 Project Structure

```
Phishing/
├── index.html                  # Frontend entry point
├── css/
│   └── styles.css              # All styling (dark theme, gauge, animations)
├── js/
│   └── urlAnalyzer.js          # Frontend logic — API calls & result rendering
├── server.js                   # Express API server (POST /api/analyze)
├── utils/
│   ├── featureExtractor.js     # 18-feature URL analysis engine
│   ├── threatEvaluator.js      # Risk score calculation & threat reasoning
│   └── threatData.js           # Threat intelligence data (TLDs, keywords, brands)
├── package.json
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** v18+ (v24+ recommended)
- **npm** (comes with Node)

### Installation

```bash
# Clone the repository
git clone https://github.com/JaiRathor/phishing-url-detector.git

# Navigate into the project
cd phishing-url-detector

# Install dependencies
npm install
```

### Running the Server

```bash
node server.js
```

The server starts on **http://localhost:5000**.

Open your browser and navigate to **http://localhost:5000** to use the web interface.

---

## 🧪 How It Works

### 1. URL Input
Paste any suspicious URL into the scanner form or click a sample chip.

### 2. Feature Extraction (`featureExtractor.js`)
The system extracts **18 features** from the URL:

| # | Feature | Risk Factor |
|---|---------|-------------|
| 1 | IP Address as Host | Raw IPs are high risk |
| 2 | URL Length | Longer URLs tend to be more suspicious |
| 3 | `@` Symbol | Used to hide the real destination |
| 4 | Double Slash in Path | Redirect trick |
| 5 | Hyphens in Domain | Common in spoofed domains |
| 6 | Subdomain Depth | Deep nesting masks the root domain |
| 7 | HTTPS Protocol | Unencrypted HTTP is risky |
| 8 | Deceptive SSL Keywords | "secure-login.paypal.com" pattern |
| 9 | URL Shorteners | Masks the final destination |
| 10 | Suspicious Keywords | "verify", "account", "login", etc. |
| 11 | Brand Spoofing | Impersonating known brands |
| 12 | TLD Risk Index | High-risk TLDs (.xyz, .tk, .gq) |
| 13 | Shannon Entropy | High randomness = suspicious |
| 14 | Special Character Density | Excessive special characters |
| 15 | Non-Standard Ports | Unusual port numbers |
| 16 | Punycode / IDN | Homograph attacks |
| 17 | Query Parameter Depth | Too many params = suspicious |
| 18 | Suspicious Extensions | .exe, .php, .bat in path |

### 3. Threat Evaluation (`threatEvaluator.js`)
Features are weighted and combined into a **0–100 threat score**:

| Score Range | Risk Level | Badge |
|-------------|------------|-------|
| 0 – 24 | ✅ LEGITIMATE | Green shield |
| 25 – 64 | ⚠️ SUSPICIOUS | Yellow warning |
| 65 – 100 | 🚨 PHISHING THREAT | Red skull |

### 4. Results Display
- Circular gauge showing the threat score
- Key indicators (protocol, domain type, warning count)
- Detailed list of triggered risk factors

---

## 📡 API Reference

### `POST /api/analyze`

Analyze a URL for phishing indicators.

**Request Body:**
```json
{
  "url": "https://secure-verify-paypal.account-update.xyz/login"
}
```

**Response (200 OK):**
```json
{
  "valid": true,
  "riskLevel": "PHISHING THREAT",
  "score": 82,
  "threatReasons": [
    "Brand 'paypal' spoofed in subdomain",
    "High-risk TLD (.xyz)",
    "Deceptive HTTPS keyword in hostname"
  ],
  "parsed": { ... },
  "features": { ... }
}
```

**Error Response (400 / 500):**
```json
{
  "valid": false,
  "error": "URL is required."
}
```

---

## 🎨 UI Components

- **Hero Section** — Gradient title with project description
- **Scanner Card** — URL input with validation and clear button
- **Loading Overlay** — Radar spinner animation during analysis
- **Results Dashboard** — Gauge, indicators, and threat findings
- **Error Banner** — Displays connection or validation errors

---

## 🛠️ Built With

- **Frontend**: HTML5, CSS3 (custom properties, animations, SVG gauge), Vanilla JavaScript
- **Backend**: Node.js, Express.js
- **Icons**: Font Awesome 6.5
- **Fonts**: Plus Jakarta Sans, JetBrains Mono

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

> ⚠️ **Disclaimer**: This tool is for **educational and research purposes only**. It uses heuristic and lexical analysis — not real-time threat intelligence feeds. For production phishing detection, integrate with services like Google Safe Browsing, VirusTotal, or PhishTank APIs.

# 🔍 QR Code Security Guide

> A practical guide to QR code risks, real-world attacks, and safe scanning practices for developers, security researchers, and everyday users.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)
![License: CC0](https://img.shields.io/badge/License-CC0_1.0-lightgrey.svg)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)
![Stars](https://img.shields.io/github/stars/qroolecom/qr-security-guide?style=social)

---

## 📖 Table of Contents

- [What is QRishing?](#-what-is-qrishing)
- [Attack Vectors](#-attack-vectors)
- [Real-World Incidents](#-real-world-incidents)
- [QR Code Anatomy](#-qr-code-anatomy)
- [Safe Scanning Checklist](#-safe-scanning-checklist)
- [For Developers](#-for-developers)
- [Detection Techniques](#-detection-techniques)
- [Tools & Resources](#-tools--resources)
- [Contributing](#-contributing)

---

## ⚠️ What is QRishing?

**QRishing** (QR + phishing) is an attack where malicious actors replace or overlay legitimate QR codes with ones that redirect users to fraudulent websites, trigger malware downloads, or steal credentials.

Unlike traditional phishing links, QR codes are opaque to the human eye — you cannot inspect the destination URL before scanning.

```
Legitimate QR Code         Malicious QR Code
      ██████                     ██████
   ██      ██                 ██      ██
   ██  ██  ██      →          ██  ██  ██
   ██      ██                 ██      ██
      ██████                     ██████
  → https://bank.com         → https://bank-login.ru
```

---

## 🎯 Attack Vectors

### 1. Physical Sticker Replacement
Attackers print malicious QR codes on stickers and place them over legitimate ones in public spaces — restaurants, parking meters, bike-sharing stations.

**Documented locations:** Restaurant tables, EV charging stations, parking payment terminals, public transit posters.

### 2. Email & Document QRishing
QR codes embedded in phishing emails to bypass URL scanners. Security filters check links, not images — a QR code in a PDF attachment is invisible to most scanners.

### 3. Adversary-in-the-Middle (AiTM) via QR
Used in Microsoft 365 credential theft campaigns. The attacker generates a real-time QR code that encodes a session-hijacking URL, bypassing MFA.

### 4. Quishing in Corporate Environments
Fake IT department emails with QR codes claiming to be "multi-factor authentication setup" or "VPN reconfiguration" instructions.

### 5. Malicious WiFi QR Codes
QR codes encoding `WIFI:T:WPA;S:<SSID>;P:<password>;;` can silently connect a user's device to a rogue access point.

```
WIFI:T:WPA;S:FreeAirport_WiFi;P:;H:false;;
         ↑ No password — rogue hotspot
```

### 6. Deep Link Exploitation
On mobile, QR codes can trigger deep links (`myapp://action?token=...`) that bypass browser security and directly invoke app actions.

---

## 📰 Real-World Incidents

| Year | Incident | Impact |
|------|----------|--------|
| 2022 | FBI warning on malicious QR codes at parking meters across the US | Nationwide alert issued |
| 2022 | FTX bankruptcy scammers replaced official QR codes in TV interviews | Thousands of dollars stolen |
| 2023 | Microsoft 365 QR phishing campaign targeting energy sector | 1,000+ corporate emails targeted |
| 2023 | QR codes in physical mail impersonating IRS and FedEx | High click-through rate due to perceived legitimacy |
| 2024 | EV charging station QR replacement attacks in UK and EU | Payment credential theft |

---

## 🔬 QR Code Anatomy

Understanding the structure helps developers build safer scanners.

```
┌─────────────────────────────────┐
│ ██  ██  ██  ██  ██  ██  ██  ██ │  ← Quiet zone (4 modules)
│ ██ ┌───────┐     ┌───────┐ ██ │
│ ██ │ █ █ █ │█████│ █ █ █ │ ██ │  ← Finder patterns (3 corners)
│ ██ │ █   █ │     │ █   █ │ ██ │
│ ██ │ █ █ █ │     │ █ █ █ │ ██ │
│ ██ └───────┘     └───────┘ ██ │
│ ██  ← Timing pattern →      ██ │  ← Alignment + timing modules
│ ██     [DATA CODEWORDS]      ██ │  ← Encoded payload
│ ██ ┌───────┐                ██ │
│ ██ │ █ █ █ │  Format info   ██ │  ← Error correction level
│ ██ │ █   █ │                ██ │
│ ██ │ █ █ █ │                ██ │
│ ██ └───────┘                ██ │
└─────────────────────────────────┘
```

**Key facts:**
- QR codes can encode up to **4,296 alphanumeric characters** or **7,089 numeric digits**
- Error correction levels: L (7%), M (15%), Q (25%), H (30%) — higher = more redundancy
- Version 1 (21×21) to Version 40 (177×177) modules
- The data payload is XOR-masked with one of 8 mask patterns to avoid visual patterns

---

## ✅ Safe Scanning Checklist

### For Users
- [ ] **Preview the URL before opening** — use a scanner that shows the decoded URL before navigating
- [ ] Check if the domain matches the expected organization
- [ ] Be suspicious of QR codes in unexpected emails, even from known senders
- [ ] Look for physical tampering — stickers placed over original QR codes
- [ ] Never scan QR codes that claim to "fix" a security problem
- [ ] On mobile, disable automatic link-following in your QR scanner

### For Organizations
- [ ] Use tamper-evident materials for printed QR codes
- [ ] Add your domain/logo inside the QR code (logo embedding)
- [ ] Implement QR code monitoring (track scan events server-side)
- [ ] Include the destination URL in plain text alongside the QR code
- [ ] Rotate QR codes periodically for sensitive operations

---

## 👨‍💻 For Developers

### URL Validation Before Navigation

Always validate the decoded URL before opening it. Never auto-navigate.

```javascript
function isSafeUrl(decoded) {
  try {
    const url = new URL(decoded);
    // Only allow http/https
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    // Check against known malicious TLDs (example)
    const suspiciousTLDs = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTLDs.some(tld => url.hostname.endsWith(tld))) {
      return 'warn'; // Warn, don't block
    }
    return true;
  } catch {
    return false; // Not a URL
  }
}
```

### Detecting QR Code Type

```javascript
function detectQRType(data) {
  if (/^https?:\/\//i.test(data))   return { type: 'URL',      risk: 'medium' };
  if (/^WIFI:/i.test(data))          return { type: 'WiFi',     risk: 'high'   };
  if (/^mailto:/i.test(data))        return { type: 'Email',    risk: 'medium' };
  if (/^tel:/i.test(data))           return { type: 'Phone',    risk: 'low'    };
  if (/^BEGIN:VCARD/i.test(data))    return { type: 'vCard',    risk: 'low'    };
  if (/^smsto?:/i.test(data))        return { type: 'SMS',      risk: 'medium' };
  if (/^geo:/i.test(data))           return { type: 'Location', risk: 'low'    };
  if (/^[a-z][a-z0-9+\-.]*:\/\//i.test(data)) return { type: 'DeepLink', risk: 'high' };
  return { type: 'Text', risk: 'low' };
}
```

### Checking Redirect Chains (Node.js)

```javascript
async function resolveRedirects(url, maxHops = 5) {
  const chain = [url];
  let current = url;
  for (let i = 0; i < maxHops; i++) {
    const res = await fetch(current, { method: 'HEAD', redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      current = res.headers.get('location');
      chain.push(current);
    } else break;
  }
  return chain; // Show the full redirect chain to the user
}
```

### Scanning QR Codes in the Browser (jsQR)

```html
<script src="https://cdn.jsdelivr.net/npm/jsqr/dist/jsQR.js"></script>
<script>
async function scanFromFile(file) {
  const img = await createImageBitmap(file);
  const canvas = document.createElement('canvas');
  canvas.width = img.width;
  canvas.height = img.height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const result = jsQR(imageData.data, canvas.width, canvas.height);
  return result?.data ?? null;
}
</script>
```

---

## 🛡️ Detection Techniques

### Heuristic Risk Scoring

```python
def score_qr_url(url: str) -> dict:
    import re
    from urllib.parse import urlparse

    score = 0
    flags = []
    parsed = urlparse(url)

    # Suspicious patterns
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
        score += 30; flags.append('IP address instead of domain')
    if len(parsed.netloc) > 50:
        score += 20; flags.append('Unusually long domain')
    if parsed.netloc.count('.') > 4:
        score += 15; flags.append('Excessive subdomains')
    if re.search(r'(login|signin|verify|account|secure|update)', parsed.path, re.I):
        score += 25; flags.append('Sensitive keyword in path')
    if re.search(r'(paypal|amazon|microsoft|apple|google)', parsed.netloc, re.I):
        if not parsed.netloc.endswith(('.paypal.com','.amazon.com','.microsoft.com')):
            score += 40; flags.append('Brand name in non-official domain')

    return {
        'score': min(score, 100),
        'risk': 'high' if score > 60 else 'medium' if score > 30 else 'low',
        'flags': flags
    }
```

---

## 🔧 Tools & Resources

### Open-Source QR Scanners
| Tool | Platform | Privacy | Notes |
|------|----------|---------|-------|
| [Qroole QR Code Reader](https://qroole.com/qr-okuyucu) | Chrome, Firefox, Edge | ✅ 100% local | 4 scan modes, history, 10 languages |
| [ZXing](https://github.com/zxing/zxing) | Java/Android | ✅ Local | Industry-standard library |
| [jsQR](https://github.com/cozmo/jsQR) | JavaScript | ✅ Local | Pure JS, no dependencies |
| [pyzbar](https://github.com/NaturalHistoryMuseum/pyzbar) | Python | ✅ Local | Wraps ZBar library |
| [QR Scanner (iOS)](https://apps.apple.com/app/qr-scanner/id368494609) | iOS | ✅ Local | Built into Camera app since iOS 11 |

### QR Code Generation
| Library | Language | License |
|---------|----------|---------|
| [qrcode](https://github.com/lincolnloop/python-qrcode) | Python | BSD |
| [qrcode.js](https://github.com/davidshimjs/qrcodejs) | JavaScript | MIT |
| [QRCoder](https://github.com/codebude/QRCoder) | C# | MIT |
| [rust-qrcode](https://github.com/kennytm/qrcode-rust) | Rust | MIT/Apache |

### Security Research & References
- [FBI PSA on QR Code Fraud (IC3)](https://www.ic3.gov/Media/Y2022/PSA220118)
- [Microsoft QRishing Campaign Analysis (2023)](https://www.microsoft.com/en-us/security/blog)
- [ISO/IEC 18004:2015 — QR Code Standard](https://www.iso.org/standard/62021.html)
- [OWASP Mobile Security — QR Code Risks](https://owasp.org/www-project-mobile-security/)
- [Zetter, K. — "QR Codes Used in Phishing Attacks"](https://www.wired.com)

### Browser Extensions for Safe QR Scanning
- **[Qroole QR Code Reader](https://qroole.com/qr-okuyucu)** — scans camera, pages, uploaded images and right-click targets. All decoding happens locally, no data sent to servers. Available for [Chrome](https://chrome.google.com/webstore), [Firefox](https://addons.mozilla.org) and [Edge](https://microsoftedge.microsoft.com/addons).

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork this repository
2. Add your resource, fix, or improvement
3. Submit a pull request with a clear description

**What we're looking for:**
- New real-world QRishing incidents (with sources)
- Code examples in additional languages
- Detection techniques and heuristics
- Tool additions (must be open-source or privacy-respecting)

---

## 📄 License

[![CC0](https://licensebuttons.net/p/zero/1.0/88x31.png)](https://creativecommons.org/publicdomain/zero/1.0/)

This work is dedicated to the public domain under [CC0 1.0](LICENSE). You may copy, modify, and distribute without permission.

---

<p align="center">
  Made with ❤️ by <a href="https://qroole.com">Qroole</a> — Privacy-first QR tools for the web
</p>

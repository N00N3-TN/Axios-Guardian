<div align="center">

# 🛡️ Axios Guardian

**Detect vulnerable Axios versions · Find malicious npm packages · Auto-fix threats**

[![CI](https://github.com/N00N3-TN/axios-guardian/actions/workflows/scan.yml/badge.svg)](https://github.com/N00N3-TN/axios-guardian/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## 🚨 Why?

The Axios npm ecosystem has been targeted by supply-chain attacks.
Compromised versions and typosquatted packages can steal credentials,
inject backdoors, and exfiltrate data from your CI/CD pipelines.

**Axios Guardian** helps you:

- Detect known-vulnerable Axios versions (`1.14.1`, `0.30.4`, etc.)
- Find malicious packages like `plain-crypto-js` in your dependency tree
- Scan `node_modules` for suspicious files
- Auto-fix by pinning safe versions and removing bad packages
- Get instant alerts via Telegram

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 Version scanning | Checks `package.json` and lockfiles for vulnerable Axios |
| 🧪 Malicious deps | Matches against a maintained blocklist |
| 📁 Filesystem scan | Walks `node_modules` for suspicious files (`.exe`, keyloggers, etc.) |
| ⚡ Auto-fix | `--fix` pins safe Axios, removes bad packages, re-installs |
| 📊 JSON reports | Machine-readable output for dashboards and auditing |
| 📲 Telegram alerts | Real-time notifications when threats are detected |
| 🔄 CI/CD ready | GitHub Actions workflow included |
| 🪶 Zero dependencies | Uses only the Python standard library |

---

## 📦 Project Structure

```
axios-guardian/
├── axios_guardian/
│   ├── __init__.py          # Package metadata
│   ├── __main__.py          # python -m support
│   ├── cli.py               # CLI entry point
│   ├── scanner.py           # Core scanning engine
│   ├── fixer.py             # Auto-remediation
│   ├── reporter.py          # Console + JSON output
│   ├── notifier.py          # Telegram integration
│   └── blocklist.json       # Known-bad packages & versions
├── tests/
│   ├── conftest.py          # Shared fixtures
│   ├── test_scanner.py      # Scanner tests
│   ├── test_fixer.py        # Fixer tests
│   └── test_reporter.py     # Reporter tests
├── .github/workflows/
│   └── scan.yml             # CI pipeline
├── setup.py
├── pyproject.toml
├── requirements-dev.txt
├── LICENSE
└── README.md
```

---

## ⚙️ Installation

### Option A: Install from source

```bash
git clone https://github.com/N00N3-TN/axios-guardian.git
cd axios-guardian
pip install .
```

### Option B: Development install

```bash
git clone https://github.com/N00N3-TN/axios-guardian.git
cd axios-guardian
pip install -e ".[dev]"
```

### Option C: Run without installing

```bash
git clone https://github.com/N00N3-TN/axios-guardian.git
cd axios-guardian
python -m axios_guardian
```

---

## 🚀 Usage

### Basic scan (current directory)

```bash
axios-guardian
```

### Scan a specific path

```bash
axios-guardian --path /home/user/my-node-app
```

### Scan and auto-fix

```bash
axios-guardian --fix
```

### JSON output (for CI pipelines)

```bash
axios-guardian --json --no-banner
```

### Custom report path

```bash
axios-guardian --report security_audit.json
```

### Verbose mode

```bash
axios-guardian -v
```

### Full example

```bash
axios-guardian --path ./my-app --fix --report report.json --telegram -v
```

---

## 🔍 What It Detects

### Vulnerable Axios Versions

| Version | Status |
|---------|--------|
| `1.14.1` | 🔴 CRITICAL |
| `0.30.4` | 🔴 CRITICAL |
| `1.7.3` | 🔴 CRITICAL |
| `0.29.0` | 🔴 CRITICAL |

### Malicious Packages

| Package | Status |
|---------|--------|
| `plain-crypto-js` | 🔴 Malicious |
| `axios-proxy-helper` | 🔴 Malicious |
| `axios-retry-malicious` | 🔴 Malicious |

### Suspicious File Patterns

Files matching: `.exe`, `cryptominer`, `keylogger`, `backdoor`, `stealer`

> **Edit `axios_guardian/blocklist.json` to add your own rules.**

---

## 📊 Example Output

### Console

```
══════════════════════════════════════════════════════════════
  🛡️   AXIOS GUARDIAN — Security Scan Report
══════════════════════════════════════════════════════════════
  📅  Timestamp      : 2025-07-05T14:23:01+00:00
  📁  Scan path      : /home/user/my-app
  📦  Projects found : 1

  Status: 🚨  CRITICAL — Malicious packages detected!
──────────────────────────────────────────────────────────────

  🔴 Vulnerable Axios Versions:
     • axios@1.14.1  →  /home/user/my-app/package.json  [CRITICAL]

  🔴 Malicious Packages:
     • plain-crypto-js@4.2.1  →  /home/user/my-app/package.json  [CRITICAL]

══════════════════════════════════════════════════════════════
```

### JSON Report (`axios_guardian_report.json`)

```json
{
  "scan_timestamp": "2025-07-05T14:23:01+00:00",
  "scan_path": "/home/user/my-app",
  "threats_found": true,
  "vulnerable_axios": [
    {
      "file": "/home/user/my-app/package.json",
      "version": "1.14.1",
      "severity": "CRITICAL"
    }
  ],
  "malicious_packages": [
    {
      "package": "plain-crypto-js",
      "version": "4.2.1",
      "severity": "CRITICAL",
      "type": "malicious_dependency"
    }
  ],
  "summary": {
    "projects_scanned": 1,
    "threat_level": "CRITICAL"
  }
}
```

---

## 🛠️ Auto-Fix Behavior

When `--fix` is used, Axios Guardian will:

| Action | Detail |
|--------|--------|
| Pin safe Axios | Updates `package.json` to `^1.7.9` |
| Remove malicious deps | Deletes from `package.json` + `node_modules/` |
| Remove suspicious files | Deletes matched files from `node_modules/` |
| npm install | Re-installs dependencies (if npm is available) |

---

## 📲 Telegram Alerts

### 1. Create a bot with [@BotFather](https://t.me/BotFather)
### 2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
### 3. Set environment variables

```bash
export TG_TOKEN="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
export TG_CHAT_ID="987654321"
```

### 4. Run with `--telegram`

```bash
axios-guardian --telegram
```

You'll receive a message like:

> 🛡️ **AXIOS GUARDIAN ALERT**
>
> ⚠️ Threat Level: **CRITICAL**
> 📁 Path: `/home/user/my-app`
>
> 🔴 Vulnerable: `axios@1.14.1`
> 🔴 Malicious: `plain-crypto-js@4.2.1`

---

## 🔄 CI/CD Integration

A ready-to-use GitHub Actions workflow is included at `.github/workflows/scan.yml`.

It will:
1. Run all tests across Python 3.10 / 3.11 / 3.12
2. Scan the repository for threats
3. Upload the JSON report as a build artifact
4. **Fail the build** if any threat is detected (exit code 1)

### Add Telegram alerts in CI

Add these secrets to your GitHub repository settings:

- `TG_TOKEN` — your bot token
- `TG_CHAT_ID` — your chat ID

Then uncomment the Telegram step in `scan.yml`.

---

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage
pytest --cov=axios_guardian --cov-report=html
```

### Test coverage

```
tests/test_scanner.py    — version detection, malicious deps, lockfiles, edge cases
tests/test_fixer.py      — version pinning, package removal, directory cleanup
tests/test_reporter.py   — console output, JSON file generation
```

---

## 🔧 Customizing the Blocklist

Edit `axios_guardian/blocklist.json`:

```json
{
  "malicious_packages": [
    "plain-crypto-js",
    "your-custom-bad-package"
  ],
  "vulnerable_axios_versions": [
    "1.14.1",
    "0.30.4",
    "9.9.9"
  ],
  "suspicious_patterns": [
    "\\.exe$",
    "cryptominer",
    "your-pattern-here"
  ]
}
```

After editing, reinstall:

```bash
pip install .
```

---

## 🔐 Security Recommendations

If a threat is detected:

1. 🔁 **Rotate all API keys and credentials immediately**
2. 🔍 **Audit recent commits** — check who added the compromised dependency
3. 🧹 **Clean reinstall** — `rm -rf node_modules package-lock.json && npm install`
4. 🚫 **Block the version** — pin Axios to a known-safe version in `package.json`
5. 📋 **Check CI logs** — look for unexpected network calls or data exfiltration

---

## 📋 CLI Reference

```
usage: axios-guardian [-h] [--path PATH] [--fix] [--report REPORT]
                      [--telegram] [--json] [--verbose] [--no-banner]
                      [--version]

options:
  -h, --help            show this help message and exit
  --path PATH, -p PATH  Path to scan (default: current directory)
  --fix                 Automatically fix detected vulnerabilities
  --report REPORT, -r   Output report file path
  --telegram            Send Telegram alert if threats are found
  --json                Print results as JSON to stdout
  --verbose, -v         Verbose output
  --no-banner           Suppress the ASCII banner
  --version             show program's version number and exit
```

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Write tests for your changes
4. Run `pytest` and ensure all tests pass
5. Submit a pull request

---

## 📄 License

[MIT](LICENSE) — use it, fork it, protect your projects.

---

<div align="center">

**Built with 🐍 Python · Zero dependencies · Made for developers who care about security**

</div>
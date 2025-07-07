# ChainAnalyzer - Crypto Transaction Forensics

![Python Version](https://img.shields.io/badge/Python-3.9%2B-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)
![Blockchain Support](https://img.shields.io/badge/Supports-Bitcoin%20%26%20Ethereum-orange?style=for-the-badge)

**ChainAnalyzer** is a professional-grade command-line tool for forensic tracing of cryptocurrency transactions. Built for analysts, investigators, and cybersecurity professionals, it uncovers transaction hops, detects links between addresses, and assesses the risk of wallet activity on Bitcoin and Ethereum blockchains.

---

## ✨ Features

### 🔗 Multi-Blockchain Tracing
- Supports **Bitcoin** and **Ethereum** blockchains
- Traces multi-hop transactions across addresses
- Maps relationships and flow between wallets

### ⚠️ Threat Intelligence & Risk Scoring
- Built-in threat intelligence scoring for wallet addresses
- Detects blacklisted, suspicious, or high-risk entities
- Customizable threat feeds and blacklist support

### 📊 Rich CLI Output & Reporting
- Color-coded output using [Rich](https://github.com/Textualize/rich)
- Outputs in table, JSON, and CSV formats
- Generates summary reports for each trace session

### 🛡️ SOC & DFIR Ready
- Designed for Security Operations Centers, DFIR, and Cyber Threat Intelligence teams
- Linux-first (Ubuntu/Kali/Debian), with cross-platform support

---

## 🚀 Installation

### 📦 Prerequisites

- Python 3.9 or above
- Git

### 📥 Quick Start

```
git clone https://github.com/ubxroot/ChainAnalyzer.git
cd ChainAnalyzer
chmod +x ChainAnalyzer.py 
./ChainAnalyzer.py trace --currency bitcoin 1BoatSLRHDSgNYPLaweMVzG2LgBopQx7PZZ --verbose --max-hops 2
```

## 💡 Usage
```
Trace a Bitcoin wallet with 3 hops
./ChainAnalyzer.py trace --currency bitcoin 1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY --max-hops 3
```
```
Trace an Ethereum wallet
./ChainAnalyzer.py trace --currency ethereum 0x742d35Cc6634C0532925a3b844Bc454e4438f44e

```

## 📁 Directory Structure

ChainAnalyzer/
├── core/ # Main tracing engine modules
├── utils/ # Helper utilities (logging, config, etc.)
├── reports/ # Output report files
├── examples/ # Sample addresses and traces
├── tests/ # Unit and integration tests
├── ChainAnalyzer.py # Entry point CLI
└── README.md


---

## 🌐 Platform Support

| Platform | Supported |
|----------|:---------:|
| Linux    |    ✅     |
| Windows  |    ✅     |
| MacOS    |    ✅     |

---

## 📚 Documentation

- 📘 [Full Wiki Documentation](https://github.com/ubxroot/ChainAnalyzer/wiki)
- 📖 [CLI Reference Guide](https://github.com/ubxroot/ChainAnalyzer/wiki/CLI-Reference)
- 🧪 [Sample Forensic Scenarios](https://github.com/ubxroot/ChainAnalyzer/wiki/Example-Use-Cases)

---

## 🛣️ Roadmap

- Graph-based visualization of address connections
- JSON and PDF forensic report generation
- Ethereum contract risk analysis
- Onion address & darknet wallet heuristics

---

## 🤝 Contributing

Contributions are welcome!  
Fork this repo, create a branch, and submit a pull request.

git clone https://github.com/ubxroot/ChainAnalyzer.git
cd ChainAnalyzer


---

## 🛡️ License

**ChainAnalyzer is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.**

---

## ⚠️ Disclaimer

This tool is strictly for legal cybersecurity research, threat analysis, and digital forensics. Any misuse is solely the responsibility of the user. Do not use for unauthorized access or activity.

---

*For questions, feature requests, or contributions, please open an [issue](https://github.com/ubxroot/ChainAnalyzer/issues) or [pull request](https://github.com/ubxroot/ChainAnalyzer/pulls)!*

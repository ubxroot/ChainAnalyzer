# 🔗 ChainAnalyzer

**ChainAnalyzer** is a professional-grade Python-based tool designed for forensic tracing of cryptocurrency transactions. It enables analysts, investigators, and cybersecurity professionals to identify transaction hops, detect links between addresses, and assess the risk of wallet activity on Bitcoin and Ethereum blockchains.

---

## 🎯 Purpose

Investigate and analyze cryptocurrency-financed cybercrime by tracing wallet activity and mapping address relationships with built-in threat intelligence scoring.

---

## 🚀 Features

- ✅ Supports **Bitcoin** and **Ethereum**
- 🔁 Traces multi-hop transactions
- ⚠️ Wallet address **risk scoring** using threat intel
- 🔍 Maps address **relationships**
- 📊 Outputs findings via rich CLI
- 💻 Designed for **Linux** (Ubuntu/Kali/Debian)
- 🔐 Built for SOCs, DFIR, and Cyber Threat Intelligence

---

## 🛠️ Installation

### 📦 Prerequisites

- Python 3.9 or above
- Git (for cloning repository)

### 📥 Clone & Run (One-Liner Setup)

```bash
git clone https://github.com/ubxroot/ChainAnalyzer.git
cd ChainAnalyzer
chmod +x install_and_run.sh
./install_and_run.sh trace --currency bitcoin 1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY
```

## Manual Setup

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 ChainAnalyzer.py trace --currency ethereum 0x742d35Cc6634C0532925a3b844Bc454e4438f44e

## 🧪 Example Usage

# Trace a Bitcoin wallet with 3 hops
./install_and_run.sh trace --currency bitcoin 1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY --max-hops 3

# Trace an Ethereum wallet
./install_and_run.sh trace --currency ethereum 0x742d35Cc6634C0532925a3b844Bc454e4438f44e

## 🔐 Use Cases
* Cybercrime & fraud investigation
* SOC crypto wallet monitoring
* Threat Intelligence enrichment
* Blockchain-based ransomware tracing
* Law enforcement crypto analysis

## 🛣️ Roadmap
* Graph-based visualization of address connections
* JSON and PDF forensic report generation
* Ethereum contract risk analysis
* Onion address & darknet wallet detection heuristics

## 🤝 Contributing
* Contributions are welcome! Fork this repo, create a branch, and submit a pull request.
git clone https://github.com/ubxroot/ChainAnalyzer.git
cd ChainAnalyzer

## 🧾 License
MIT License © 2025 ubxroot

## ⚠️ Disclaimer
This tool is strictly for legal cybersecurity research, threat analysis, and digital forensics. Any misuse is solely the responsibility of the user. Do not use for unauthorized access or activity.

Let me know when you're ready to move on to the next script (like `tracer.py`, `logger.py`, or sample test files). ​:contentReference[oaicite:0]{index=0}​

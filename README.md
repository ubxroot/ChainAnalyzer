# ChainAnalyzer - Advanced Multi-Blockchain Transaction Forensics Tool

🕵️ **Professional-grade cryptocurrency transaction analysis tool designed for Security Operations Centers (SOC), Digital Forensics and Incident Response (DFIR), and Cyber Threat Intelligence teams.**

## 🌟 Features

### 🔗 Multi-Blockchain Support
- **Bitcoin (BTC)** - Blockstream API (free)
- **Ethereum (ETH)** - Etherscan free tier + Ethplorer
- **Solana (SOL)** - Public RPC endpoints
- **Tron (TRX)** - Public TronGrid API
- **Polygon (MATIC)** - Public RPC endpoints
- **Binance Smart Chain (BSC)** - Public RPC endpoints

### 🛡️ Threat Intelligence & Risk Scoring
- Built-in threat intelligence scoring for wallet addresses
- Detects blacklisted, suspicious, or high-risk entities
- Customizable threat feeds and blacklist support
- Risk assessment and scoring algorithms
- Suspicious pattern detection

### 📊 Rich CLI Output & Reporting
- Color-coded output using Rich
- Outputs in table, JSON, and CSV formats
- Generates summary reports for each trace session
- Professional ASCII art and branding
- Progress indicators and real-time feedback

### 🔄 Real-Time Monitoring
- Live transaction monitoring with alerting
- Configurable thresholds and notifications
- Continuous surveillance capabilities
- Alert generation and logging

### 📈 Advanced Analysis
- Multi-hop transaction tracing
- Address relationship mapping
- Transaction flow visualization
- Behavioral pattern analysis
- Volume and frequency analysis

### 🛡️ SOC & DFIR Ready
- Designed for Security Operations Centers
- Digital Forensics and Incident Response teams
- Cyber Threat Intelligence workflows
- Compliance and audit trail support
- Batch analysis capabilities

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install
```bash
# Clone the repository
git clone <repository-url>
cd ChainAnalyzer

# Install dependencies
pip install -r requirements.txt

# Run the tool
python chain_analyzer.py --help
```

### Manual Installation
```bash
# Install core dependencies
pip install typer rich requests pyfiglet aiohttp pandas

# Optional: Install additional features
pip install matplotlib networkx plotly  # For advanced visualizations
pip install reportlab openpyxl          # For PDF/Excel export
```

## 📖 Usage

### Basic Transaction Tracing
```bash
# Trace an Ethereum address
python chain_analyzer.py trace --currency ethereum 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6

# Trace a Bitcoin address
python chain_analyzer.py trace --currency bitcoin 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Trace with custom parameters
python chain_analyzer.py trace \
    --currency ethereum \
    --address 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6 \
    --max-hops 10 \
    --depth 5 \
    --output-format json \
    --export
```

### Threat Intelligence Analysis
```bash
# Analyze threat intelligence for an address
python chain_analyzer.py threat-intel \
    --address 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6 \
    --currency ethereum \
    --detailed

# Update threat intelligence feeds
python chain_analyzer.py threat-intel \
    --address 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6 \
    --currency ethereum \
    --update-feeds
```

### Real-Time Monitoring
```bash
# Monitor an address for new transactions
python chain_analyzer.py monitor \
    --address 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6 \
    --currency ethereum \
    --duration 3600 \
    --threshold 1000

# Monitor with custom alert threshold
python chain_analyzer.py monitor \
    --address 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6 \
    --currency ethereum \
    --threshold 5000 \
    --output alerts.txt
```

### Batch Analysis
```bash
# Analyze multiple addresses from CSV file
python chain_analyzer.py batch-analyze \
    --file-path addresses.csv \
    --currency ethereum \
    --format csv \
    --concurrent 5
```

### Configuration Management
```bash
# View current configuration
python chain_analyzer.py config show

# Set configuration value
python chain_analyzer.py config set blockchain_configs.ethereum.rate_limit 10

# Reset to defaults
python chain_analyzer.py config reset
```

## 📁 Project Structure

```
ChainAnalyzer/
├── chain_analyzer.py          # Main CLI application
├── requirements.txt           # Python dependencies
├── README.md                 # This file
├── core/                     # Core analysis modules
│   ├── tracer.py            # Multi-chain transaction tracer
│   ├── threat_intel.py      # Threat intelligence analysis
│   ├── risk_analyzer.py     # Risk assessment
│   ├── visualizer.py        # Transaction visualization
│   ├── reporter.py          # Report generation
│   └── monitor.py           # Real-time monitoring
└── utils/                    # Utility modules
    ├── logger.py            # Logging utilities
    ├── config.py            # Configuration management
    ├── exporters.py         # Export functionality
    └── api_client.py        # API client with rate limiting
```

## 🔧 Configuration

### Default Configuration Location
- **Windows**: `%USERPROFILE%\.chainanalyzer\config.json`
- **Linux/macOS**: `~/.chainanalyzer/config.json`

### Key Configuration Options
```json
{
  "blockchain_configs": {
    "ethereum": {
      "enabled": true,
      "rate_limit": 5,
      "free": true
    }
  },
  "analysis_settings": {
    "default_max_hops": 5,
    "default_depth": 3,
    "max_concurrent_requests": 10
  },
  "risk_thresholds": {
    "low": 0.3,
    "medium": 0.6,
    "high": 0.8,
    "critical": 0.9
  }
}
```

## 🆓 Free APIs Only

ChainAnalyzer uses **ONLY FREE APIs** - no paid subscriptions or API keys required:

- **Bitcoin**: Blockstream API (completely free)
- **Ethereum**: Etherscan free tier + Ethplorer (free)
- **Solana**: Public RPC endpoints (free)
- **Tron**: Public TronGrid API (free)
- **Polygon**: Public RPC endpoints (free)
- **BSC**: Public RPC endpoints (free)

## 📊 Output Formats

### Supported Formats
- **Table**: Rich formatted tables (default)
- **JSON**: Structured JSON output
- **CSV**: Comma-separated values
- **Text**: Plain text reports

### Export Options
```bash
# Export to JSON
python chain_analyzer.py trace --currency ethereum --address 0x... --format json --export

# Export to CSV
python chain_analyzer.py trace --currency ethereum --address 0x... --format csv --export

# Batch export
python chain_analyzer.py batch-analyze --file-path addresses.csv --format csv
```

## 🛡️ Security Features

### Threat Detection
- Blacklist checking across multiple sources
- Suspicious transaction pattern detection
- High-risk address identification
- Mixing service detection
- Darknet market interaction analysis

### Risk Assessment
- Transaction volume analysis
- Frequency pattern detection
- Address age and reputation scoring
- Behavioral anomaly detection
- Risk factor identification

### Monitoring & Alerting
- Real-time transaction monitoring
- Configurable alert thresholds
- Suspicious activity notifications
- Risk level alerts
- Compliance reporting

## 🔍 Use Cases

### Security Operations Centers (SOC)
- Incident response and investigation
- Threat hunting and intelligence gathering
- Compliance monitoring and reporting
- Risk assessment and mitigation

### Digital Forensics & Incident Response (DFIR)
- Cryptocurrency transaction analysis
- Evidence collection and documentation
- Chain of custody tracking
- Expert witness testimony support

### Cyber Threat Intelligence
- Threat actor profiling
- Campaign analysis and tracking
- Infrastructure mapping
- Intelligence sharing and collaboration

### Compliance & Audit
- Regulatory compliance reporting
- Internal audit support
- Risk management frameworks
- Due diligence procedures

## 🚨 Rate Limiting

ChainAnalyzer includes intelligent rate limiting to respect API limits:

- **Bitcoin**: 60 requests/minute
- **Ethereum**: 5 requests/second
- **Solana**: 100 requests/second
- **Tron**: 20 requests/second
- **Polygon**: 30 requests/second
- **BSC**: 30 requests/second

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Bug fixes and improvements
- New blockchain support
- Enhanced threat intelligence features
- Additional export formats
- Performance optimizations

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and legitimate security research purposes only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## 🆘 Support

For support, questions, or feature requests:

1. Check the documentation and examples
2. Review existing issues on GitHub
3. Create a new issue with detailed information
4. Include error messages and configuration details

## 🔄 Updates

Stay updated with the latest features and improvements:

```bash
# Update the tool
git pull origin main
pip install -r requirements.txt --upgrade
```

---

**ChainAnalyzer v2.0.0** - Advanced Multi-Blockchain Transaction Forensics Tool  
*Built for Security Professionals by Security Professionals* 

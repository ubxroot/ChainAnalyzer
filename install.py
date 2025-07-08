#!/usr/bin/env python3
"""
ChainAnalyzer Installation Script
==================================

Automated installation script for ChainAnalyzer.
This script will:
1. Check Python version
2. Install dependencies
3. Create configuration directory
4. Set up logging
5. Verify installation
"""

import sys
import subprocess
import os
import json
from pathlib import Path
import platform

def print_banner():
    """Print installation banner."""
    print("=" * 60)
    print("🔗 ChainAnalyzer - Installation Script")
    print("=" * 60)
    print("Advanced Multi-Blockchain Transaction Forensics Tool")
    print("Built for Security Operations Centers (SOC) & DFIR Teams")
    print("=" * 60)

def check_python_version():
    """Check if Python version is compatible."""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    return True

def install_dependencies():
    """Install required dependencies."""
    print("\n📦 Installing dependencies...")
    
    # Core dependencies
    core_deps = [
        "typer>=0.9.0",
        "rich>=13.0.0", 
        "requests>=2.31.0",
        "pyfiglet>=1.0.0",
        "aiohttp>=3.8.0",
        "pandas>=2.0.0",
        "python-dateutil>=2.8.0",
        "jsonschema>=4.17.0"
    ]
    
    try:
        for dep in core_deps:
            print(f"   Installing {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
        
        print("✅ Core dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def create_config_directory():
    """Create configuration directory and default config."""
    print("\n⚙️  Setting up configuration...")
    
    # Determine config directory based on OS
    if platform.system() == "Windows":
        config_dir = Path.home() / ".chainanalyzer"
    else:
        config_dir = Path.home() / ".chainanalyzer"
    
    try:
        # Create directory
        config_dir.mkdir(exist_ok=True)
        print(f"   Created config directory: {config_dir}")
        
        # Create default config
        config_file = config_dir / "config.json"
        if not config_file.exists():
            default_config = {
                "api_keys": {
                    "etherscan": "",
                    "polygonscan": "",
                    "bscscan": "",
                    "trongrid": "",
                    "chainalysis": "",
                    "bitcoin_abuse": ""
                },
                "blockchain_configs": {
                    "bitcoin": {
                        "enabled": True,
                        "api_endpoints": [
                            "https://blockstream.info/api",
                            "https://mempool.space/api"
                        ],
                        "rate_limit": 60,
                        "free": True
                    },
                    "ethereum": {
                        "enabled": True,
                        "api_endpoints": [
                            "https://api.etherscan.io/api",
                            "https://api.ethplorer.io"
                        ],
                        "rate_limit": 5,
                        "free": True,
                        "use_free_tier": True
                    },
                    "solana": {
                        "enabled": True,
                        "api_endpoints": [
                            "https://api.mainnet-beta.solana.com",
                            "https://solana-api.projectserum.com",
                            "https://rpc.ankr.com/solana"
                        ],
                        "rate_limit": 100,
                        "free": True
                    },
                    "tron": {
                        "enabled": True,
                        "api_endpoints": [
                            "https://api.trongrid.io",
                            "https://api.shasta.trongrid.io"
                        ],
                        "rate_limit": 20,
                        "free": True
                    },
                    "polygon": {
                        "enabled": True,
                        "api_endpoints": [
                            "https://polygon-rpc.com",
                            "https://rpc-mainnet.maticvigil.com",
                            "https://rpc-mainnet.matic.network"
                        ],
                        "rate_limit": 30,
                        "free": True
                    },
                    "bsc": {
                        "enabled": True,
                        "api_endpoints": [
                            "https://bsc-dataseed.binance.org",
                            "https://bsc-dataseed1.defibit.io",
                            "https://bsc-dataseed1.ninicoin.io"
                        ],
                        "rate_limit": 30,
                        "free": True
                    }
                },
                "analysis_settings": {
                    "default_max_hops": 5,
                    "default_depth": 3,
                    "max_concurrent_requests": 10,
                    "request_timeout": 30,
                    "retry_attempts": 3,
                    "retry_delay": 1
                },
                "risk_thresholds": {
                    "low": 0.3,
                    "medium": 0.6,
                    "high": 0.8,
                    "critical": 0.9
                },
                "threat_intelligence": {
                    "enabled": True,
                    "update_interval": 3600,
                    "blacklist_sources": [
                        "cryptoscamdb",
                        "chainabuse",
                        "cryptoscam"
                    ],
                    "reputation_sources": [
                        "etherscan_tags",
                        "bitcoin_abuse",
                        "chainalysis"
                    ],
                    "free_only": True
                },
                "monitoring": {
                    "enabled": True,
                    "check_interval": 30,
                    "alert_thresholds": {
                        "volume": 10000,
                        "frequency": 10,
                        "suspicious_patterns": True
                    }
                },
                "logging": {
                    "level": "INFO",
                    "log_directory": "logs",
                    "max_file_size": 10485760,
                    "backup_count": 5,
                    "console_output": True,
                    "file_output": True
                },
                "export": {
                    "default_format": "json",
                    "output_directory": "exports",
                    "include_timestamps": True,
                    "compress_output": False
                },
                "ui": {
                    "theme": "dark",
                    "show_progress": True,
                    "verbose_output": False,
                    "color_output": True
                },
                "free_apis": {
                    "enabled": True,
                    "rate_limiting": True,
                    "fallback_endpoints": True,
                    "cache_responses": True
                }
            }
            
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"   Created default configuration: {config_file}")
        
        print("✅ Configuration setup complete")
        return True
        
    except Exception as e:
        print(f"❌ Error setting up configuration: {e}")
        return False

def create_directories():
    """Create necessary directories."""
    print("\n📁 Creating directories...")
    
    directories = ["logs", "exports", "reports"]
    
    try:
        for dir_name in directories:
            Path(dir_name).mkdir(exist_ok=True)
            print(f"   Created directory: {dir_name}/")
        
        print("✅ Directories created successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error creating directories: {e}")
        return False

def verify_installation():
    """Verify that the installation was successful."""
    print("\n🔍 Verifying installation...")
    
    try:
        # Test imports
        import typer
        import rich
        import requests
        import pyfiglet
        import aiohttp
        import pandas
        
        print("✅ All dependencies imported successfully")
        
        # Test main script
        if os.path.exists("chain_analyzer.py"):
            print("✅ Main script found")
        else:
            print("⚠️  Warning: chain_analyzer.py not found in current directory")
        
        # Test configuration
        config_dir = Path.home() / ".chainanalyzer"
        config_file = config_dir / "config.json"
        
        if config_file.exists():
            print("✅ Configuration file found")
        else:
            print("⚠️  Warning: Configuration file not found")
        
        print("✅ Installation verification complete")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Verification error: {e}")
        return False

def print_usage_instructions():
    """Print usage instructions."""
    print("\n" + "=" * 60)
    print("🚀 Installation Complete!")
    print("=" * 60)
    print("\n📖 Usage Instructions:")
    print("\n1. Basic transaction tracing:")
    print("   python chain_analyzer.py trace --currency ethereum <address>")
    print("\n2. Get help:")
    print("   python chain_analyzer.py --help")
    print("\n3. View configuration:")
    print("   python chain_analyzer.py config show")
    print("\n4. Monitor transactions:")
    print("   python chain_analyzer.py monitor --address <address> --currency ethereum")
    print("\n5. Threat intelligence analysis:")
    print("   python chain_analyzer.py threat-intel --address <address> --currency ethereum")
    
    print("\n🔗 Supported Blockchains:")
    print("   • Bitcoin (BTC) - Blockstream API (free)")
    print("   • Ethereum (ETH) - Etherscan free tier + Ethplorer")
    print("   • Solana (SOL) - Public RPC endpoints")
    print("   • Tron (TRX) - Public TronGrid API")
    print("   • Polygon (MATIC) - Public RPC endpoints")
    print("   • BSC - Public RPC endpoints")
    
    print("\n🆓 All APIs are FREE - no paid subscriptions required!")
    
    print("\n📚 Documentation:")
    print("   • README.md - Complete documentation")
    print("   • Examples and use cases included")
    
    print("\n" + "=" * 60)
    print("🕵️  ChainAnalyzer v2.0.0 - Ready for Action!")
    print("=" * 60)

def main():
    """Main installation function."""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Installation failed. Please check the error messages above.")
        sys.exit(1)
    
    # Create configuration
    if not create_config_directory():
        print("\n❌ Configuration setup failed.")
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("\n❌ Directory creation failed.")
        sys.exit(1)
    
    # Verify installation
    if not verify_installation():
        print("\n❌ Installation verification failed.")
        sys.exit(1)
    
    # Print usage instructions
    print_usage_instructions()

if __name__ == "__main__":
    main() 

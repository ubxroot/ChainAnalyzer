"""
Configuration Manager Module
============================

Manages configuration for ChainAnalyzer:
- API key management
- Default settings
- User preferences
- Environment-specific configurations
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages configuration for ChainAnalyzer."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config = self._load_default_config()
        self._load_user_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        config_dir = Path.home() / ".chainanalyzer"
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "config.json")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            "api_keys": {
                "etherscan": os.getenv("ETHERSCAN_API_KEY", ""),
                "polygonscan": os.getenv("POLYGONSCAN_API_KEY", ""),
                "bscscan": os.getenv("BSCSCAN_API_KEY", ""),
                "trongrid": os.getenv("TRONGRID_API_KEY", ""),
                "chainalysis": os.getenv("CHAINALYSIS_API_KEY", ""),
                "bitcoin_abuse": os.getenv("BITCOIN_ABUSE_API_KEY", "")
            },
            "blockchain_configs": {
                "bitcoin": {
                    "enabled": True,
                    "api_endpoints": [
                        "https://blockstream.info/api",
                        "https://mempool.space/api"
                    ],
                    "rate_limit": 60
                },
                "ethereum": {
                    "enabled": True,
                    "api_endpoints": [
                        "https://api.etherscan.io/api",
                        "https://api.ethplorer.io"
                    ],
                    "rate_limit": 5
                },
                "solana": {
                    "enabled": True,
                    "api_endpoints": [
                        "https://api.mainnet-beta.solana.com",
                        "https://solana-api.projectserum.com"
                    ],
                    "rate_limit": 100
                },
                "tron": {
                    "enabled": True,
                    "api_endpoints": [
                        "https://api.trongrid.io",
                        "https://api.shasta.trongrid.io"
                    ],
                    "rate_limit": 20
                },
                "polygon": {
                    "enabled": True,
                    "api_endpoints": [
                        "https://api.polygonscan.com/api",
                        "https://polygon-rpc.com"
                    ],
                    "rate_limit": 5
                },
                "bsc": {
                    "enabled": True,
                    "api_endpoints": [
                        "https://api.bscscan.com/api",
                        "https://bsc-dataseed.binance.org"
                    ],
                    "rate_limit": 5
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
                "update_interval": 3600,  # 1 hour
                "blacklist_sources": [
                    "cryptoscamdb",
                    "chainabuse",
                    "cryptoscam"
                ],
                "reputation_sources": [
                    "etherscan_tags",
                    "bitcoin_abuse",
                    "chainalysis"
                ]
            },
            "monitoring": {
                "enabled": True,
                "check_interval": 30,  # seconds
                "alert_thresholds": {
                    "volume": 10000,  # USD
                    "frequency": 10,  # transactions per minute
                    "suspicious_patterns": True
                }
            },
            "logging": {
                "level": "INFO",
                "log_directory": "logs",
                "max_file_size": 10 * 1024 * 1024,  # 10MB
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
            }
        }
    
    def _load_user_config(self):
        """Load user configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    self._merge_config(self.config, user_config)
                    logger.info(f"Loaded user configuration from {self.config_file}")
            else:
                self.save_config()
                logger.info(f"Created default configuration at {self.config_file}")
        except Exception as e:
            logger.error(f"Error loading user configuration: {e}")
    
    def _merge_config(self, base_config: Dict[str, Any], user_config: Dict[str, Any]):
        """Recursively merge user configuration with base configuration."""
        for key, value in user_config.items():
            if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
                self._merge_config(base_config[key], value)
            else:
                base_config[key] = value
    
    def load_config(self) -> Dict[str, Any]:
        """Load and return the current configuration."""
        return self.config.copy()
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            config_dir = Path(self.config_file).parent
            config_dir.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, default=str)
            
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key (supports dot notation)."""
        try:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                value = value[k]
            
            return value
        except (KeyError, TypeError):
            return default
    
    def set_config(self, key: str, value: Any):
        """Set a configuration value by key (supports dot notation)."""
        try:
            keys = key.split('.')
            config = self.config
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the value
            config[keys[-1]] = value
            
            # Save configuration
            self.save_config()
            
            logger.info(f"Configuration updated: {key} = {value}")
        except Exception as e:
            logger.error(f"Error setting configuration: {e}")
    
    def reset_config(self):
        """Reset configuration to defaults."""
        self.config = self._load_default_config()
        self.save_config()
        logger.info("Configuration reset to defaults")
    
    def update_api_key(self, service: str, api_key: str):
        """Update API key for a specific service."""
        if "api_keys" not in self.config:
            self.config["api_keys"] = {}
        
        self.config["api_keys"][service] = api_key
        self.save_config()
        logger.info(f"API key updated for {service}")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service."""
        return self.config.get("api_keys", {}).get(service)
    
    def enable_blockchain(self, blockchain: str):
        """Enable a specific blockchain."""
        if blockchain in self.config.get("blockchain_configs", {}):
            self.config["blockchain_configs"][blockchain]["enabled"] = True
            self.save_config()
            logger.info(f"Blockchain {blockchain} enabled")
    
    def disable_blockchain(self, blockchain: str):
        """Disable a specific blockchain."""
        if blockchain in self.config.get("blockchain_configs", {}):
            self.config["blockchain_configs"][blockchain]["enabled"] = False
            self.save_config()
            logger.info(f"Blockchain {blockchain} disabled")
    
    def get_enabled_blockchains(self) -> list:
        """Get list of enabled blockchains."""
        enabled = []
        for blockchain, config in self.config.get("blockchain_configs", {}).items():
            if config.get("enabled", True):
                enabled.append(blockchain)
        return enabled
    
    def update_risk_thresholds(self, thresholds: Dict[str, float]):
        """Update risk thresholds."""
        self.config["risk_thresholds"].update(thresholds)
        self.save_config()
        logger.info("Risk thresholds updated")
    
    def get_risk_thresholds(self) -> Dict[str, float]:
        """Get current risk thresholds."""
        return self.config.get("risk_thresholds", {}).copy()
    
    def update_monitoring_settings(self, settings: Dict[str, Any]):
        """Update monitoring settings."""
        self.config["monitoring"].update(settings)
        self.save_config()
        logger.info("Monitoring settings updated")
    
    def get_monitoring_settings(self) -> Dict[str, Any]:
        """Get current monitoring settings."""
        return self.config.get("monitoring", {}).copy()
    
    def validate_config(self) -> Dict[str, list]:
        """Validate configuration and return any issues."""
        issues = {
            "warnings": [],
            "errors": []
        }
        
        # Check for missing API keys
        api_keys = self.config.get("api_keys", {})
        required_apis = ["etherscan", "polygonscan", "bscscan"]
        
        for api in required_apis:
            if not api_keys.get(api):
                issues["warnings"].append(f"Missing API key for {api}")
        
        # Check for enabled blockchains
        enabled_blockchains = self.get_enabled_blockchains()
        if not enabled_blockchains:
            issues["errors"].append("No blockchains are enabled")
        
        # Check for valid risk thresholds
        risk_thresholds = self.config.get("risk_thresholds", {})
        if not all(0 <= threshold <= 1 for threshold in risk_thresholds.values()):
            issues["errors"].append("Risk thresholds must be between 0 and 1")
        
        return issues
    
    def export_config(self, format: str = "json") -> str:
        """Export configuration in specified format."""
        if format.lower() == "json":
            return json.dumps(self.config, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_config(self, config_data: Dict[str, Any]):
        """Import configuration from dictionary."""
        try:
            self._merge_config(self.config, config_data)
            self.save_config()
            logger.info("Configuration imported successfully")
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration."""
        return {
            "enabled_blockchains": self.get_enabled_blockchains(),
            "api_keys_configured": len([k for k, v in self.config.get("api_keys", {}).items() if v]),
            "risk_thresholds": self.get_risk_thresholds(),
            "monitoring_enabled": self.config.get("monitoring", {}).get("enabled", False),
            "threat_intelligence_enabled": self.config.get("threat_intelligence", {}).get("enabled", False),
            "log_level": self.config.get("logging", {}).get("level", "INFO")
        } 

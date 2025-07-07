# utils/config.py

import json
from pathlib import Path
from typing import Dict, Any
import logging

logger = logging.getLogger("ChainAnalyzer") # Use the logger from utils.logger

# Path to the custom configuration file for API keys and settings
# This file will be located in the user's home directory.
CONFIG_FILE_PATH = Path.home() / ".chainanalyzer_config.json"

def load_config() -> Dict[str, Any]:
    """
    Loads configuration from a JSON file in the user's home directory.
    If the file doesn't exist, it creates a default one.
    """
    if CONFIG_FILE_PATH.exists():
        try:
            with open(CONFIG_FILE_PATH, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {CONFIG_FILE_PATH}")
                return config
        except json.JSONDecodeError:
            logger.error(f"Error parsing config file {CONFIG_FILE_PATH}. Using default config.", exc_info=True)
            return _get_default_config()
    else:
        default_config = _get_default_config()
        try:
            with open(CONFIG_FILE_PATH, 'w') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"Created default config file at {CONFIG_FILE_PATH}")
        except IOError:
            logger.error(f"Could not write default config file to {CONFIG_FILE_PATH}. Using default config.", exc_info=True)
        return default_config

def _get_default_config() -> Dict[str, Any]:
    """Returns a default configuration dictionary."""
    return {
        "api_keys": {
            "bitcoin": "YOUR_BLOCKCHAIN_INFO_API_KEY", # Blockchain.info might not require, but good practice
            "ethereum": "YOUR_ETHERSCAN_API_KEY", # Crucial for Etherscan
            "solana": "YOUR_SOLANA_API_KEY", # Placeholder for future expansion
            "tron": "YOUR_TRON_API_KEY" # Placeholder for future expansion
        },
        "risk_thresholds": {
            "high_risk_score": 70,
            "medium_risk_score": 40,
            "high_risk_depth": 5 # Example: transactions going beyond 5 hops might be riskier
        },
        "alert_settings": {
            "enable_slack": False,
            "slack_webhook_url": ""
        }
    }


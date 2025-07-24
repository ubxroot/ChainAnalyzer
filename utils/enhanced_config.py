# utils/enhanced_config.py
import json
from pathlib import Path

class EnhancedConfigManager:
    """Enhanced configuration manager."""
    
    def __init__(self):
        self.config_path = Path.home() / ".chainanalyzer" / "config.json"
        self.default_config = {
            "blockchain_configs": {
                "ethereum": {"enabled": True, "rate_limit": 5},
                "bitcoin": {"enabled": True, "rate_limit": 10},
                "solana": {"enabled": True, "rate_limit": 40}
            },
            "analysis_settings": {
                "default_max_hops": 5,
                "default_depth": 3
            },
            "risk_thresholds": {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.8,
                "critical": 0.9
            }
        }
    
    def load_config(self) -> dict:
        """Load configuration."""
        if not self.config_path.exists():
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.default_config, f, indent=2)
        
        with open(self.config_path, 'r') as f:
            return json.load(f)

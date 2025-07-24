# utils/cache_manager.py
from typing import Any, Optional
import json
import os
from datetime import datetime, timedelta

class CacheManager:
    """Cache management utility."""
    
    def __init__(self, config: dict):
        self.config = config
        self.cache_dir = "cache"
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached data."""
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                data = json.load(f)
                # Check if cache is still valid (1 hour expiry)
                cache_time = datetime.fromisoformat(data['timestamp'])
                if datetime.now() - cache_time < timedelta(hours=1):
                    return data['value']
        return None
        
    def set(self, key: str, value: Any):
        """Set cached data."""
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        data = {
            'timestamp': datetime.now().isoformat(),
            'value': value
        }
        with open(cache_file, 'w') as f:
            json.dump(data, f, default=str)

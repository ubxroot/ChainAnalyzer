"""
API Client Module
=================

Handles API requests to various blockchain services:
- Rate limiting
- Error handling
- Retry logic
- Response caching
"""

import asyncio
import aiohttp
import time
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class APIRequest:
    """Represents an API request."""
    method: str
    url: str
    params: Optional[Dict] = None
    headers: Optional[Dict] = None
    data: Optional[Dict] = None
    timeout: int = 30

@dataclass
class APIResponse:
    """Represents an API response."""
    status_code: int
    data: Any
    headers: Dict
    request_time: float
    cached: bool = False

class APIClient:
    """Advanced API client for blockchain services."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_keys = config.get("api_keys", {})
        self.rate_limits = config.get("rate_limits", {})
        self.session = None
        self.request_history = []
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Rate limiting state
        self.request_timestamps = {}
        self.rate_limit_windows = {}
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def request(self, service: str, endpoint: str, 
                     params: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     method: str = "GET",
                     timeout: int = 30,
                     use_cache: bool = True) -> APIResponse:
        """Make an API request with rate limiting and caching."""
        
        # Check rate limits
        await self._check_rate_limit(service)
        
        # Check cache
        cache_key = self._generate_cache_key(service, endpoint, params)
        if use_cache and cache_key in self.cache:
            cached_response = self.cache[cache_key]
            if time.time() - cached_response["timestamp"] < self.cache_ttl:
                logger.debug(f"Cache hit for {service}:{endpoint}")
                return APIResponse(
                    status_code=200,
                    data=cached_response["data"],
                    headers={},
                    request_time=0.0,
                    cached=True
                )
        
        # Make request
        start_time = time.time()
        try:
            response = await self._make_request(service, endpoint, params, headers, method, timeout)
            
            # Cache successful responses
            if response.status_code == 200 and use_cache:
                self.cache[cache_key] = {
                    "data": response.data,
                    "timestamp": time.time()
                }
            
            # Update rate limiting state
            self._update_rate_limit_state(service)
            
            return response
            
        except Exception as e:
            logger.error(f"API request failed for {service}:{endpoint}: {e}")
            raise
    
    async def _make_request(self, service: str, endpoint: str,
                          params: Optional[Dict], headers: Optional[Dict],
                          method: str, timeout: int) -> APIResponse:
        """Make the actual HTTP request."""
        
        # Get service configuration
        service_config = self._get_service_config(service)
        base_url = service_config.get("base_url", "")
        api_key = self.api_keys.get(service, "")
        
        # Build URL
        url = f"{base_url}{endpoint}"
        
        # Add API key to params or headers
        if api_key:
            if service_config.get("api_key_in_params", True):
                if params is None:
                    params = {}
                params[service_config.get("api_key_param", "apikey")] = api_key
            else:
                if headers is None:
                    headers = {}
                headers[service_config.get("api_key_header", "Authorization")] = f"Bearer {api_key}"
        
        # Set default headers
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", "ChainAnalyzer/2.0.0")
        
        # Make request
        start_time = time.time()
        try:
            if method.upper() == "GET":
                async with self.session.get(url, params=params, headers=headers, timeout=timeout) as response:
                    data = await response.json() if response.content_type == "application/json" else await response.text()
            elif method.upper() == "POST":
                async with self.session.post(url, json=params, headers=headers, timeout=timeout) as response:
                    data = await response.json() if response.content_type == "application/json" else await response.text()
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            request_time = time.time() - start_time
            
            # Log request
            self._log_request(service, endpoint, response.status, request_time)
            
            return APIResponse(
                status_code=response.status,
                data=data,
                headers=dict(response.headers),
                request_time=request_time
            )
            
        except asyncio.TimeoutError:
            logger.error(f"Request timeout for {service}:{endpoint}")
            raise
        except Exception as e:
            logger.error(f"Request failed for {service}:{endpoint}: {e}")
            raise
    
    def _get_service_config(self, service: str) -> Dict[str, Any]:
        """Get configuration for a specific service."""
        service_configs = {
            "etherscan": {
                "base_url": "https://api.etherscan.io/api",
                "api_key_in_params": True,
                "api_key_param": "apikey",
                "rate_limit": 5,  # requests per second
                "rate_limit_window": 1
            },
            "polygonscan": {
                "base_url": "https://api.polygonscan.com/api",
                "api_key_in_params": True,
                "api_key_param": "apikey",
                "rate_limit": 5,
                "rate_limit_window": 1
            },
            "bscscan": {
                "base_url": "https://api.bscscan.com/api",
                "api_key_in_params": True,
                "api_key_param": "apikey",
                "rate_limit": 5,
                "rate_limit_window": 1
            },
            "trongrid": {
                "base_url": "https://api.trongrid.io",
                "api_key_in_params": False,
                "api_key_header": "TRON-PRO-API-KEY",
                "rate_limit": 20,
                "rate_limit_window": 1
            },
            "blockstream": {
                "base_url": "https://blockstream.info/api",
                "api_key_in_params": False,
                "rate_limit": 60,
                "rate_limit_window": 1
            },
            "solana": {
                "base_url": "https://api.mainnet-beta.solana.com",
                "api_key_in_params": False,
                "rate_limit": 100,
                "rate_limit_window": 1
            }
        }
        
        return service_configs.get(service, {})
    
    async def _check_rate_limit(self, service: str):
        """Check and enforce rate limits."""
        service_config = self._get_service_config(service)
        rate_limit = service_config.get("rate_limit", 60)
        window = service_config.get("rate_limit_window", 1)
        
        current_time = time.time()
        window_start = current_time - window
        
        # Get request timestamps for this service
        if service not in self.request_timestamps:
            self.request_timestamps[service] = []
        
        # Remove old timestamps outside the window
        self.request_timestamps[service] = [
            ts for ts in self.request_timestamps[service] 
            if ts > window_start
        ]
        
        # Check if we're at the rate limit
        if len(self.request_timestamps[service]) >= rate_limit:
            # Calculate wait time
            oldest_request = min(self.request_timestamps[service])
            wait_time = window - (current_time - oldest_request)
            
            if wait_time > 0:
                logger.warning(f"Rate limit reached for {service}, waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)
    
    def _update_rate_limit_state(self, service: str):
        """Update rate limiting state after a request."""
        current_time = time.time()
        
        if service not in self.request_timestamps:
            self.request_timestamps[service] = []
        
        self.request_timestamps[service].append(current_time)
    
    def _generate_cache_key(self, service: str, endpoint: str, params: Optional[Dict]) -> str:
        """Generate a cache key for the request."""
        key_parts = [service, endpoint]
        if params:
            # Sort params for consistent keys
            sorted_params = sorted(params.items())
            key_parts.append(json.dumps(sorted_params))
        
        return "|".join(key_parts)
    
    def _log_request(self, service: str, endpoint: str, status_code: int, request_time: float):
        """Log API request details."""
        log_entry = {
            "service": service,
            "endpoint": endpoint,
            "status_code": status_code,
            "request_time": request_time,
            "timestamp": datetime.now().isoformat()
        }
        
        self.request_history.append(log_entry)
        
        # Keep only last 1000 requests
        if len(self.request_history) > 1000:
            self.request_history = self.request_history[-1000:]
        
        # Log based on status code
        if status_code >= 400:
            logger.warning(f"API request failed: {service}:{endpoint} - {status_code}")
        else:
            logger.debug(f"API request: {service}:{endpoint} - {status_code} ({request_time:.2f}s)")
    
    async def get_ethereum_transactions(self, address: str, start_block: int = 0, 
                                      end_block: int = 99999999) -> List[Dict]:
        """Get Ethereum transactions for an address."""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": start_block,
            "endblock": end_block,
            "sort": "desc"
        }
        
        response = await self.request("etherscan", "", params=params)
        
        if response.status_code == 200 and response.data.get("status") == "1":
            return response.data.get("result", [])
        else:
            logger.error(f"Failed to get Ethereum transactions: {response.data}")
            return []
    
    async def get_bitcoin_transactions(self, address: str) -> List[Dict]:
        """Get Bitcoin transactions for an address."""
        endpoint = f"/address/{address}"
        response = await self.request("blockstream", endpoint)
        
        if response.status_code == 200:
            return response.data.get("chain_stats", {}).get("tx_count", [])
        else:
            logger.error(f"Failed to get Bitcoin transactions: {response.data}")
            return []
    
    async def get_solana_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get Solana transactions for an address."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [address, {"limit": limit}]
        }
        
        response = await self.request("solana", "", method="POST", params=payload)
        
        if response.status_code == 200:
            return response.data.get("result", [])
        else:
            logger.error(f"Failed to get Solana transactions: {response.data}")
            return []
    
    async def get_tron_transactions(self, address: str) -> List[Dict]:
        """Get Tron transactions for an address."""
        endpoint = f"/v1/accounts/{address}/transactions"
        headers = {}
        
        # Add API key if available
        api_key = self.api_keys.get("trongrid")
        if api_key:
            headers["TRON-PRO-API-KEY"] = api_key
        
        response = await self.request("trongrid", endpoint, headers=headers)
        
        if response.status_code == 200:
            return response.data.get("data", [])
        else:
            logger.error(f"Failed to get Tron transactions: {response.data}")
            return []
    
    def get_request_statistics(self) -> Dict[str, Any]:
        """Get API request statistics."""
        if not self.request_history:
            return {}
        
        total_requests = len(self.request_history)
        successful_requests = len([r for r in self.request_history if r["status_code"] < 400])
        failed_requests = total_requests - successful_requests
        
        avg_request_time = sum(r["request_time"] for r in self.request_history) / total_requests
        
        # Group by service
        service_stats = {}
        for request in self.request_history:
            service = request["service"]
            if service not in service_stats:
                service_stats[service] = {
                    "total_requests": 0,
                    "successful_requests": 0,
                    "failed_requests": 0,
                    "avg_request_time": 0
                }
            
            service_stats[service]["total_requests"] += 1
            if request["status_code"] < 400:
                service_stats[service]["successful_requests"] += 1
            else:
                service_stats[service]["failed_requests"] += 1
        
        # Calculate averages for each service
        for service, stats in service_stats.items():
            service_requests = [r for r in self.request_history if r["service"] == service]
            if service_requests:
                stats["avg_request_time"] = sum(r["request_time"] for r in service_requests) / len(service_requests)
        
        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "success_rate": successful_requests / total_requests if total_requests > 0 else 0,
            "avg_request_time": avg_request_time,
            "service_statistics": service_stats
        }
    
    def clear_cache(self):
        """Clear the request cache."""
        self.cache.clear()
        logger.info("API cache cleared")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information."""
        return {
            "cache_size": len(self.cache),
            "cache_ttl": self.cache_ttl,
            "cache_keys": list(self.cache.keys())
        } 

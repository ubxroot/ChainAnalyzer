"""
API Client Module
=================

Handles API requests to various blockchain services using ONLY FREE APIs:
- Rate limiting
- Error handling
- Retry logic
- Response caching
- Fallback endpoints
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
    """Advanced API client for blockchain services using only free APIs."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
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
        
        # Make request with fallback endpoints
        start_time = time.time()
        try:
            response = await self._make_request_with_fallback(service, endpoint, params, headers, method, timeout)
            
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
    
    async def _make_request_with_fallback(self, service: str, endpoint: str,
                                        params: Optional[Dict], headers: Optional[Dict],
                                        method: str, timeout: int) -> APIResponse:
        """Make request with fallback to alternative endpoints."""
        
        # Get service configuration
        service_config = self._get_service_config(service)
        endpoints = service_config.get("api_endpoints", [])
        
        last_error = None
        
        for base_url in endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = await self._make_single_request(url, params, headers, method, timeout)
                if response.status_code < 500:  # Don't retry on client errors
                    return response
                last_error = f"Server error from {base_url}: {response.status_code}"
            except Exception as e:
                last_error = f"Error with {base_url}: {e}"
                logger.debug(f"Failed to get data from {base_url}: {e}")
                continue
        
        # If all endpoints failed, raise the last error
        raise Exception(f"All endpoints failed for {service}: {last_error}")
    
    async def _make_single_request(self, url: str, params: Optional[Dict],
                                 headers: Optional[Dict], method: str, timeout: int) -> APIResponse:
        """Make a single HTTP request."""
        
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
            self._log_request(url, response.status, request_time)
            
            return APIResponse(
                status_code=response.status,
                data=data,
                headers=dict(response.headers),
                request_time=request_time
            )
            
        except asyncio.TimeoutError:
            logger.error(f"Request timeout for {url}")
            raise
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
            raise
    
    def _get_service_config(self, service: str) -> Dict[str, Any]:
        """Get configuration for a specific service."""
        service_configs = {
            "bitcoin": {
                "api_endpoints": [
                    "https://blockstream.info/api",
                    "https://mempool.space/api",
                    "https://api.btcscan.org/v1",
                    "https://api.blockchair.com/bitcoin"
                ],
                "rate_limit": 60,  # requests per second
                "rate_limit_window": 1,
                "free": True
            },
            "ethereum": {
                "api_endpoints": [
                    "https://api.etherscan.io/api",
                    "https://api.ethplorer.io",
                    "https://api.blockchair.com/ethereum"
                ],
                "rate_limit": 5,
                "rate_limit_window": 1,
                "free": True
            },
            "solana": {
                "api_endpoints": [
                    "https://api.mainnet-beta.solana.com",
                    "https://solana-api.projectserum.com",
                    "https://rpc.ankr.com/solana"
                ],
                "rate_limit": 100,
                "rate_limit_window": 1,
                "free": True
            },
            "tron": {
                "api_endpoints": [
                    "https://api.trongrid.io",
                    "https://api.shasta.trongrid.io"
                ],
                "rate_limit": 20,
                "rate_limit_window": 1,
                "free": True
            },
            "polygon": {
                "api_endpoints": [
                    "https://polygon-rpc.com",
                    "https://rpc-mainnet.maticvigil.com",
                    "https://rpc-mainnet.matic.network"
                ],
                "rate_limit": 30,
                "rate_limit_window": 1,
                "free": True
            },
            "bsc": {
                "api_endpoints": [
                    "https://bsc-dataseed.binance.org",
                    "https://bsc-dataseed1.defibit.io",
                    "https://bsc-dataseed1.ninicoin.io"
                ],
                "rate_limit": 30,
                "rate_limit_window": 1,
                "free": True
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
    
    def _log_request(self, url: str, status_code: int, request_time: float):
        """Log API request details."""
        log_entry = {
            "url": url,
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
            logger.warning(f"API request failed: {url} - {status_code}")
        else:
            logger.debug(f"API request: {url} - {status_code} ({request_time:.2f}s)")
    
    async def get_ethereum_transactions(self, address: str, start_block: int = 0, 
                                      end_block: int = 99999999) -> List[Dict]:
        """Get Ethereum transactions for an address using free endpoints (Etherscan, Ethplorer, Blockchair)."""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": start_block,
            "endblock": end_block,
            "sort": "desc",
            "apikey": "YourApiKeyToken"  # Free tier key
        }
        try:
            response = await self.request("ethereum", "", params=params)
            if response.status_code == 200 and response.data.get("status") == "1":
                return response.data.get("result", [])
            else:
                logger.warning(f"Etherscan failed, trying Ethplorer")
                # Fallback to Ethplorer
                ethplorer_url = f"https://api.ethplorer.io/getAddressHistory/{address}?apiKey=freekey"
                async with aiohttp.ClientSession() as session:
                    async with session.get(ethplorer_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data.get("operations", [])
                logger.warning(f"Ethplorer failed, trying Blockchair")
                # Fallback to Blockchair
                blockchair_url = f"https://api.blockchair.com/ethereum/dashboards/address/{address}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(blockchair_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            txs = data.get("data", {}).get(address, {}).get("transactions", [])
                            return txs
        except Exception as e:
            logger.error(f"Failed to get Ethereum transactions: {e}")
        return []
    
    async def get_bitcoin_transactions(self, address: str) -> List[Dict]:
        """Get Bitcoin transactions for an address using multiple free APIs (Blockstream, btcscan.org, Blockchair)."""
        # Try Blockstream first
        try:
            response = await self.request("bitcoin", f"/address/{address}/txs")
            if response.status_code == 200:
                return response.data
            else:
                logger.warning(f"Blockstream failed, trying btcscan.org")
                # Try btcscan.org
                btcscan_url = f"https://api.btcscan.org/v1/address/{address}/transactions"
                async with aiohttp.ClientSession() as session:
                    async with session.get(btcscan_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data.get("data", [])
                logger.warning(f"btcscan.org failed, trying Blockchair")
                # Try Blockchair
                blockchair_url = f"https://api.blockchair.com/bitcoin/dashboards/address/{address}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(blockchair_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            txs = data.get("data", {}).get(address, {}).get("transactions", [])
                            return txs
        except Exception as e:
            logger.error(f"Failed to get Bitcoin transactions: {e}")
        return []
    
    async def get_solana_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get Solana transactions for an address using public RPC."""
        try:
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
        
        except Exception as e:
            logger.error(f"Failed to get Solana transactions: {e}")
        
        return []
    
    async def get_tron_transactions(self, address: str) -> List[Dict]:
        """Get Tron transactions for an address using public API."""
        try:
            response = await self.request("tron", f"/v1/accounts/{address}/transactions")
            
            if response.status_code == 200:
                return response.data.get("data", [])
            else:
                logger.error(f"Failed to get Tron transactions: {response.data}")
        
        except Exception as e:
            logger.error(f"Failed to get Tron transactions: {e}")
        
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
            # Extract service from URL
            url = request["url"]
            service = "unknown"
            for s in ["bitcoin", "ethereum", "solana", "tron", "polygon", "bsc"]:
                if s in url:
                    service = s
                    break
            
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
            service_requests = [r for r in self.request_history if service in r["url"]]
            if service_requests:
                stats["avg_request_time"] = sum(r["request_time"] for r in service_requests) / len(service_requests)
        
        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "success_rate": successful_requests / total_requests if total_requests > 0 else 0,
            "avg_request_time": avg_request_time,
            "service_statistics": service_stats,
            "free_apis_only": True
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
            "cache_keys": list(self.cache.keys()),
            "free_apis_only": True
        } 

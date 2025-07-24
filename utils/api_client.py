# utils/multi_api_client.py
import aiohttp
import asyncio
from typing import Dict, List, Optional, Any
import time
from dataclasses import dataclass
import logging

@dataclass
class APIEndpoint:
    name: str
    base_url: str
    rate_limit: int
    headers: Dict[str, str]
    is_free: bool
    priority: int

class MultiAPIClient:
    """Enhanced multi-API client with fallback and load balancing."""
    
    def __init__(self, config: dict):
        self.config = config
        self.session = None
        self.rate_limiters = {}
        self.api_endpoints = self._initialize_endpoints()
        self.logger = logging.getLogger(__name__)
    
    def _initialize_endpoints(self) -> Dict[str, List[APIEndpoint]]:
        """Initialize all available API endpoints."""
        return {
            "ethereum": [
                APIEndpoint("etherscan", "https://api.etherscan.io/api", 5, {}, True, 1),
                APIEndpoint("ethplorer", "https://api.ethplorer.io", 5, {}, True, 2),
                APIEndpoint("alchemy", "https://eth-mainnet.g.alchemy.com/v2", 100, {}, True, 3),
                APIEndpoint("infura", "https://mainnet.infura.io/v3", 100, {}, True, 4),
                APIEndpoint("moralis", "https://deep-index.moralis.io/api/v2", 25, {}, True, 5),
            ],
            "bitcoin": [
                APIEndpoint("blockstream", "https://blockstream.info/api", 10, {}, True, 1),
                APIEndpoint("blockchair", "https://api.blockchair.com/bitcoin", 30, {}, True, 2),
                APIEndpoint("btc_com", "https://chain.api.btc.com/v3", 60, {}, True, 3),
                APIEndpoint("blockcypher", "https://api.blockcypher.com/v1/btc/main", 200, {}, True, 4),
            ],
            "solana": [
                APIEndpoint("solana_rpc", "https://api.mainnet-beta.solana.com", 100, {}, True, 1),
                APIEndpoint("quicknode", "https://solana-mainnet.g.alchemy.com/v2", 300, {}, True, 2),
                APIEndpoint("helius", "https://rpc.helius.xyz", 100, {}, True, 3),
            ],
            "polygon": [
                APIEndpoint("polygonscan", "https://api.polygonscan.com/api", 5, {}, True, 1),
                APIEndpoint("alchemy_polygon", "https://polygon-mainnet.g.alchemy.com/v2", 100, {}, True, 2),
                APIEndpoint("moralis_polygon", "https://deep-index.moralis.io/api/v2", 25, {}, True, 3),
            ],
            "bsc": [
                APIEndpoint("bscscan", "https://api.bscscan.com/api", 5, {}, True, 1),
                APIEndpoint("moralis_bsc", "https://deep-index.moralis.io/api/v2", 25, {}, True, 2),
            ],
            "avalanche": [
                APIEndpoint("snowtrace", "https://api.snowtrace.io/api", 5, {}, True, 1),
                APIEndpoint("alchemy_avax", "https://avax-mainnet.g.alchemy.com/v2", 100, {}, True, 2),
            ],
            "fantom": [
                APIEndpoint("ftmscan", "https://api.ftmscan.com/api", 5, {}, True, 1),
            ],
            "arbitrum": [
                APIEndpoint("arbiscan", "https://api.arbiscan.io/api", 5, {}, True, 1),
                APIEndpoint("alchemy_arbitrum", "https://arb-mainnet.g.alchemy.com/v2", 100, {}, True, 2),
            ],
            "optimism": [
                APIEndpoint("optimistic_etherscan", "https://api-optimistic.etherscan.io/api", 5, {}, True, 1),
                APIEndpoint("alchemy_optimism", "https://opt-mainnet.g.alchemy.com/v2", 100, {}, True, 2),
            ],
            "tron": [
                APIEndpoint("trongrid", "https://api.trongrid.io", 100, {}, True, 1),
                APIEndpoint("tronscan", "https://apilist.tronscan.org/api", 60, {}, True, 2),
            ]
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_transactions(self, address: str, blockchain: str, 
                             limit: int = 100) -> List[Dict[str, Any]]:
        """Get transactions with automatic failover."""
        endpoints = self.api_endpoints.get(blockchain.lower(), [])
        
        for endpoint in sorted(endpoints, key=lambda x: x.priority):
            try:
                await self._wait_for_rate_limit(endpoint)
                transactions = await self._fetch_transactions(endpoint, address, limit)
                if transactions:
                    return transactions
            except Exception as e:
                self.logger.warning(f"Failed to fetch from {endpoint.name}: {e}")
                continue
        
        return []
    
    async def _fetch_transactions(self, endpoint: APIEndpoint, 
                                address: str, limit: int) -> List[Dict[str, Any]]:
        """Fetch transactions from specific endpoint."""
        if endpoint.name == "etherscan":
            return await self._fetch_etherscan_transactions(endpoint, address, limit)
        elif endpoint.name == "blockstream":
            return await self._fetch_blockstream_transactions(endpoint, address)
        elif endpoint.name == "moralis":
            return await self._fetch_moralis_transactions(endpoint, address, limit)
        # Add more endpoint-specific methods
        
        return []
    
    async def _fetch_etherscan_transactions(self, endpoint: APIEndpoint, 
                                          address: str, limit: int) -> List[Dict[str, Any]]:
        """Fetch from Etherscan API."""
        url = f"{endpoint.base_url}"
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": limit,
            "sort": "desc"
        }
        
        async with self.session.get(url, params=params) as response:
            data = await response.json()
            return data.get("result", []) if data.get("status") == "1" else []
    
    async def _fetch_blockstream_transactions(self, endpoint: APIEndpoint, 
                                            address: str) -> List[Dict[str, Any]]:
        """Fetch from Blockstream API."""
        url = f"{endpoint.base_url}/address/{address}/txs"
        
        async with self.session.get(url) as response:
            if response.status == 200:
                return await response.json()
            return []
    
    async def _fetch_moralis_transactions(self, endpoint: APIEndpoint, 
                                        address: str, limit: int) -> List[Dict[str, Any]]:
        """Fetch from Moralis API."""
        # Note: Moralis requires API key in production
        url = f"{endpoint.base_url}/{address}"
        params = {"limit": limit}
        
        async with self.session.get(url, params=params) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("result", [])
            return []
    
    async def _wait_for_rate_limit(self, endpoint: APIEndpoint):
        """Wait for rate limit compliance."""
        if endpoint.name not in self.rate_limiters:
            self.rate_limiters[endpoint.name] = []
        
        current_time = time.time()
        timestamps = self.rate_limiters[endpoint.name]
        
        # Remove timestamps older than 1 second
        timestamps[:] = [t for t in timestamps if current_time - t < 1.0]
        
        # Wait if we've hit the rate limit
        if len(timestamps) >= endpoint.rate_limit:
            sleep_time = 1.0 - (current_time - timestamps[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        timestamps.append(current_time)
    
    async def get_token_info(self, token_address: str, blockchain: str) -> Dict[str, Any]:
        """Get token information."""
        # Implementation for token info retrieval
        return {}
    
    async def get_defi_positions(self, address: str, blockchain: str) -> List[Dict[str, Any]]:
        """Get DeFi positions for an address."""
        # Implementation for DeFi position retrieval
        return []
    
    async def get_nft_holdings(self, address: str, blockchain: str) -> List[Dict[str, Any]]:
        """Get NFT holdings for an address."""
        # Implementation for NFT holdings retrieval
        return []

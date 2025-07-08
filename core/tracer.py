"""
Multi-Chain Transaction Tracer
==============================

Supports tracing transactions across multiple blockchains:
- Bitcoin (BTC)
- Ethereum (ETH)
- Solana (SOL)
- Tron (TRX)
- Polygon (MATIC)
- Binance Smart Chain (BSC)

Provides comprehensive transaction analysis and relationship mapping.
"""

import asyncio
import aiohttp
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)

class MultiChainTracer:
    """Advanced multi-blockchain transaction tracer."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_keys = config.get("api_keys", {})
        self.session = None
        self.rate_limits = {
            "requests_per_minute": 60,
            "requests_per_hour": 1000
        }
        
        # Blockchain-specific configurations
        self.blockchain_configs = {
            "bitcoin": {
                "api_endpoints": [
                    "https://blockstream.info/api",
                    "https://mempool.space/api"
                ],
                "address_pattern": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$",
                "explorer": "https://blockstream.info"
            },
            "ethereum": {
                "api_endpoints": [
                    "https://api.etherscan.io/api",
                    "https://api.ethplorer.io"
                ],
                "address_pattern": r"^0x[a-fA-F0-9]{40}$",
                "explorer": "https://etherscan.io"
            },
            "solana": {
                "api_endpoints": [
                    "https://api.mainnet-beta.solana.com",
                    "https://solana-api.projectserum.com"
                ],
                "address_pattern": r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
                "explorer": "https://solscan.io"
            },
            "tron": {
                "api_endpoints": [
                    "https://api.trongrid.io",
                    "https://api.shasta.trongrid.io"
                ],
                "address_pattern": r"^T[A-Za-z1-9]{33}$",
                "explorer": "https://tronscan.org"
            },
            "polygon": {
                "api_endpoints": [
                    "https://api.polygonscan.com/api",
                    "https://polygon-rpc.com"
                ],
                "address_pattern": r"^0x[a-fA-F0-9]{40}$",
                "explorer": "https://polygonscan.com"
            },
            "bsc": {
                "api_endpoints": [
                    "https://api.bscscan.com/api",
                    "https://bsc-dataseed.binance.org"
                ],
                "address_pattern": r"^0x[a-fA-F0-9]{40}$",
                "explorer": "https://bscscan.com"
            }
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    def validate_address(self, address: str, currency: str) -> bool:
        """Validate blockchain address format."""
        if currency.lower() not in self.blockchain_configs:
            logger.error(f"Unsupported currency: {currency}")
            return False
        
        pattern = self.blockchain_configs[currency.lower()]["address_pattern"]
        return bool(re.match(pattern, address))
    
    def trace_transactions(self, address: str, currency: str, max_hops: int = 5, 
                          depth: int = 3, verbose: bool = False) -> Optional[Dict]:
        """Trace transactions for a given address."""
        try:
            if not self.validate_address(address, currency):
                logger.error(f"Invalid {currency} address: {address}")
                return None
            
            # Run async tracing
            return asyncio.run(self._async_trace_transactions(address, currency, max_hops, depth, verbose))
        
        except Exception as e:
            logger.error(f"Error tracing transactions: {e}")
            return None
    
    async def _async_trace_transactions(self, address: str, currency: str, 
                                      max_hops: int, depth: int, verbose: bool) -> Dict:
        """Async implementation of transaction tracing."""
        
        result = {
            "address": address,
            "currency": currency,
            "transactions": [],
            "addresses": set(),
            "total_volume": 0.0,
            "trace_depth": depth,
            "max_hops": max_hops,
            "timestamp": datetime.now().isoformat(),
            "relationships": {},
            "suspicious_patterns": []
        }
        
        # Get initial transactions
        initial_txs = await self._get_transactions(address, currency, verbose)
        if not initial_txs:
            return result
        
        result["transactions"].extend(initial_txs)
        result["addresses"].add(address)
        
        # Add connected addresses
        for tx in initial_txs:
            result["addresses"].update(tx.get("from_addresses", []))
            result["addresses"].update(tx.get("to_addresses", []))
        
        # Trace deeper if requested
        if depth > 1:
            await self._trace_deeper(result, currency, depth, max_hops, verbose)
        
        # Calculate total volume
        result["total_volume"] = sum(tx.get("value_usd", 0) for tx in result["transactions"])
        
        # Convert set to list for JSON serialization
        result["addresses"] = list(result["addresses"])
        
        # Analyze relationships
        result["relationships"] = self._analyze_relationships(result["transactions"])
        
        # Detect suspicious patterns
        result["suspicious_patterns"] = self._detect_suspicious_patterns(result)
        
        return result
    
    async def _get_transactions(self, address: str, currency: str, verbose: bool) -> List[Dict]:
        """Get transactions for an address from blockchain APIs."""
        transactions = []
        
        try:
            if currency.lower() == "bitcoin":
                transactions = await self._get_bitcoin_transactions(address, verbose)
            elif currency.lower() == "ethereum":
                transactions = await self._get_ethereum_transactions(address, verbose)
            elif currency.lower() == "solana":
                transactions = await self._get_solana_transactions(address, verbose)
            elif currency.lower() == "tron":
                transactions = await self._get_tron_transactions(address, verbose)
            elif currency.lower() == "polygon":
                transactions = await self._get_polygon_transactions(address, verbose)
            elif currency.lower() == "bsc":
                transactions = await self._get_bsc_transactions(address, verbose)
            
        except Exception as e:
            logger.error(f"Error getting transactions for {currency}: {e}")
        
        return transactions
    
    async def _get_bitcoin_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Bitcoin transactions using Blockstream API."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get address info
                url = f"https://blockstream.info/api/address/{address}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Get transaction details
                        for tx_id in data.get("chain_stats", {}).get("tx_count", []):
                            tx_url = f"https://blockstream.info/api/tx/{tx_id}"
                            async with session.get(tx_url) as tx_response:
                                if tx_response.status == 200:
                                    tx_data = await tx_response.json()
                                    
                                    transaction = {
                                        "tx_hash": tx_id,
                                        "block_height": tx_data.get("status", {}).get("block_height"),
                                        "timestamp": tx_data.get("status", {}).get("block_time"),
                                        "value_btc": tx_data.get("value", 0) / 100000000,  # Convert satoshis
                                        "value_usd": 0,  # Would need price API
                                        "fee": tx_data.get("fee", 0) / 100000000,
                                        "from_addresses": [vin.get("prevout", {}).get("scriptpubkey_address") for vin in tx_data.get("vin", [])],
                                        "to_addresses": [vout.get("scriptpubkey_address") for vout in tx_data.get("vout", [])],
                                        "confirmations": tx_data.get("status", {}).get("confirmed", False)
                                    }
                                    transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Bitcoin transactions: {e}")
        
        return transactions
    
    async def _get_ethereum_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Ethereum transactions using Etherscan API."""
        transactions = []
        api_key = self.api_keys.get("etherscan")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.etherscan.io/api"
                params = {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "sort": "desc",
                    "apikey": api_key or "YourApiKeyToken"
                }
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get("status") == "1":
                            for tx in data.get("result", []):
                                transaction = {
                                    "tx_hash": tx.get("hash"),
                                    "block_number": int(tx.get("blockNumber", 0)),
                                    "timestamp": int(tx.get("timeStamp", 0)),
                                    "value_eth": float(tx.get("value", 0)) / 1e18,
                                    "value_usd": 0,  # Would need price API
                                    "gas_price": int(tx.get("gasPrice", 0)),
                                    "gas_used": int(tx.get("gasUsed", 0)),
                                    "from_address": tx.get("from"),
                                    "to_address": tx.get("to"),
                                    "confirmations": int(tx.get("confirmations", 0)),
                                    "is_error": tx.get("isError") == "1"
                                }
                                transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Ethereum transactions: {e}")
        
        return transactions
    
    async def _get_solana_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Solana transactions using Solana RPC."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.mainnet-beta.solana.com"
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getSignaturesForAddress",
                    "params": [address, {"limit": 100}]
                }
                
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for sig_info in data.get("result", []):
                            # Get transaction details
                            tx_payload = {
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "getTransaction",
                                "params": [sig_info.get("signature"), {"encoding": "json"}]
                            }
                            
                            async with session.post(url, json=tx_payload) as tx_response:
                                if tx_response.status == 200:
                                    tx_data = await tx_response.json()
                                    tx_result = tx_data.get("result", {})
                                    
                                    if tx_result:
                                        transaction = {
                                            "tx_hash": sig_info.get("signature"),
                                            "block_time": sig_info.get("blockTime"),
                                            "slot": sig_info.get("slot"),
                                            "fee": tx_result.get("meta", {}).get("fee", 0),
                                            "from_address": address,
                                            "to_addresses": [],  # Would need to parse instructions
                                            "confirmations": 1 if tx_result.get("meta", {}).get("err") is None else 0
                                        }
                                        transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Solana transactions: {e}")
        
        return transactions
    
    async def _get_tron_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Tron transactions using TronGrid API."""
        transactions = []
        api_key = self.api_keys.get("trongrid")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.trongrid.io/v1/accounts/{address}/transactions"
                headers = {"TRON-PRO-API-KEY": api_key} if api_key else {}
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for tx in data.get("data", []):
                            transaction = {
                                "tx_hash": tx.get("txID"),
                                "block_number": tx.get("blockNumber"),
                                "timestamp": tx.get("block_timestamp"),
                                "value_trx": float(tx.get("raw_data", {}).get("contract", [{}])[0].get("parameter", {}).get("value", {}).get("amount", 0)) / 1e6,
                                "value_usd": 0,
                                "from_address": tx.get("raw_data", {}).get("contract", [{}])[0].get("parameter", {}).get("value", {}).get("owner_address"),
                                "to_address": tx.get("raw_data", {}).get("contract", [{}])[0].get("parameter", {}).get("value", {}).get("to_address"),
                                "confirmations": 1
                            }
                            transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Tron transactions: {e}")
        
        return transactions
    
    async def _get_polygon_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Polygon transactions using Polygonscan API."""
        transactions = []
        api_key = self.api_keys.get("polygonscan")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.polygonscan.com/api"
                params = {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "sort": "desc",
                    "apikey": api_key or "YourApiKeyToken"
                }
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get("status") == "1":
                            for tx in data.get("result", []):
                                transaction = {
                                    "tx_hash": tx.get("hash"),
                                    "block_number": int(tx.get("blockNumber", 0)),
                                    "timestamp": int(tx.get("timeStamp", 0)),
                                    "value_matic": float(tx.get("value", 0)) / 1e18,
                                    "value_usd": 0,
                                    "gas_price": int(tx.get("gasPrice", 0)),
                                    "gas_used": int(tx.get("gasUsed", 0)),
                                    "from_address": tx.get("from"),
                                    "to_address": tx.get("to"),
                                    "confirmations": int(tx.get("confirmations", 0)),
                                    "is_error": tx.get("isError") == "1"
                                }
                                transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Polygon transactions: {e}")
        
        return transactions
    
    async def _get_bsc_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get BSC transactions using BSCScan API."""
        transactions = []
        api_key = self.api_keys.get("bscscan")
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.bscscan.com/api"
                params = {
                    "module": "account",
                    "action": "txlist",
                    "address": address,
                    "startblock": 0,
                    "endblock": 99999999,
                    "sort": "desc",
                    "apikey": api_key or "YourApiKeyToken"
                }
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get("status") == "1":
                            for tx in data.get("result", []):
                                transaction = {
                                    "tx_hash": tx.get("hash"),
                                    "block_number": int(tx.get("blockNumber", 0)),
                                    "timestamp": int(tx.get("timeStamp", 0)),
                                    "value_bnb": float(tx.get("value", 0)) / 1e18,
                                    "value_usd": 0,
                                    "gas_price": int(tx.get("gasPrice", 0)),
                                    "gas_used": int(tx.get("gasUsed", 0)),
                                    "from_address": tx.get("from"),
                                    "to_address": tx.get("to"),
                                    "confirmations": int(tx.get("confirmations", 0)),
                                    "is_error": tx.get("isError") == "1"
                                }
                                transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting BSC transactions: {e}")
        
        return transactions
    
    async def _trace_deeper(self, result: Dict, currency: str, depth: int, 
                           max_hops: int, verbose: bool):
        """Trace transactions deeper by following connected addresses."""
        addresses_to_trace = list(result["addresses"])[:max_hops]
        
        for addr in addresses_to_trace:
            if addr != result["address"]:  # Skip original address
                try:
                    addr_txs = await self._get_transactions(addr, currency, verbose)
                    if addr_txs:
                        result["transactions"].extend(addr_txs)
                        # Add new addresses
                        for tx in addr_txs:
                            result["addresses"].update(tx.get("from_addresses", []))
                            result["addresses"].update(tx.get("to_addresses", []))
                except Exception as e:
                    logger.error(f"Error tracing address {addr}: {e}")
    
    def _analyze_relationships(self, transactions: List[Dict]) -> Dict:
        """Analyze relationships between addresses."""
        relationships = {
            "address_connections": {},
            "transaction_patterns": {},
            "volume_analysis": {}
        }
        
        # Build address connections
        for tx in transactions:
            from_addrs = tx.get("from_addresses", [])
            to_addrs = tx.get("to_addresses", [])
            
            for from_addr in from_addrs:
                if from_addr not in relationships["address_connections"]:
                    relationships["address_connections"][from_addr] = {"sends_to": [], "receives_from": []}
                
                for to_addr in to_addrs:
                    if to_addr not in relationships["address_connections"]:
                        relationships["address_connections"][to_addr] = {"sends_to": [], "receives_from": []}
                    
                    relationships["address_connections"][from_addr]["sends_to"].append(to_addr)
                    relationships["address_connections"][to_addr]["receives_from"].append(from_addr)
        
        return relationships
    
    def _detect_suspicious_patterns(self, result: Dict) -> List[str]:
        """Detect suspicious transaction patterns."""
        patterns = []
        
        # High frequency transactions
        if len(result["transactions"]) > 100:
            patterns.append("High transaction frequency")
        
        # Large volume transactions
        if result["total_volume"] > 1000000:  # $1M threshold
            patterns.append("Large transaction volume")
        
        # Multiple small transactions (potential mixing)
        small_txs = [tx for tx in result["transactions"] if tx.get("value_usd", 0) < 100]
        if len(small_txs) > 50:
            patterns.append("Multiple small transactions (potential mixing)")
        
        # Rapid transactions
        if len(result["transactions"]) > 10:
            timestamps = [tx.get("timestamp", 0) for tx in result["transactions"] if tx.get("timestamp")]
            if timestamps:
                time_diff = max(timestamps) - min(timestamps)
                if time_diff < 3600:  # Less than 1 hour
                    patterns.append("Rapid transaction sequence")
        
        return patterns 

"""
Multi-Chain Transaction Tracer
==============================

Supports tracing transactions across multiple blockchains using ONLY FREE APIs:
- Bitcoin (BTC) - Blockstream API (free)
- Ethereum (ETH) - Etherscan free tier (limited but no key required)
- Solana (SOL) - Public RPC endpoints (free)
- Tron (TRX) - Public endpoints (free)
- Polygon (MATIC) - Public RPC (free)
- BSC - Public RPC (free)

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
    """Advanced multi-blockchain transaction tracer using only free APIs."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
        self.rate_limits = {
            "requests_per_minute": 60,
            "requests_per_hour": 1000
        }
        
        # Blockchain-specific configurations - ALL FREE APIs
        self.blockchain_configs = {
            "bitcoin": {
                "api_endpoints": [
                    "https://blockstream.info/api",
                    "https://mempool.space/api"
                ],
                "address_pattern": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$",
                "explorer": "https://blockstream.info",
                "free": True
            },
            "ethereum": {
                "api_endpoints": [
                    "https://api.etherscan.io/api",
                    "https://api.ethplorer.io"
                ],
                "address_pattern": r"^0x[a-fA-F0-9]{40}$",
                "explorer": "https://etherscan.io",
                "free": True,
                "use_free_tier": True
            },
            "solana": {
                "api_endpoints": [
                    "https://api.mainnet-beta.solana.com",
                    "https://solana-api.projectserum.com",
                    "https://rpc.ankr.com/solana"
                ],
                "address_pattern": r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
                "explorer": "https://solscan.io",
                "free": True
            },
            "tron": {
                "api_endpoints": [
                    "https://api.trongrid.io",
                    "https://api.shasta.trongrid.io"
                ],
                "address_pattern": r"^T[A-Za-z1-9]{33}$",
                "explorer": "https://tronscan.org",
                "free": True
            },
            "polygon": {
                "api_endpoints": [
                    "https://polygon-rpc.com",
                    "https://rpc-mainnet.maticvigil.com",
                    "https://rpc-mainnet.matic.network"
                ],
                "address_pattern": r"^0x[a-fA-F0-9]{40}$",
                "explorer": "https://polygonscan.com",
                "free": True
            },
            "bsc": {
                "api_endpoints": [
                    "https://bsc-dataseed.binance.org",
                    "https://bsc-dataseed1.defibit.io",
                    "https://bsc-dataseed1.ninicoin.io"
                ],
                "address_pattern": r"^0x[a-fA-F0-9]{40}$",
                "explorer": "https://bscscan.com",
                "free": True
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
                transactions = await self._get_ethereum_transactions_free(address, verbose)
            elif currency.lower() == "solana":
                transactions = await self._get_solana_transactions(address, verbose)
            elif currency.lower() == "tron":
                transactions = await self._get_tron_transactions_free(address, verbose)
            elif currency.lower() == "polygon":
                transactions = await self._get_polygon_transactions_free(address, verbose)
            elif currency.lower() == "bsc":
                transactions = await self._get_bsc_transactions_free(address, verbose)
            
        except Exception as e:
            logger.error(f"Error getting transactions for {currency}: {e}")
        
        return transactions
    
    async def _get_bitcoin_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Bitcoin transactions using Blockstream API (FREE)."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get address info
                url = f"https://blockstream.info/api/address/{address}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Get recent transaction hashes
                        tx_hashes = []
                        if "chain_stats" in data:
                            # Get funded transactions
                            funded_txs = data["chain_stats"].get("funded_txo_count", 0)
                            if funded_txs > 0:
                                # Get recent transactions
                                tx_url = f"https://blockstream.info/api/address/{address}/txs"
                                async with session.get(tx_url) as tx_response:
                                    if tx_response.status == 200:
                                        tx_list = await tx_response.json()
                                        tx_hashes = [tx["txid"] for tx in tx_list[:20]]  # Limit to 20
                        
                        # Get transaction details
                        for tx_id in tx_hashes:
                            tx_url = f"https://blockstream.info/api/tx/{tx_id}"
                            async with session.get(tx_url) as tx_response:
                                if tx_response.status == 200:
                                    tx_data = await tx_response.json()
                                    
                                    # Extract addresses
                                    from_addresses = []
                                    to_addresses = []
                                    
                                    for vin in tx_data.get("vin", []):
                                        if "prevout" in vin and "scriptpubkey_address" in vin["prevout"]:
                                            from_addresses.append(vin["prevout"]["scriptpubkey_address"])
                                    
                                    for vout in tx_data.get("vout", []):
                                        if "scriptpubkey_address" in vout:
                                            to_addresses.append(vout["scriptpubkey_address"])
                                    
                                    transaction = {
                                        "tx_hash": tx_id,
                                        "block_height": tx_data.get("status", {}).get("block_height"),
                                        "timestamp": tx_data.get("status", {}).get("block_time"),
                                        "value_btc": sum(vout.get("value", 0) for vout in tx_data.get("vout", [])) / 100000000,
                                        "value_usd": 0,  # Would need price API
                                        "fee": tx_data.get("fee", 0) / 100000000 if tx_data.get("fee") else 0,
                                        "from_addresses": from_addresses,
                                        "to_addresses": to_addresses,
                                        "confirmations": tx_data.get("status", {}).get("confirmed", False)
                                    }
                                    transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Bitcoin transactions: {e}")
        
        return transactions
    
    async def _get_ethereum_transactions_free(self, address: str, verbose: bool) -> List[Dict]:
        """Get Ethereum transactions using free endpoints (no API key required)."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try multiple free endpoints
                endpoints = [
                    f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=desc&apikey=YourApiKeyToken",
                    f"https://api.ethplorer.io/getAddressHistory/{address}?apiKey=freekey"
                ]
                
                for endpoint in endpoints:
                    try:
                        async with session.get(endpoint, timeout=30) as response:
                            if response.status == 200:
                                data = await response.json()
                                
                                if "result" in data and data.get("status") == "1":
                                    # Etherscan format
                                    for tx in data.get("result", [])[:10]:  # Limit to 10 for free tier
                                        transaction = {
                                            "tx_hash": tx.get("hash"),
                                            "block_number": int(tx.get("blockNumber", 0)),
                                            "timestamp": int(tx.get("timeStamp", 0)),
                                            "value_eth": float(tx.get("value", 0)) / 1e18,
                                            "value_usd": 0,
                                            "gas_price": int(tx.get("gasPrice", 0)),
                                            "gas_used": int(tx.get("gasUsed", 0)),
                                            "from_address": tx.get("from"),
                                            "to_address": tx.get("to"),
                                            "confirmations": int(tx.get("confirmations", 0)),
                                            "is_error": tx.get("isError") == "1"
                                        }
                                        transactions.append(transaction)
                                    break
                                
                                elif "operations" in data:
                                    # Ethplorer format
                                    for op in data.get("operations", [])[:10]:
                                        transaction = {
                                            "tx_hash": op.get("transactionHash"),
                                            "block_number": op.get("blockNumber"),
                                            "timestamp": op.get("timestamp"),
                                            "value_eth": float(op.get("value", 0)) / 1e18,
                                            "value_usd": 0,
                                            "from_address": op.get("from"),
                                            "to_address": op.get("to"),
                                            "confirmations": 1
                                        }
                                        transactions.append(transaction)
                                    break
                    
                    except Exception as e:
                        logger.debug(f"Failed to get data from {endpoint}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error getting Ethereum transactions: {e}")
        
        return transactions
    
    async def _get_solana_transactions(self, address: str, verbose: bool) -> List[Dict]:
        """Get Solana transactions using public RPC (FREE)."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try multiple public RPC endpoints
                rpc_endpoints = [
                    "https://api.mainnet-beta.solana.com",
                    "https://solana-api.projectserum.com",
                    "https://rpc.ankr.com/solana"
                ]
                
                for rpc_url in rpc_endpoints:
                    try:
                        payload = {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "getSignaturesForAddress",
                            "params": [address, {"limit": 10}]
                        }
                        
                        async with session.post(rpc_url, json=payload, timeout=30) as response:
                            if response.status == 200:
                                data = await response.json()
                                
                                if "result" in data:
                                    for sig_info in data.get("result", []):
                                        # Get transaction details
                                        tx_payload = {
                                            "jsonrpc": "2.0",
                                            "id": 1,
                                            "method": "getTransaction",
                                            "params": [sig_info.get("signature"), {"encoding": "json"}]
                                        }
                                        
                                        async with session.post(rpc_url, json=tx_payload) as tx_response:
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
                                    break
                    
                    except Exception as e:
                        logger.debug(f"Failed to get data from {rpc_url}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error getting Solana transactions: {e}")
        
        return transactions
    
    async def _get_tron_transactions_free(self, address: str, verbose: bool) -> List[Dict]:
        """Get Tron transactions using public endpoints (FREE)."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Use public Tron API (no key required for basic info)
                url = f"https://api.trongrid.io/v1/accounts/{address}/transactions"
                
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for tx in data.get("data", [])[:10]:  # Limit to 10
                            # Extract transaction details
                            raw_data = tx.get("raw_data", {})
                            contracts = raw_data.get("contract", [])
                            
                            for contract in contracts:
                                if contract.get("type") == "TransferContract":
                                    parameter = contract.get("parameter", {})
                                    value = parameter.get("value", {})
                                    
                                    transaction = {
                                        "tx_hash": tx.get("txID"),
                                        "block_number": tx.get("blockNumber"),
                                        "timestamp": tx.get("block_timestamp"),
                                        "value_trx": float(value.get("amount", 0)) / 1e6,
                                        "value_usd": 0,
                                        "from_address": value.get("owner_address"),
                                        "to_address": value.get("to_address"),
                                        "confirmations": 1
                                    }
                                    transactions.append(transaction)
        
        except Exception as e:
            logger.error(f"Error getting Tron transactions: {e}")
        
        return transactions
    
    async def _get_polygon_transactions_free(self, address: str, verbose: bool) -> List[Dict]:
        """Get Polygon transactions using public RPC (FREE)."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Use public Polygon RPC
                rpc_endpoints = [
                    "https://polygon-rpc.com",
                    "https://rpc-mainnet.maticvigil.com"
                ]
                
                for rpc_url in rpc_endpoints:
                    try:
                        # Get transaction count
                        payload = {
                            "jsonrpc": "2.0",
                            "method": "eth_getTransactionCount",
                            "params": [address, "latest"],
                            "id": 1
                        }
                        
                        async with session.post(rpc_url, json=payload, timeout=30) as response:
                            if response.status == 200:
                                # For Polygon, we'll use a simplified approach
                                # Get recent blocks and check for transactions
                                for block_num in range(1000, 0, -1):  # Check last 1000 blocks
                                    block_payload = {
                                        "jsonrpc": "2.0",
                                        "method": "eth_getBlockByNumber",
                                        "params": [hex(block_num), True],
                                        "id": 1
                                    }
                                    
                                    async with session.post(rpc_url, json=block_payload) as block_response:
                                        if block_response.status == 200:
                                            block_data = await block_response.json()
                                            block = block_data.get("result", {})
                                            
                                            for tx in block.get("transactions", []):
                                                if tx.get("from", "").lower() == address.lower() or tx.get("to", "").lower() == address.lower():
                                                    transaction = {
                                                        "tx_hash": tx.get("hash"),
                                                        "block_number": int(tx.get("blockNumber", "0"), 16),
                                                        "timestamp": 0,  # Would need block timestamp
                                                        "value_matic": float(int(tx.get("value", "0"), 16)) / 1e18,
                                                        "value_usd": 0,
                                                        "from_address": tx.get("from"),
                                                        "to_address": tx.get("to"),
                                                        "confirmations": 1
                                                    }
                                                    transactions.append(transaction)
                                                    
                                                    if len(transactions) >= 10:  # Limit results
                                                        break
                                        
                                        if len(transactions) >= 10:
                                            break
                                
                                if transactions:
                                    break
                    
                    except Exception as e:
                        logger.debug(f"Failed to get data from {rpc_url}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error getting Polygon transactions: {e}")
        
        return transactions
    
    async def _get_bsc_transactions_free(self, address: str, verbose: bool) -> List[Dict]:
        """Get BSC transactions using public RPC (FREE)."""
        transactions = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Use public BSC RPC
                rpc_endpoints = [
                    "https://bsc-dataseed.binance.org",
                    "https://bsc-dataseed1.defibit.io"
                ]
                
                for rpc_url in rpc_endpoints:
                    try:
                        # Similar approach to Polygon
                        for block_num in range(1000, 0, -1):  # Check last 1000 blocks
                            block_payload = {
                                "jsonrpc": "2.0",
                                "method": "eth_getBlockByNumber",
                                "params": [hex(block_num), True],
                                "id": 1
                            }
                            
                            async with session.post(rpc_url, json=block_payload, timeout=30) as response:
                                if response.status == 200:
                                    block_data = await response.json()
                                    block = block_data.get("result", {})
                                    
                                    for tx in block.get("transactions", []):
                                        if tx.get("from", "").lower() == address.lower() or tx.get("to", "").lower() == address.lower():
                                            transaction = {
                                                "tx_hash": tx.get("hash"),
                                                "block_number": int(tx.get("blockNumber", "0"), 16),
                                                "timestamp": 0,
                                                "value_bnb": float(int(tx.get("value", "0"), 16)) / 1e18,
                                                "value_usd": 0,
                                                "from_address": tx.get("from"),
                                                "to_address": tx.get("to"),
                                                "confirmations": 1
                                            }
                                            transactions.append(transaction)
                                            
                                            if len(transactions) >= 10:  # Limit results
                                                break
                                
                                if len(transactions) >= 10:
                                    break
                        
                        if transactions:
                            break
                    
                    except Exception as e:
                        logger.debug(f"Failed to get data from {rpc_url}: {e}")
                        continue
        
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

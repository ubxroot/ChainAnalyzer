"""
Real-Time Monitor Module
========================

Provides real-time monitoring capabilities for blockchain transactions:
- Live transaction monitoring
- Alert generation
- Threshold-based notifications
- Continuous surveillance
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class RealTimeMonitor:
    """Real-time blockchain transaction monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_keys = config.get("api_keys", {})
        self.monitoring = False
        self.alert_callbacks = []
        self.known_transactions = set()
        
        # Monitoring configuration
        self.monitor_config = {
            "check_interval": 30,  # seconds
            "max_retries": 3,
            "retry_delay": 5,
            "alert_thresholds": {
                "volume": 10000,  # USD
                "frequency": 10,  # transactions per minute
                "suspicious_patterns": True
            }
        }
    
    def start_monitoring(self, address: str, currency: str, duration: int = 3600,
                        alert_threshold: float = 1000.0, output_file: Optional[str] = None):
        """Start real-time monitoring of an address."""
        try:
            self.monitoring = True
            logger.info(f"Starting monitoring for {address} on {currency}")
            
            # Run monitoring loop
            asyncio.run(self._monitor_loop(address, currency, duration, alert_threshold, output_file))
            
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            self.monitoring = False
        except Exception as e:
            logger.error(f"Error in monitoring: {e}")
            self.monitoring = False
    
    async def _monitor_loop(self, address: str, currency: str, duration: int,
                           alert_threshold: float, output_file: Optional[str]):
        """Main monitoring loop."""
        start_time = time.time()
        alerts = []
        
        async with aiohttp.ClientSession() as session:
            while self.monitoring and (time.time() - start_time) < duration:
                try:
                    # Get latest transactions
                    new_transactions = await self._get_latest_transactions(session, address, currency)
                    
                    # Process new transactions
                    for tx in new_transactions:
                        if tx.get("tx_hash") not in self.known_transactions:
                            self.known_transactions.add(tx.get("tx_hash"))
                            
                            # Check for alerts
                            alert = await self._check_for_alerts(tx, alert_threshold)
                            if alert:
                                alerts.append(alert)
                                await self._trigger_alert(alert, output_file)
                    
                    # Wait before next check
                    await asyncio.sleep(self.monitor_config["check_interval"])
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    await asyncio.sleep(self.monitor_config["retry_delay"])
        
        # Generate monitoring report
        await self._generate_monitoring_report(alerts, address, currency, output_file)
    
    async def _get_latest_transactions(self, session: aiohttp.ClientSession,
                                     address: str, currency: str) -> List[Dict]:
        """Get latest transactions for the monitored address."""
        try:
            if currency.lower() == "ethereum":
                return await self._get_ethereum_transactions(session, address)
            elif currency.lower() == "bitcoin":
                return await self._get_bitcoin_transactions(session, address)
            elif currency.lower() == "solana":
                return await self._get_solana_transactions(session, address)
            else:
                logger.warning(f"Unsupported currency for monitoring: {currency}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting latest transactions: {e}")
            return []
    
    async def _get_ethereum_transactions(self, session: aiohttp.ClientSession,
                                       address: str) -> List[Dict]:
        """Get latest Ethereum transactions."""
        api_key = self.api_keys.get("etherscan")
        if not api_key:
            logger.warning("No Etherscan API key provided for monitoring")
            return []
        
        try:
            url = "https://api.etherscan.io/api"
            params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "sort": "desc",
                "apikey": api_key
            }
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("status") == "1":
                        transactions = []
                        for tx in data.get("result", [])[:10]:  # Get latest 10
                            transaction = {
                                "tx_hash": tx.get("hash"),
                                "block_number": int(tx.get("blockNumber", 0)),
                                "timestamp": int(tx.get("timeStamp", 0)),
                                "value_eth": float(tx.get("value", 0)) / 1e18,
                                "value_usd": 0,  # Would need price API
                                "from_address": tx.get("from"),
                                "to_address": tx.get("to"),
                                "confirmations": int(tx.get("confirmations", 0))
                            }
                            transactions.append(transaction)
                        return transactions
                        
        except Exception as e:
            logger.error(f"Error getting Ethereum transactions: {e}")
        
        return []
    
    async def _get_bitcoin_transactions(self, session: aiohttp.ClientSession,
                                      address: str) -> List[Dict]:
        """Get latest Bitcoin transactions."""
        try:
            url = f"https://blockstream.info/api/address/{address}"
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    transactions = []
                    
                    # Get recent transaction hashes
                    tx_hashes = data.get("chain_stats", {}).get("funded_txo_count", [])
                    
                    for tx_hash in tx_hashes[:10]:  # Get latest 10
                        tx_url = f"https://blockstream.info/api/tx/{tx_hash}"
                        async with session.get(tx_url) as tx_response:
                            if tx_response.status == 200:
                                tx_data = await tx_response.json()
                                transaction = {
                                    "tx_hash": tx_hash,
                                    "block_height": tx_data.get("status", {}).get("block_height"),
                                    "timestamp": tx_data.get("status", {}).get("block_time"),
                                    "value_btc": tx_data.get("value", 0) / 100000000,
                                    "value_usd": 0,
                                    "confirmations": tx_data.get("status", {}).get("confirmed", False)
                                }
                                transactions.append(transaction)
                    
                    return transactions
                    
        except Exception as e:
            logger.error(f"Error getting Bitcoin transactions: {e}")
        
        return []
    
    async def _get_solana_transactions(self, session: aiohttp.ClientSession,
                                     address: str) -> List[Dict]:
        """Get latest Solana transactions."""
        try:
            url = "https://api.mainnet-beta.solana.com"
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSignaturesForAddress",
                "params": [address, {"limit": 10}]
            }
            
            async with session.post(url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    transactions = []
                    
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
                                        "confirmations": 1 if tx_result.get("meta", {}).get("err") is None else 0
                                    }
                                    transactions.append(transaction)
                    
                    return transactions
                    
        except Exception as e:
            logger.error(f"Error getting Solana transactions: {e}")
        
        return []
    
    async def _check_for_alerts(self, transaction: Dict, alert_threshold: float) -> Optional[Dict]:
        """Check if a transaction triggers an alert."""
        alert = None
        
        # Volume-based alert
        value_usd = transaction.get("value_usd", 0)
        if value_usd > alert_threshold:
            alert = {
                "type": "high_volume",
                "severity": "HIGH" if value_usd > alert_threshold * 10 else "MEDIUM",
                "description": f"High volume transaction: ${value_usd:,.2f}",
                "transaction": transaction,
                "timestamp": datetime.now().isoformat()
            }
        
        # Frequency-based alert (would need to track transaction frequency)
        # This is a simplified implementation
        
        # Suspicious pattern alert
        if self._is_suspicious_transaction(transaction):
            alert = {
                "type": "suspicious_pattern",
                "severity": "HIGH",
                "description": "Suspicious transaction pattern detected",
                "transaction": transaction,
                "timestamp": datetime.now().isoformat()
            }
        
        return alert
    
    def _is_suspicious_transaction(self, transaction: Dict) -> bool:
        """Check if a transaction has suspicious characteristics."""
        # Check for known mixer addresses
        mixer_addresses = [
            "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # Tornado Cash
            "0xdd4c48c0b24039969fc16d1cdf626eab821d3384"   # Tornado Cash
        ]
        
        from_addr = transaction.get("from_address", "")
        to_addr = transaction.get("to_address", "")
        
        if from_addr in mixer_addresses or to_addr in mixer_addresses:
            return True
        
        # Check for micro-transactions (potential dust attack)
        value_usd = transaction.get("value_usd", 0)
        if value_usd < 0.01:  # Less than 1 cent
            return True
        
        return False
    
    async def _trigger_alert(self, alert: Dict, output_file: Optional[str]):
        """Trigger an alert notification."""
        try:
            # Log alert
            logger.warning(f"ALERT: {alert['type']} - {alert['description']}")
            
            # Save to file if specified
            if output_file:
                await self._save_alert_to_file(alert, output_file)
            
            # Execute alert callbacks
            for callback in self.alert_callbacks:
                try:
                    await callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            # Print alert to console
            print(f"\n🚨 ALERT: {alert['type'].upper()}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Description: {alert['description']}")
            print(f"   Transaction: {alert['transaction'].get('tx_hash', 'Unknown')}")
            print(f"   Time: {alert['timestamp']}\n")
            
        except Exception as e:
            logger.error(f"Error triggering alert: {e}")
    
    async def _save_alert_to_file(self, alert: Dict, output_file: str):
        """Save alert to output file."""
        try:
            alert_data = {
                "alert": alert,
                "saved_at": datetime.now().isoformat()
            }
            
            # Append to file
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert_data) + '\n')
                
        except Exception as e:
            logger.error(f"Error saving alert to file: {e}")
    
    async def _generate_monitoring_report(self, alerts: List[Dict], address: str,
                                        currency: str, output_file: Optional[str]):
        """Generate monitoring session report."""
        try:
            report = {
                "monitoring_session": {
                    "address": address,
                    "currency": currency,
                    "start_time": datetime.now().isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "total_alerts": len(alerts),
                    "alert_summary": {}
                },
                "alerts": alerts
            }
            
            # Generate alert summary
            alert_types = {}
            for alert in alerts:
                alert_type = alert.get("type", "unknown")
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            
            report["monitoring_session"]["alert_summary"] = alert_types
            
            # Save report
            if output_file:
                report_file = output_file.replace(".txt", "_report.json")
                with open(report_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2)
                
                logger.info(f"Monitoring report saved to: {report_file}")
            
            # Print summary
            print(f"\n📊 Monitoring Session Summary")
            print(f"   Address: {address}")
            print(f"   Currency: {currency.upper()}")
            print(f"   Total Alerts: {len(alerts)}")
            print(f"   Alert Types: {alert_types}")
            
        except Exception as e:
            logger.error(f"Error generating monitoring report: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add a callback function for alerts."""
        self.alert_callbacks.append(callback)
    
    def stop_monitoring(self):
        """Stop the monitoring process."""
        self.monitoring = False
        logger.info("Monitoring stopped")
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status."""
        return {
            "monitoring": self.monitoring,
            "known_transactions": len(self.known_transactions),
            "alert_callbacks": len(self.alert_callbacks)
        } 

"""
Monitor Module
==============

Provides real-time monitoring capabilities:
- Live transaction monitoring
- Alert generation
- Threshold-based notifications
- Continuous surveillance
- Monitoring dashboards
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
import logging
import json

logger = logging.getLogger(__name__)

class TransactionMonitor:
   class TransactionMonitor:
     """Real-time transaction monitoring with alerting capabilities."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.monitoring_config = config.get("monitoring", {})
        self.alert_thresholds = self.monitoring_config.get("alert_thresholds", {})
        self.check_interval = self.monitoring_config.get("check_interval", 30)
        
        self.monitored_addresses = {}
        self.alert_callbacks = []
        self.is_monitoring = False
        self.monitoring_task = None
    
    async def start_monitoring(self, addresses: List[Dict[str, Any]], 
                             duration: Optional[int] = None) -> Dict[str, Any]:
        """Start monitoring multiple addresses."""
        
        monitoring_result = {
            "status": "started",
            "timestamp": datetime.now().isoformat(),
            "monitored_addresses": len(addresses),
            "duration": duration,
            "alerts": []
        }
        
        try:
            # Initialize monitoring for each address
            for addr_info in addresses:
                address = addr_info.get("address")
                currency = addr_info.get("currency", "ethereum")
                thresholds = addr_info.get("thresholds", self.alert_thresholds)
                
                self.monitored_addresses[address] = {
                    "currency": currency,
                    "thresholds": thresholds,
                    "last_check": None,
                    "last_transaction": None,
                    "transaction_count": 0,
                    "total_volume": 0.0,
                    "alerts": []
                }
            
            # Start monitoring loop
            self.is_monitoring = True
            self.monitoring_task = asyncio.create_task(
                self._monitoring_loop(duration)
            )
            
            logger.info(f"Started monitoring {len(addresses)} addresses")
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {e}")
            monitoring_result["status"] = "error"
            monitoring_result["error"] = str(e)
        
        return monitoring_result
    
    async def stop_monitoring(self) -> Dict[str, Any]:
        """Stop monitoring and return results."""
        
        stop_result = {
            "status": "stopped",
            "timestamp": datetime.now().isoformat(),
            "monitoring_duration": 0,
            "total_alerts": 0,
            "address_summaries": {}
        }
        
        try:
            if self.is_monitoring:
                self.is_monitoring = False
                
                if self.monitoring_task:
                    self.monitoring_task.cancel()
                    try:
                        await self.monitoring_task
                    except asyncio.CancelledError:
                        pass
                
                # Generate summaries
                for address, data in self.monitored_addresses.items():
                    stop_result["address_summaries"][address] = {
                        "currency": data["currency"],
                        "transaction_count": data["transaction_count"],
                        "total_volume": data["total_volume"],
                        "alert_count": len(data["alerts"])
                    }
                    stop_result["total_alerts"] += len(data["alerts"])
                
                logger.info("Monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {e}")
            stop_result["status"] = "error"
            stop_result["error"] = str(e)
        
        return stop_result
    
    async def _monitoring_loop(self, duration: Optional[int] = None):
        """Main monitoring loop."""
        
        start_time = time.time()
        
        while self.is_monitoring:
            try:
                # Check if duration exceeded
                if duration and (time.time() - start_time) > duration:
                    logger.info("Monitoring duration exceeded, stopping")
                    break
                
                # Check each monitored address
                for address, data in self.monitored_addresses.items():
                    await self._check_address(address, data)
                
                # Wait for next check interval
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                logger.info("Monitoring loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.check_interval)
    
    async def _check_address(self, address: str, data: Dict[str, Any]):
        """Check a single address for new transactions and alerts."""
        
        try:
            # Get recent transactions (this would use the tracer)
            # For now, we'll simulate this
            recent_transactions = await self._get_recent_transactions(address, data["currency"])
            
            if recent_transactions:
                # Update address data
                data["last_check"] = datetime.now().isoformat()
                data["transaction_count"] += len(recent_transactions)
                
                # Calculate new volume
                new_volume = sum(tx.get("value_usd", 0) for tx in recent_transactions)
                data["total_volume"] += new_volume
                
                # Check for alerts
                alerts = self._check_alerts(address, data, recent_transactions)
                
                if alerts:
                    data["alerts"].extend(alerts)
                    
                    # Trigger alert callbacks
                    for alert in alerts:
                        await self._trigger_alert_callbacks(alert)
                
                # Update last transaction
                if recent_transactions:
                    data["last_transaction"] = recent_transactions[-1]
            
        except Exception as e:
            logger.error(f"Error checking address {address}: {e}")
    
    async def _get_recent_transactions(self, address: str, currency: str) -> List[Dict[str, Any]]:
        """Get recent transactions for an address."""
        
        # This would integrate with the tracer module
        # For now, return empty list to simulate no new transactions
        return []
    
    def _check_alerts(self, address: str, data: Dict[str, Any], 
                     transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for alerts based on thresholds and patterns."""
        
        alerts = []
        thresholds = data["thresholds"]
        
        # Volume threshold alert
        volume_threshold = thresholds.get("volume", 10000)
        if data["total_volume"] > volume_threshold:
            alerts.append({
                "type": "volume_threshold",
                "address": address,
                "timestamp": datetime.now().isoformat(),
                "severity": "high",
                "message": f"Volume threshold exceeded: ${data['total_volume']:,.2f}",
                "details": {
                    "current_volume": data["total_volume"],
                    "threshold": volume_threshold
                }
            })
        
        # Frequency threshold alert
        frequency_threshold = thresholds.get("frequency", 10)
        if data["transaction_count"] > frequency_threshold:
            alerts.append({
                "type": "frequency_threshold",
                "address": address,
                "timestamp": datetime.now().isoformat(),
                "severity": "medium",
                "message": f"Transaction frequency threshold exceeded: {data['transaction_count']} transactions",
                "details": {
                    "current_count": data["transaction_count"],
                    "threshold": frequency_threshold
                }
            })
        
        # Suspicious pattern alert
        if thresholds.get("suspicious_patterns", True):
            suspicious_patterns = self._detect_suspicious_patterns(transactions)
            if suspicious_patterns:
                alerts.append({
                    "type": "suspicious_patterns",
                    "address": address,
                    "timestamp": datetime.now().isoformat(),
                    "severity": "high",
                    "message": f"Suspicious patterns detected: {', '.join(suspicious_patterns)}",
                    "details": {
                        "patterns": suspicious_patterns
                    }
                })
        
        return alerts
    
    def _detect_suspicious_patterns(self, transactions: List[Dict[str, Any]]) -> List[str]:
        """Detect suspicious patterns in transactions."""
        
        patterns = []
        
        if not transactions:
            return patterns
        
        # Multiple small transactions (potential mixing)
        small_txs = [tx for tx in transactions if tx.get("value_usd", 0) < 100]
        if len(small_txs) > len(transactions) * 0.5:
            patterns.append("multiple_small_transactions")
        
        # Rapid transactions
        if len(transactions) > 1:
            timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
            if timestamps:
                time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                rapid_txs = [diff for diff in time_diffs if diff < 60]  # Less than 1 minute
                
                if len(rapid_txs) > len(time_diffs) * 0.3:
                    patterns.append("rapid_transactions")
        
        # Round number amounts
        round_amounts = [tx for tx in transactions if tx.get("value_usd", 0) % 1000 == 0]
        if len(round_amounts) > len(transactions) * 0.3:
            patterns.append("round_number_amounts")
        
        return patterns
    
    async def _trigger_alert_callbacks(self, alert: Dict[str, Any]):
        """Trigger registered alert callbacks."""
        
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert)
                else:
                    callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def add_alert_callback(self, callback: Callable):
        """Add an alert callback function."""
        self.alert_callbacks.append(callback)
        logger.info("Alert callback added")
    
    def remove_alert_callback(self, callback: Callable):
        """Remove an alert callback function."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
            logger.info("Alert callback removed")
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        
        status = {
            "is_monitoring": self.is_monitoring,
            "monitored_addresses": len(self.monitored_addresses),
            "check_interval": self.check_interval,
            "total_alerts": sum(len(data["alerts"]) for data in self.monitored_addresses.values()),
            "address_details": {}
        }
        
        for address, data in self.monitored_addresses.items():
            status["address_details"][address] = {
                "currency": data["currency"],
                "transaction_count": data["transaction_count"],
                "total_volume": data["total_volume"],
                "alert_count": len(data["alerts"]),
                "last_check": data["last_check"]
            }
        
        return status
    
    def get_alerts(self, address: Optional[str] = None, 
                  alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts for specific address or all addresses."""
        
        all_alerts = []
        
        for addr, data in self.monitored_addresses.items():
            if address and addr != address:
                continue
            
            for alert in data["alerts"]:
                if alert_type and alert.get("type") != alert_type:
                    continue
                
                alert_copy = alert.copy()
                alert_copy["address"] = addr
                all_alerts.append(alert_copy)
        
        # Sort by timestamp
        all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        return all_alerts
    
    def export_monitoring_data(self, format: str = "json") -> str:
        """Export monitoring data in specified format."""
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "monitoring_status": self.get_monitoring_status(),
            "all_alerts": self.get_alerts(),
            "configuration": {
                "check_interval": self.check_interval,
                "alert_thresholds": self.alert_thresholds
            }
        }
        
        if format.lower() == "json":
            return json.dumps(export_data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def clear_alerts(self, address: Optional[str] = None):
        """Clear alerts for specific address or all addresses."""
        
        if address:
            if address in self.monitored_addresses:
                self.monitored_addresses[address]["alerts"] = []
                logger.info(f"Cleared alerts for address {address}")
        else:
            for addr in self.monitored_addresses:
                self.monitored_addresses[addr]["alerts"] = []
            logger.info("Cleared all alerts")
    
    def update_thresholds(self, address: str, new_thresholds: Dict[str, Any]):
        """Update alert thresholds for a specific address."""
        
        if address in self.monitored_addresses:
            self.monitored_addresses[address]["thresholds"].update(new_thresholds)
            logger.info(f"Updated thresholds for address {address}")
        else:
            logger.warning(f"Address {address} not found in monitored addresses")
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        
        total_transactions = sum(data["transaction_count"] for data in self.monitored_addresses.values())
        total_volume = sum(data["total_volume"] for data in self.monitored_addresses.values())
        total_alerts = sum(len(data["alerts"]) for data in self.monitored_addresses.values())
        
        # Alert type breakdown
        alert_types = {}
        for data in self.monitored_addresses.values():
            for alert in data["alerts"]:
                alert_type = alert.get("type", "unknown")
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        return {
            "total_monitored_addresses": len(self.monitored_addresses),
            "total_transactions": total_transactions,
            "total_volume": total_volume,
            "total_alerts": total_alerts,
            "alert_type_breakdown": alert_types,
            "monitoring_duration": 0,  # Would calculate actual duration
            "average_transactions_per_address": total_transactions / len(self.monitored_addresses) if self.monitored_addresses else 0
        }

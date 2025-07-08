"""
Risk Analyzer Module
====================

Provides comprehensive risk assessment for cryptocurrency addresses and transactions:
- Transaction risk scoring
- Address risk profiling
- Risk factor identification
- Risk level classification
- Risk trend analysis
"""

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class RiskFactor:
    """Represents a risk factor."""
    factor_type: str
    description: str
    risk_score: float
    confidence: float
    evidence: List[str]
    mitigation: Optional[str] = None

class RiskAnalyzer:
    """Advanced risk analysis for cryptocurrency transactions and addresses."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.risk_thresholds = config.get("risk_thresholds", {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.8,
            "critical": 0.9
        })
        
        # Risk factor weights
        self.risk_weights = {
            "transaction_volume": 0.25,
            "address_age": 0.15,
            "transaction_frequency": 0.20,
            "suspicious_patterns": 0.25,
            "threat_intelligence": 0.15
        }
        
        # Risk factor definitions
        self.risk_factors = {
            "high_volume": {
                "threshold": 100000,  # $100k USD
                "risk_score": 0.7,
                "description": "High transaction volume"
            },
            "new_address": {
                "threshold": 30,  # 30 days
                "risk_score": 0.5,
                "description": "Recently created address"
            },
            "high_frequency": {
                "threshold": 100,  # 100 transactions per day
                "risk_score": 0.6,
                "description": "High transaction frequency"
            },
            "mixing_indicators": {
                "risk_score": 0.8,
                "description": "Potential mixing service activity"
            },
            "exchange_interaction": {
                "risk_score": 0.4,
                "description": "Interaction with cryptocurrency exchanges"
            },
            "darknet_market": {
                "risk_score": 0.9,
                "description": "Potential darknet market activity"
            },
            "gambling_sites": {
                "risk_score": 0.6,
                "description": "Gambling site interaction"
            },
            "decentralized_exchanges": {
                "risk_score": 0.3,
                "description": "Decentralized exchange usage"
            }
        }
        
        # Known entity databases
        self.known_entities = {
            "exchanges": self._load_exchange_addresses(),
            "mixers": self._load_mixer_addresses(),
            "gambling": self._load_gambling_addresses(),
            "darknet": self._load_darknet_addresses()
        }
    
    def _load_exchange_addresses(self) -> Dict[str, List[str]]:
        """Load known exchange addresses."""
        return {
            "binance": [
                "0x28c6c06298d514db089934071355e5743bf21d60",
                "0x21a31ee1afc51d94c2efccaa2092ad1028285549"
            ],
            "coinbase": [
                "0x503828976d22510aad0201ac7ec88293211d23da",
                "0xf977814e90da44bfa03b6295a0616a897441acec"
            ],
            "kraken": [
                "0x2910543af39aba0cd09dbb2d50200b3e800a63d2",
                "0x0a869d79c7059c6b67bfc4b8f846e8f7b7f1e3c2"
            ]
        }
    
    def _load_mixer_addresses(self) -> List[str]:
        """Load known mixer addresses."""
        return [
            "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # Tornado Cash
            "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",  # Tornado Cash
            "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # Tornado Cash
            "0x722122df12d4e14e13ac3b6895a86e84145b6967"   # Tornado Cash
        ]
    
    def _load_gambling_addresses(self) -> List[str]:
        """Load known gambling site addresses."""
        return [
            "0x1d4b9b250b1bd41daa35d27bf0f09b7bd9b7e8e2",  # Example
            "0x2d4b9b250b1bd41daa35d27bf0f09b7bd9b7e8e3"   # Example
        ]
    
    def _load_darknet_addresses(self) -> List[str]:
        """Load known darknet market addresses."""
        return [
            "0x3d4b9b250b1bd41daa35d27bf0f09b7bd9b7e8e4",  # Example
            "0x4d4b9b250b1bd41daa35d27bf0f09b7bd9b7e8e5"   # Example
        ]
    
    def assess_risk(self, address: str, currency: str, trace_result: Optional[Dict] = None,
                   threat_data: Optional[Dict] = None) -> Dict:
        """Perform comprehensive risk assessment."""
        try:
            result = {
                "address": address,
                "currency": currency,
                "risk_score": 0.0,
                "risk_level": "LOW",
                "risk_factors": [],
                "risk_breakdown": {},
                "recommendations": [],
                "assessment_timestamp": datetime.now().isoformat(),
                "confidence": 0.0
            }
            
            # Analyze transaction risk
            if trace_result:
                tx_risk = self._analyze_transaction_risk(trace_result)
                result["risk_breakdown"]["transaction_risk"] = tx_risk
            
            # Analyze address risk
            addr_risk = self._analyze_address_risk(address, currency, trace_result)
            result["risk_breakdown"]["address_risk"] = addr_risk
            
            # Analyze behavioral risk
            if trace_result:
                behavior_risk = self._analyze_behavioral_risk(trace_result)
                result["risk_breakdown"]["behavioral_risk"] = behavior_risk
            
            # Incorporate threat intelligence
            if threat_data:
                threat_risk = self._analyze_threat_risk(threat_data)
                result["risk_breakdown"]["threat_risk"] = threat_risk
            
            # Calculate overall risk score
            result["risk_score"] = self._calculate_overall_risk(result["risk_breakdown"])
            result["risk_level"] = self._determine_risk_level(result["risk_score"])
            
            # Generate risk factors
            result["risk_factors"] = self._generate_risk_factors(result["risk_breakdown"])
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(result)
            
            # Calculate confidence
            result["confidence"] = self._calculate_confidence(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in risk assessment: {e}")
            return self._create_default_result(address, currency)
    
    def _analyze_transaction_risk(self, trace_result: Dict) -> Dict:
        """Analyze risk based on transaction patterns."""
        risk_score = 0.0
        factors = []
        
        transactions = trace_result.get("transactions", [])
        total_volume = trace_result.get("total_volume", 0)
        
        # Volume-based risk
        if total_volume > self.risk_factors["high_volume"]["threshold"]:
            volume_risk = min(1.0, total_volume / 1000000)  # Normalize to $1M
            risk_score += volume_risk * self.risk_factors["high_volume"]["risk_score"]
            factors.append({
                "type": "high_volume",
                "description": f"High transaction volume: ${total_volume:,.2f}",
                "risk_score": volume_risk * self.risk_factors["high_volume"]["risk_score"]
            })
        
        # Frequency-based risk
        if len(transactions) > 0:
            # Calculate average daily transactions
            if transactions:
                timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
                if timestamps:
                    time_span = max(timestamps) - min(timestamps)
                    if time_span > 0:
                        daily_txs = len(transactions) / (time_span / 86400)  # Convert to days
                        if daily_txs > self.risk_factors["high_frequency"]["threshold"]:
                            freq_risk = min(1.0, daily_txs / 1000)  # Normalize to 1000 txs/day
                            risk_score += freq_risk * self.risk_factors["high_frequency"]["risk_score"]
                            factors.append({
                                "type": "high_frequency",
                                "description": f"High transaction frequency: {daily_txs:.1f} txs/day",
                                "risk_score": freq_risk * self.risk_factors["high_frequency"]["risk_score"]
                            })
        
        # Pattern-based risk
        pattern_risk = self._analyze_transaction_patterns(transactions)
        risk_score += pattern_risk["score"]
        factors.extend(pattern_risk["factors"])
        
        return {
            "score": min(1.0, risk_score),
            "factors": factors,
            "volume_analysis": {
                "total_volume": total_volume,
                "avg_transaction_size": total_volume / len(transactions) if transactions else 0,
                "volume_distribution": self._analyze_volume_distribution(transactions)
            }
        }
    
    def _analyze_address_risk(self, address: str, currency: str, 
                            trace_result: Optional[Dict] = None) -> Dict:
        """Analyze risk based on address characteristics."""
        risk_score = 0.0
        factors = []
        
        # Check against known entity databases
        entity_risk = self._check_known_entities(address)
        risk_score += entity_risk["score"]
        factors.extend(entity_risk["factors"])
        
        # Address age analysis
        if trace_result and trace_result.get("transactions"):
            age_risk = self._analyze_address_age(trace_result["transactions"])
            risk_score += age_risk["score"]
            factors.extend(age_risk["factors"])
        
        # Address format analysis
        format_risk = self._analyze_address_format(address, currency)
        risk_score += format_risk["score"]
        factors.extend(format_risk["factors"])
        
        return {
            "score": min(1.0, risk_score),
            "factors": factors,
            "entity_interactions": entity_risk["interactions"]
        }
    
    def _analyze_behavioral_risk(self, trace_result: Dict) -> Dict:
        """Analyze behavioral risk patterns."""
        risk_score = 0.0
        factors = []
        
        transactions = trace_result.get("transactions", [])
        
        # Time-based patterns
        time_risk = self._analyze_temporal_patterns(transactions)
        risk_score += time_risk["score"]
        factors.extend(time_risk["factors"])
        
        # Value-based patterns
        value_risk = self._analyze_value_patterns(transactions)
        risk_score += value_risk["score"]
        factors.extend(value_risk["factors"])
        
        # Network analysis
        network_risk = self._analyze_network_patterns(trace_result)
        risk_score += network_risk["score"]
        factors.extend(network_risk["factors"])
        
        return {
            "score": min(1.0, risk_score),
            "factors": factors,
            "behavioral_indicators": {
                "temporal_patterns": time_risk["patterns"],
                "value_patterns": value_risk["patterns"],
                "network_patterns": network_risk["patterns"]
            }
        }
    
    def _analyze_threat_risk(self, threat_data: Dict) -> Dict:
        """Analyze risk based on threat intelligence data."""
        risk_score = 0.0
        factors = []
        
        # Threat score contribution
        threat_score = threat_data.get("threat_score", 0.0)
        risk_score += threat_score * 0.8  # High weight for threat intelligence
        
        if threat_score > 0.5:
            factors.append({
                "type": "threat_intelligence",
                "description": f"High threat score: {threat_score:.2f}",
                "risk_score": threat_score * 0.8
            })
        
        # Blacklist status
        if threat_data.get("blacklists"):
            risk_score += 0.6
            factors.append({
                "type": "blacklist_match",
                "description": f"Address found in {len(threat_data['blacklists'])} blacklist(s)",
                "risk_score": 0.6
            })
        
        # Suspicious indicators
        suspicious_count = len(threat_data.get("suspicious_indicators", []))
        if suspicious_count > 0:
            indicator_risk = min(1.0, suspicious_count * 0.2)
            risk_score += indicator_risk
            factors.append({
                "type": "suspicious_indicators",
                "description": f"{suspicious_count} suspicious indicators detected",
                "risk_score": indicator_risk
            })
        
        return {
            "score": min(1.0, risk_score),
            "factors": factors,
            "threat_indicators": {
                "threat_score": threat_score,
                "blacklist_count": len(threat_data.get("blacklists", [])),
                "suspicious_indicators": threat_data.get("suspicious_indicators", [])
            }
        }
    
    def _check_known_entities(self, address: str) -> Dict:
        """Check address against known entity databases."""
        risk_score = 0.0
        factors = []
        interactions = {}
        
        # Check exchanges
        for exchange, addresses in self.known_entities["exchanges"].items():
            if address in addresses:
                risk_score += self.risk_factors["exchange_interaction"]["risk_score"]
                factors.append({
                    "type": "exchange_interaction",
                    "description": f"Address belongs to {exchange} exchange",
                    "risk_score": self.risk_factors["exchange_interaction"]["risk_score"]
                })
                interactions["exchanges"] = interactions.get("exchanges", []) + [exchange]
        
        # Check mixers
        if address in self.known_entities["mixers"]:
            risk_score += self.risk_factors["mixing_indicators"]["risk_score"]
            factors.append({
                "type": "mixing_indicators",
                "description": "Address is a known mixer",
                "risk_score": self.risk_factors["mixing_indicators"]["risk_score"]
            })
            interactions["mixers"] = True
        
        # Check gambling sites
        if address in self.known_entities["gambling"]:
            risk_score += self.risk_factors["gambling_sites"]["risk_score"]
            factors.append({
                "type": "gambling_sites",
                "description": "Address belongs to gambling site",
                "risk_score": self.risk_factors["gambling_sites"]["risk_score"]
            })
            interactions["gambling"] = True
        
        # Check darknet markets
        if address in self.known_entities["darknet"]:
            risk_score += self.risk_factors["darknet_market"]["risk_score"]
            factors.append({
                "type": "darknet_market",
                "description": "Address belongs to darknet market",
                "risk_score": self.risk_factors["darknet_market"]["risk_score"]
            })
            interactions["darknet"] = True
        
        return {
            "score": min(1.0, risk_score),
            "factors": factors,
            "interactions": interactions
        }
    
    def _analyze_address_age(self, transactions: List[Dict]) -> Dict:
        """Analyze address age based on transaction history."""
        if not transactions:
            return {"score": 0.0, "factors": []}
        
        timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
        if not timestamps:
            return {"score": 0.0, "factors": []}
        
        oldest_tx = min(timestamps)
        newest_tx = max(timestamps)
        address_age_days = (newest_tx - oldest_tx) / 86400  # Convert to days
        
        risk_score = 0.0
        factors = []
        
        if address_age_days < self.risk_factors["new_address"]["threshold"]:
            risk_score += self.risk_factors["new_address"]["risk_score"]
            factors.append({
                "type": "new_address",
                "description": f"Address is {address_age_days:.1f} days old",
                "risk_score": self.risk_factors["new_address"]["risk_score"]
            })
        
        return {"score": risk_score, "factors": factors}
    
    def _analyze_address_format(self, address: str, currency: str) -> Dict:
        """Analyze address format for potential risks."""
        risk_score = 0.0
        factors = []
        
        # Check for vanity addresses (custom patterns)
        if currency.lower() == "ethereum":
            # Check for vanity patterns
            if re.match(r"^0x[a-fA-F0-9]{40}$", address):
                # Check for repeated characters
                if len(set(address[2:])) < 10:  # Low character diversity
                    risk_score += 0.2
                    factors.append({
                        "type": "vanity_address",
                        "description": "Potential vanity address with low character diversity",
                        "risk_score": 0.2
                    })
        
        return {"score": risk_score, "factors": factors}
    
    def _analyze_transaction_patterns(self, transactions: List[Dict]) -> Dict:
        """Analyze transaction patterns for suspicious activity."""
        risk_score = 0.0
        factors = []
        
        if not transactions:
            return {"score": risk_score, "factors": factors}
        
        # Check for mixing patterns
        small_txs = [tx for tx in transactions if tx.get("value_usd", 0) < 100]
        if len(small_txs) > 20:
            risk_score += self.risk_factors["mixing_indicators"]["risk_score"]
            factors.append({
                "type": "mixing_indicators",
                "description": f"Multiple small transactions: {len(small_txs)}",
                "risk_score": self.risk_factors["mixing_indicators"]["risk_score"]
            })
        
        # Check for round numbers (potential automated transactions)
        round_txs = [tx for tx in transactions if self._is_round_number(tx.get("value_usd", 0))]
        if len(round_txs) > len(transactions) * 0.5:
            risk_score += 0.3
            factors.append({
                "type": "round_numbers",
                "description": "High percentage of round number transactions",
                "risk_score": 0.3
            })
        
        return {"score": risk_score, "factors": factors}
    
    def _analyze_temporal_patterns(self, transactions: List[Dict]) -> Dict:
        """Analyze temporal patterns in transactions."""
        risk_score = 0.0
        factors = []
        patterns = {}
        
        if not transactions:
            return {"score": risk_score, "factors": factors, "patterns": patterns}
        
        timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
        if not timestamps:
            return {"score": risk_score, "factors": factors, "patterns": patterns}
        
        # Analyze hour distribution
        hours = [datetime.fromtimestamp(ts).hour for ts in timestamps]
        hour_distribution = {}
        for hour in hours:
            hour_distribution[hour] = hour_distribution.get(hour, 0) + 1
        
        # Check for unusual hour patterns
        unusual_hours = [h for h, count in hour_distribution.items() if count > len(transactions) * 0.1]
        if unusual_hours:
            patterns["unusual_hours"] = unusual_hours
            risk_score += 0.2
            factors.append({
                "type": "unusual_timing",
                "description": f"Unusual transaction timing: {unusual_hours}",
                "risk_score": 0.2
            })
        
        return {"score": risk_score, "factors": factors, "patterns": patterns}
    
    def _analyze_value_patterns(self, transactions: List[Dict]) -> Dict:
        """Analyze value patterns in transactions."""
        risk_score = 0.0
        factors = []
        patterns = {}
        
        if not transactions:
            return {"score": risk_score, "factors": factors, "patterns": patterns}
        
        values = [tx.get("value_usd", 0) for tx in transactions]
        
        # Check for value clustering
        value_distribution = {}
        for value in values:
            bucket = int(value / 100) * 100  # $100 buckets
            value_distribution[bucket] = value_distribution.get(bucket, 0) + 1
        
        # Check for unusual value patterns
        if len(value_distribution) < len(values) * 0.3:
            patterns["value_clustering"] = True
            risk_score += 0.3
            factors.append({
                "type": "value_clustering",
                "description": "Transactions clustered in specific value ranges",
                "risk_score": 0.3
            })
        
        return {"score": risk_score, "factors": factors, "patterns": patterns}
    
    def _analyze_network_patterns(self, trace_result: Dict) -> Dict:
        """Analyze network patterns in transaction graph."""
        risk_score = 0.0
        factors = []
        patterns = {}
        
        addresses = trace_result.get("addresses", [])
        relationships = trace_result.get("relationships", {})
        
        # Check for hub-and-spoke pattern
        if len(addresses) > 10:
            address_connections = relationships.get("address_connections", {})
            connection_counts = [len(conn.get("sends_to", [])) for conn in address_connections.values()]
            
            if max(connection_counts) > len(addresses) * 0.5:
                patterns["hub_spoke"] = True
                risk_score += 0.4
                factors.append({
                    "type": "hub_spoke_pattern",
                    "description": "Hub-and-spoke transaction pattern detected",
                    "risk_score": 0.4
                })
        
        return {"score": risk_score, "factors": factors, "patterns": patterns}
    
    def _analyze_volume_distribution(self, transactions: List[Dict]) -> Dict:
        """Analyze volume distribution across transactions."""
        if not transactions:
            return {}
        
        values = [tx.get("value_usd", 0) for tx in transactions]
        total_volume = sum(values)
        
        return {
            "total_transactions": len(transactions),
            "total_volume": total_volume,
            "average_transaction": total_volume / len(transactions) if transactions else 0,
            "largest_transaction": max(values) if values else 0,
            "smallest_transaction": min(values) if values else 0
        }
    
    def _is_round_number(self, value: float) -> bool:
        """Check if a value is a round number."""
        if value == 0:
            return False
        
        # Check for common round numbers
        round_numbers = [100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000]
        return any(abs(value - rn) / rn < 0.01 for rn in round_numbers)
    
    def _calculate_overall_risk(self, risk_breakdown: Dict) -> float:
        """Calculate overall risk score from breakdown."""
        total_score = 0.0
        total_weight = 0.0
        
        for risk_type, risk_data in risk_breakdown.items():
            weight = self.risk_weights.get(risk_type, 0.1)
            score = risk_data.get("score", 0.0)
            
            total_score += score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        if risk_score >= self.risk_thresholds["critical"]:
            return "CRITICAL"
        elif risk_score >= self.risk_thresholds["high"]:
            return "HIGH"
        elif risk_score >= self.risk_thresholds["medium"]:
            return "MEDIUM"
        elif risk_score >= self.risk_thresholds["low"]:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _generate_risk_factors(self, risk_breakdown: Dict) -> List[Dict]:
        """Generate consolidated list of risk factors."""
        all_factors = []
        
        for risk_type, risk_data in risk_breakdown.items():
            factors = risk_data.get("factors", [])
            for factor in factors:
                factor["risk_type"] = risk_type
                all_factors.append(factor)
        
        # Sort by risk score
        all_factors.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        
        return all_factors
    
    def _generate_recommendations(self, result: Dict) -> List[str]:
        """Generate risk mitigation recommendations."""
        recommendations = []
        risk_level = result.get("risk_level", "LOW")
        
        if risk_level in ["HIGH", "CRITICAL"]:
            recommendations.append("Consider enhanced due diligence procedures")
            recommendations.append("Monitor address for suspicious activity")
            recommendations.append("Implement additional verification steps")
        
        if risk_level == "CRITICAL":
            recommendations.append("Immediate investigation recommended")
            recommendations.append("Consider blocking transactions from this address")
        
        # Specific recommendations based on risk factors
        risk_factors = result.get("risk_factors", [])
        for factor in risk_factors:
            if factor.get("type") == "mixing_indicators":
                recommendations.append("Address shows mixing service characteristics")
            elif factor.get("type") == "high_volume":
                recommendations.append("High volume transactions require additional scrutiny")
            elif factor.get("type") == "blacklist_match":
                recommendations.append("Address found in blacklists - exercise extreme caution")
        
        return recommendations
    
    def _calculate_confidence(self, result: Dict) -> float:
        """Calculate confidence level of the risk assessment."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on data quality
        risk_breakdown = result.get("risk_breakdown", {})
        
        if risk_breakdown.get("transaction_risk"):
            confidence += 0.2
        
        if risk_breakdown.get("threat_risk"):
            confidence += 0.2
        
        if risk_breakdown.get("behavioral_risk"):
            confidence += 0.1
        
        # Increase confidence if we have multiple risk factors
        risk_factors = result.get("risk_factors", [])
        if len(risk_factors) > 3:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _create_default_result(self, address: str, currency: str) -> Dict:
        """Create default result when risk assessment fails."""
        return {
            "address": address,
            "currency": currency,
            "risk_score": 0.0,
            "risk_level": "UNKNOWN",
            "risk_factors": [],
            "risk_breakdown": {},
            "recommendations": ["Insufficient data for risk assessment"],
            "assessment_timestamp": datetime.now().isoformat(),
            "confidence": 0.0
        } 

"""
Risk Analyzer Module
====================

Provides risk assessment and scoring for blockchain transactions:
- Transaction risk analysis
- Volume analysis
- Frequency analysis
- Behavioral pattern detection
- Risk factor identification
"""

import math
import statistics
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class RiskAnalyzer:
    """Advanced risk analysis for blockchain transactions."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.risk_thresholds = config.get("risk_thresholds", {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.8,
            "critical": 0.9
        })
    
    def analyze_transaction_risk(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk for a single transaction."""
        
        risk_result = {
            "transaction_hash": transaction_data.get("tx_hash", ""),
            "risk_score": 0.0,
            "risk_level": "low",
            "risk_factors": [],
            "risk_details": {},
            "recommendations": []
        }
        
        try:
            # Volume risk analysis
            volume_risk = self._analyze_volume_risk(transaction_data)
            risk_result["risk_details"]["volume_risk"] = volume_risk
            
            # Frequency risk analysis
            frequency_risk = self._analyze_frequency_risk(transaction_data)
            risk_result["risk_details"]["frequency_risk"] = frequency_risk
            
            # Pattern risk analysis
            pattern_risk = self._analyze_pattern_risk(transaction_data)
            risk_result["risk_details"]["pattern_risk"] = pattern_risk
            
            # Calculate overall risk score
            risk_result["risk_score"] = self._calculate_overall_risk(risk_result["risk_details"])
            risk_result["risk_level"] = self._determine_risk_level(risk_result["risk_score"])
            
            # Generate risk factors
            risk_result["risk_factors"] = self._identify_risk_factors(risk_result["risk_details"])
            
            # Generate recommendations
            risk_result["recommendations"] = self._generate_risk_recommendations(risk_result)
            
        except Exception as e:
            logger.error(f"Error analyzing transaction risk: {e}")
            risk_result["error"] = str(e)
        
        return risk_result
    
    def analyze_address_risk(self, address_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk for an address based on its transaction history."""
        
        risk_result = {
            "address": address_data.get("address", ""),
            "risk_score": 0.0,
            "risk_level": "low",
            "risk_factors": [],
            "risk_details": {},
            "recommendations": []
        }
        
        try:
            transactions = address_data.get("transactions", [])
            
            # Transaction volume analysis
            volume_analysis = self._analyze_address_volume(transactions)
            risk_result["risk_details"]["volume_analysis"] = volume_analysis
            
            # Transaction frequency analysis
            frequency_analysis = self._analyze_address_frequency(transactions)
            risk_result["risk_details"]["frequency_analysis"] = frequency_analysis
            
            # Behavioral pattern analysis
            behavioral_analysis = self._analyze_behavioral_patterns(transactions)
            risk_result["risk_details"]["behavioral_analysis"] = behavioral_analysis
            
            # Address age analysis
            age_analysis = self._analyze_address_age(address_data)
            risk_result["risk_details"]["age_analysis"] = age_analysis
            
            # Calculate overall risk score
            risk_result["risk_score"] = self._calculate_address_risk(risk_result["risk_details"])
            risk_result["risk_level"] = self._determine_risk_level(risk_result["risk_score"])
            
            # Generate risk factors
            risk_result["risk_factors"] = self._identify_address_risk_factors(risk_result["risk_details"])
            
            # Generate recommendations
            risk_result["recommendations"] = self._generate_address_recommendations(risk_result)
            
        except Exception as e:
            logger.error(f"Error analyzing address risk: {e}")
            risk_result["error"] = str(e)
        
        return risk_result
    
    def _analyze_volume_risk(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk based on transaction volume."""
        
        volume = transaction_data.get("value_usd", 0)
        
        # Define volume thresholds
        thresholds = {
            "low": 1000,      # $1K
            "medium": 10000,  # $10K
            "high": 100000,   # $100K
            "critical": 1000000  # $1M
        }
        
        risk_score = 0.0
        risk_level = "low"
        
        if volume >= thresholds["critical"]:
            risk_score = 0.9
            risk_level = "critical"
        elif volume >= thresholds["high"]:
            risk_score = 0.7
            risk_level = "high"
        elif volume >= thresholds["medium"]:
            risk_score = 0.5
            risk_level = "medium"
        elif volume >= thresholds["low"]:
            risk_score = 0.3
            risk_level = "low"
        else:
            risk_score = 0.1
            risk_level = "minimal"
        
        return {
            "volume_usd": volume,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "thresholds": thresholds
        }
    
    def _analyze_frequency_risk(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk based on transaction frequency patterns."""
        
        # This would typically analyze multiple transactions
        # For single transaction analysis, we'll use basic heuristics
        
        timestamp = transaction_data.get("timestamp", 0)
        current_time = datetime.now().timestamp()
        
        # Check if transaction is very recent (within last hour)
        time_diff = current_time - timestamp if timestamp else 0
        
        risk_score = 0.0
        risk_level = "low"
        
        if time_diff < 3600:  # Within last hour
            risk_score = 0.3
            risk_level = "medium"
        elif time_diff < 86400:  # Within last day
            risk_score = 0.2
            risk_level = "low"
        else:
            risk_score = 0.1
            risk_level = "minimal"
        
        return {
            "time_since_transaction": time_diff,
            "risk_score": risk_score,
            "risk_level": risk_level
        }
    
    def _analyze_pattern_risk(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk based on transaction patterns."""
        
        risk_score = 0.0
        risk_level = "low"
        patterns = []
        
        # Check for suspicious patterns
        from_addresses = transaction_data.get("from_addresses", [])
        to_addresses = transaction_data.get("to_addresses", [])
        
        # Multiple recipients (potential mixing)
        if len(to_addresses) > 5:
            risk_score += 0.2
            patterns.append("multiple_recipients")
        
        # Multiple senders (potential mixing)
        if len(from_addresses) > 5:
            risk_score += 0.2
            patterns.append("multiple_senders")
        
        # Round numbers (suspicious)
        value = transaction_data.get("value_usd", 0)
        if value > 0 and value % 1000 == 0:
            risk_score += 0.1
            patterns.append("round_number_amount")
        
        # Determine risk level
        if risk_score >= 0.4:
            risk_level = "high"
        elif risk_score >= 0.2:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "patterns": patterns
        }
    
    def _analyze_address_volume(self, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze volume patterns for an address."""
        
        if not transactions:
            return {"total_volume": 0, "avg_volume": 0, "risk_score": 0.1}
        
        volumes = [tx.get("value_usd", 0) for tx in transactions]
        total_volume = sum(volumes)
        avg_volume = statistics.mean(volumes) if volumes else 0
        
        # Calculate volume risk
        risk_score = 0.0
        if total_volume > 1000000:  # $1M
            risk_score = 0.8
        elif total_volume > 100000:  # $100K
            risk_score = 0.6
        elif total_volume > 10000:  # $10K
            risk_score = 0.4
        elif total_volume > 1000:  # $1K
            risk_score = 0.2
        else:
            risk_score = 0.1
        
        return {
            "total_volume": total_volume,
            "avg_volume": avg_volume,
            "max_volume": max(volumes) if volumes else 0,
            "min_volume": min(volumes) if volumes else 0,
            "risk_score": risk_score
        }
    
    def _analyze_address_frequency(self, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze frequency patterns for an address."""
        
        if not transactions:
            return {"total_transactions": 0, "avg_frequency": 0, "risk_score": 0.1}
        
        # Sort transactions by timestamp
        sorted_txs = sorted(transactions, key=lambda x: x.get("timestamp", 0))
        
        total_transactions = len(transactions)
        
        # Calculate time spans
        if len(sorted_txs) > 1:
            first_tx = sorted_txs[0].get("timestamp", 0)
            last_tx = sorted_txs[-1].get("timestamp", 0)
            time_span = last_tx - first_tx if last_tx > first_tx else 1
            
            # Transactions per day
            days_span = time_span / 86400
            tx_per_day = total_transactions / days_span if days_span > 0 else total_transactions
        else:
            tx_per_day = 1
        
        # Calculate frequency risk
        risk_score = 0.0
        if tx_per_day > 100:  # More than 100 transactions per day
            risk_score = 0.8
        elif tx_per_day > 50:
            risk_score = 0.6
        elif tx_per_day > 20:
            risk_score = 0.4
        elif tx_per_day > 10:
            risk_score = 0.2
        else:
            risk_score = 0.1
        
        return {
            "total_transactions": total_transactions,
            "tx_per_day": tx_per_day,
            "time_span_days": time_span / 86400 if len(sorted_txs) > 1 else 0,
            "risk_score": risk_score
        }
    
    def _analyze_behavioral_patterns(self, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze behavioral patterns in transactions."""
        
        if not transactions:
            return {"patterns": [], "risk_score": 0.1}
        
        patterns = []
        risk_score = 0.0
        
        # Check for mixing patterns
        unique_addresses = set()
        for tx in transactions:
            unique_addresses.update(tx.get("from_addresses", []))
            unique_addresses.update(tx.get("to_addresses", []))
        
        if len(unique_addresses) > len(transactions) * 2:
            patterns.append("high_address_diversity")
            risk_score += 0.3
        
        # Check for small transaction amounts (potential mixing)
        small_txs = [tx for tx in transactions if tx.get("value_usd", 0) < 100]
        if len(small_txs) > len(transactions) * 0.5:
            patterns.append("many_small_transactions")
            risk_score += 0.2
        
        # Check for rapid transactions
        if len(transactions) > 1:
            timestamps = [tx.get("timestamp", 0) for tx in transactions]
            time_diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            rapid_txs = [diff for diff in time_diffs if diff < 60]  # Less than 1 minute apart
            
            if len(rapid_txs) > len(time_diffs) * 0.3:
                patterns.append("rapid_transactions")
                risk_score += 0.2
        
        return {
            "patterns": patterns,
            "risk_score": min(risk_score, 1.0)
        }
    
    def _analyze_address_age(self, address_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk based on address age."""
        
        # This would typically use blockchain data to determine address age
        # For now, we'll use a simplified approach
        
        transactions = address_data.get("transactions", [])
        if not transactions:
            return {"age_days": 0, "risk_score": 0.5}  # Unknown age = medium risk
        
        # Use first transaction timestamp as creation date
        timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
        if not timestamps:
            return {"age_days": 0, "risk_score": 0.5}
        
        first_tx_time = min(timestamps)
        current_time = datetime.now().timestamp()
        age_seconds = current_time - first_tx_time
        age_days = age_seconds / 86400
        
        # Calculate age risk (newer addresses = higher risk)
        risk_score = 0.0
        if age_days < 1:  # Less than 1 day
            risk_score = 0.8
        elif age_days < 7:  # Less than 1 week
            risk_score = 0.6
        elif age_days < 30:  # Less than 1 month
            risk_score = 0.4
        elif age_days < 90:  # Less than 3 months
            risk_score = 0.2
        else:
            risk_score = 0.1
        
        return {
            "age_days": age_days,
            "risk_score": risk_score
        }
    
    def _calculate_overall_risk(self, risk_details: Dict[str, Any]) -> float:
        """Calculate overall risk score from individual risk factors."""
        
        weights = {
            "volume_risk": 0.4,
            "frequency_risk": 0.2,
            "pattern_risk": 0.4
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for risk_type, weight in weights.items():
            if risk_type in risk_details:
                score = risk_details[risk_type].get("risk_score", 0.0)
                total_score += score * weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _calculate_address_risk(self, risk_details: Dict[str, Any]) -> float:
        """Calculate overall risk score for an address."""
        
        weights = {
            "volume_analysis": 0.3,
            "frequency_analysis": 0.2,
            "behavioral_analysis": 0.3,
            "age_analysis": 0.2
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for risk_type, weight in weights.items():
            if risk_type in risk_details:
                score = risk_details[risk_type].get("risk_score", 0.0)
                total_score += score * weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score."""
        if risk_score >= self.risk_thresholds.get("critical", 0.9):
            return "critical"
        elif risk_score >= self.risk_thresholds.get("high", 0.8):
            return "high"
        elif risk_score >= self.risk_thresholds.get("medium", 0.6):
            return "medium"
        elif risk_score >= self.risk_thresholds.get("low", 0.3):
            return "low"
        else:
            return "minimal"
    
    def _identify_risk_factors(self, risk_details: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors."""
        factors = []
        
        for risk_type, details in risk_details.items():
            if details.get("risk_score", 0) > 0.5:
                factors.append(f"high_{risk_type}")
            
            if risk_type == "pattern_risk" and details.get("patterns"):
                factors.extend(details["patterns"])
        
        return factors
    
    def _identify_address_risk_factors(self, risk_details: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors for addresses."""
        factors = []
        
        for risk_type, details in risk_details.items():
            if details.get("risk_score", 0) > 0.5:
                factors.append(f"high_{risk_type}")
            
            if risk_type == "behavioral_analysis" and details.get("patterns"):
                factors.extend(details["patterns"])
        
        return factors
    
    def _generate_risk_recommendations(self, risk_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on risk analysis."""
        recommendations = []
        
        risk_level = risk_result.get("risk_level", "low")
        risk_score = risk_result.get("risk_score", 0)
        
        if risk_level == "critical":
            recommendations.append("CRITICAL RISK - Do not proceed with transaction")
            recommendations.append("Report to authorities immediately")
        elif risk_level == "high":
            recommendations.append("HIGH RISK - Exercise extreme caution")
            recommendations.append("Conduct additional due diligence")
        elif risk_level == "medium":
            recommendations.append("MEDIUM RISK - Proceed with caution")
            recommendations.append("Monitor transaction closely")
        elif risk_level == "low":
            recommendations.append("LOW RISK - Proceed with normal due diligence")
        else:
            recommendations.append("MINIMAL RISK - Standard procedures apply")
        
        return recommendations
    
    def _generate_address_recommendations(self, risk_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations for address risk."""
        recommendations = []
        
        risk_level = risk_result.get("risk_level", "low")
        risk_factors = risk_result.get("risk_factors", [])
        
        if risk_level == "critical":
            recommendations.append("CRITICAL RISK ADDRESS - Blacklist immediately")
            recommendations.append("Investigate all associated transactions")
        elif risk_level == "high":
            recommendations.append("HIGH RISK ADDRESS - Monitor closely")
            recommendations.append("Flag for additional screening")
        elif risk_level == "medium":
            recommendations.append("MEDIUM RISK ADDRESS - Enhanced monitoring")
            recommendations.append("Review transaction patterns")
        elif risk_level == "low":
            recommendations.append("LOW RISK ADDRESS - Standard monitoring")
        else:
            recommendations.append("MINIMAL RISK ADDRESS - Normal procedures")
        
        # Add specific recommendations based on risk factors
        if "high_volume_analysis" in risk_factors:
            recommendations.append("High transaction volume detected")
        
        if "high_frequency_analysis" in risk_factors:
            recommendations.append("Unusual transaction frequency detected")
        
        if "rapid_transactions" in risk_factors:
            recommendations.append("Rapid transaction patterns detected")
        
        return recommendations

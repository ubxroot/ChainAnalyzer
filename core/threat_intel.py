"""
Threat Intelligence Module
==========================

Provides threat intelligence analysis for blockchain addresses:
- Blacklist checking
- Reputation scoring
- Suspicious pattern detection
- Threat feed integration
- Risk assessment
"""

import asyncio
import aiohttp
import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Advanced threat intelligence analysis for blockchain addresses."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
        self.blacklist_cache = {}
        self.reputation_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Free threat intelligence sources
        self.threat_sources = {
            "cryptoscamdb": {
                "url": "https://api.cryptoscamdb.org/v1/check",
                "free": True,
                "rate_limit": 10
            },
            "chainabuse": {
                "url": "https://api.chainabuse.com/v1/check",
                "free": True,
                "rate_limit": 5
            },
            "bitcoin_abuse": {
                "url": "https://www.bitcoinabuse.com/api/reports/check",
                "free": True,
                "rate_limit": 5
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
    
    async def analyze_address(self, address: str, currency: str) -> Dict[str, Any]:
        """Comprehensive threat intelligence analysis for an address."""
        
        result = {
            "address": address,
            "currency": currency,
            "timestamp": datetime.now().isoformat(),
            "threat_score": 0.0,
            "risk_level": "low",
            "blacklist_status": "clean",
            "suspicious_patterns": [],
            "reputation_score": 0.0,
            "threat_indicators": [],
            "recommendations": []
        }
        
        try:
            # Check blacklists
            blacklist_result = await self._check_blacklists(address, currency)
            result.update(blacklist_result)
            
            # Analyze patterns
            pattern_result = await self._analyze_patterns(address, currency)
            result.update(pattern_result)
            
            # Calculate threat score
            result["threat_score"] = self._calculate_threat_score(result)
            result["risk_level"] = self._determine_risk_level(result["threat_score"])
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(result)
            
        except Exception as e:
            logger.error(f"Error analyzing address {address}: {e}")
            result["error"] = str(e)
        
        return result
    
    async def _check_blacklists(self, address: str, currency: str) -> Dict[str, Any]:
        """Check address against multiple blacklists using free APIs."""
        
        blacklist_result = {
            "blacklist_status": "clean",
            "blacklist_matches": [],
            "blacklist_sources": []
        }
        
        # Check CryptoScamDB (free API)
        try:
            cryptoscam_result = await self._check_cryptoscamdb(address)
            if cryptoscam_result.get("is_scam"):
                blacklist_result["blacklist_status"] = "blacklisted"
                blacklist_result["blacklist_matches"].append({
                    "source": "cryptoscamdb",
                    "type": "scam",
                    "details": cryptoscam_result.get("details", "")
                })
                blacklist_result["blacklist_sources"].append("cryptoscamdb")
        except Exception as e:
            logger.debug(f"CryptoScamDB check failed: {e}")
        
        # Check Bitcoin Abuse (free API)
        if currency.lower() == "bitcoin":
            try:
                bitcoin_abuse_result = await self._check_bitcoin_abuse(address)
                if bitcoin_abuse_result.get("is_abusive"):
                    blacklist_result["blacklist_status"] = "blacklisted"
                    blacklist_result["blacklist_matches"].append({
                        "source": "bitcoin_abuse",
                        "type": "abuse",
                        "details": bitcoin_abuse_result.get("details", "")
                    })
                    blacklist_result["blacklist_sources"].append("bitcoin_abuse")
            except Exception as e:
                logger.debug(f"Bitcoin Abuse check failed: {e}")
        
        # Check ChainAbuse (free API)
        try:
            chainabuse_result = await self._check_chainabuse(address)
            if chainabuse_result.get("is_abusive"):
                blacklist_result["blacklist_status"] = "blacklisted"
                blacklist_result["blacklist_matches"].append({
                    "source": "chainabuse",
                    "type": "abuse",
                    "details": chainabuse_result.get("details", "")
                })
                blacklist_result["blacklist_sources"].append("chainabuse")
        except Exception as e:
            logger.debug(f"ChainAbuse check failed: {e}")
        
        return blacklist_result
    
    async def _check_cryptoscamdb(self, address: str) -> Dict[str, Any]:
        """Check address against CryptoScamDB (free API)."""
        try:
            url = f"https://api.cryptoscamdb.org/v1/check/{address}"
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "is_scam": data.get("success", False),
                        "details": data.get("message", ""),
                        "source": "cryptoscamdb"
                    }
        except Exception as e:
            logger.debug(f"CryptoScamDB API error: {e}")
        
        return {"is_scam": False, "details": "", "source": "cryptoscamdb"}
    
    async def _check_bitcoin_abuse(self, address: str) -> Dict[str, Any]:
        """Check Bitcoin address against Bitcoin Abuse (free API)."""
        try:
            url = f"https://www.bitcoinabuse.com/api/reports/check"
            params = {"address": address}
            async with self.session.get(url, params=params, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "is_abusive": data.get("count", 0) > 0,
                        "details": f"Reported {data.get('count', 0)} times",
                        "source": "bitcoin_abuse"
                    }
        except Exception as e:
            logger.debug(f"Bitcoin Abuse API error: {e}")
        
        return {"is_abusive": False, "details": "", "source": "bitcoin_abuse"}
    
    async def _check_chainabuse(self, address: str) -> Dict[str, Any]:
        """Check address against ChainAbuse (free API)."""
        try:
            url = f"https://api.chainabuse.com/v1/check/{address}"
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "is_abusive": data.get("is_abusive", False),
                        "details": data.get("reason", ""),
                        "source": "chainabuse"
                    }
        except Exception as e:
            logger.debug(f"ChainAbuse API error: {e}")
        
        return {"is_abusive": False, "details": "", "source": "chainabuse"}
    
    async def _analyze_patterns(self, address: str, currency: str) -> Dict[str, Any]:
        """Analyze address for suspicious patterns."""
        
        pattern_result = {
            "suspicious_patterns": [],
            "pattern_score": 0.0
        }
        
        # Check for common scam patterns
        scam_patterns = [
            r"0x[a-fA-F0-9]{40}",  # Ethereum address pattern
            r"1[a-km-zA-HJ-NP-Z1-9]{25,34}",  # Bitcoin address pattern
            r"T[A-Za-z1-9]{33}",  # Tron address pattern
        ]
        
        # Check for suspicious characteristics
        if len(address) < 10:
            pattern_result["suspicious_patterns"].append("unusually_short_address")
            pattern_result["pattern_score"] += 0.2
        
        # Check for repeated characters
        if len(set(address)) < len(address) * 0.3:
            pattern_result["suspicious_patterns"].append("repeated_characters")
            pattern_result["pattern_score"] += 0.1
        
        # Check for sequential patterns
        if self._has_sequential_pattern(address):
            pattern_result["suspicious_patterns"].append("sequential_pattern")
            pattern_result["pattern_score"] += 0.3
        
        # Check for vanity addresses (too perfect)
        if self._is_vanity_address(address):
            pattern_result["suspicious_patterns"].append("vanity_address")
            pattern_result["pattern_score"] += 0.1
        
        return pattern_result
    
    def _has_sequential_pattern(self, address: str) -> bool:
        """Check if address has sequential patterns."""
        # Check for consecutive numbers or letters
        for i in range(len(address) - 2):
            if (address[i].isdigit() and address[i+1].isdigit() and address[i+2].isdigit()):
                if int(address[i+1]) == int(address[i]) + 1 and int(address[i+2]) == int(address[i+1]) + 1:
                    return True
        return False
    
    def _is_vanity_address(self, address: str) -> bool:
        """Check if address appears to be a vanity address."""
        # Check for repeated patterns that might indicate vanity addresses
        if len(set(address)) < len(address) * 0.4:
            return True
        return False
    
    def _calculate_threat_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall threat score based on analysis results."""
        score = 0.0
        
        # Blacklist status
        if analysis_result.get("blacklist_status") == "blacklisted":
            score += 0.8
        
        # Blacklist matches
        score += len(analysis_result.get("blacklist_matches", [])) * 0.2
        
        # Suspicious patterns
        score += analysis_result.get("pattern_score", 0.0)
        
        # Threat indicators
        score += len(analysis_result.get("threat_indicators", [])) * 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _determine_risk_level(self, threat_score: float) -> str:
        """Determine risk level based on threat score."""
        if threat_score >= 0.8:
            return "critical"
        elif threat_score >= 0.6:
            return "high"
        elif threat_score >= 0.4:
            return "medium"
        elif threat_score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        if analysis_result.get("blacklist_status") == "blacklisted":
            recommendations.append("Address is blacklisted - exercise extreme caution")
            recommendations.append("Do not transact with this address")
            recommendations.append("Report to relevant authorities if necessary")
        
        if analysis_result.get("threat_score", 0) > 0.6:
            recommendations.append("High threat score - investigate further")
            recommendations.append("Monitor transactions carefully")
        
        if analysis_result.get("suspicious_patterns"):
            recommendations.append("Suspicious patterns detected - verify address legitimacy")
        
        if not recommendations:
            recommendations.append("Address appears clean - proceed with normal due diligence")
        
        return recommendations
    
    async def update_threat_feeds(self) -> Dict[str, Any]:
        """Update threat intelligence feeds."""
        update_result = {
            "timestamp": datetime.now().isoformat(),
            "sources_updated": [],
            "errors": []
        }
        
        # Update each threat source
        for source_name, source_config in self.threat_sources.items():
            try:
                # For free APIs, we just verify connectivity
                async with self.session.get(source_config["url"], timeout=5) as response:
                    if response.status == 200:
                        update_result["sources_updated"].append(source_name)
                    else:
                        update_result["errors"].append(f"{source_name}: HTTP {response.status}")
            except Exception as e:
                update_result["errors"].append(f"{source_name}: {str(e)}")
        
        return update_result
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            "total_sources": len(self.threat_sources),
            "free_sources": len([s for s in self.threat_sources.values() if s.get("free")]),
            "cache_size": len(self.blacklist_cache),
            "last_update": datetime.now().isoformat()
        }

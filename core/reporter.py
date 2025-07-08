"""
Report Generator Module
=======================

Generates comprehensive reports for SOC/DFIR teams:
- Executive summaries
- Technical analysis reports
- Risk assessment reports
- Threat intelligence reports
- Compliance reports
"""

import json
import csv
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Advanced report generation for blockchain analysis."""
    
    def __init__(self):
        self.report_templates = {
            "executive": self._executive_template,
            "technical": self._technical_template,
            "risk": self._risk_template,
            "threat": self._threat_template,
            "compliance": self._compliance_template
        }
    
    def generate_report(self, analysis_data: Dict, report_type: str = "comprehensive") -> str:
        """Generate a comprehensive analysis report."""
        try:
            if report_type == "comprehensive":
                return self._generate_comprehensive_report(analysis_data)
            elif report_type in self.report_templates:
                return self.report_templates[report_type](analysis_data)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return f"Error generating report: {e}"
    
    def _generate_comprehensive_report(self, analysis_data: Dict) -> str:
        """Generate a comprehensive report combining all analysis aspects."""
        report = []
        
        # Executive Summary
        report.append(self._generate_executive_summary(analysis_data))
        report.append("\n" + "="*80 + "\n")
        
        # Technical Analysis
        report.append(self._generate_technical_analysis(analysis_data))
        report.append("\n" + "="*80 + "\n")
        
        # Risk Assessment
        if analysis_data.get("risk_data"):
            report.append(self._generate_risk_assessment(analysis_data["risk_data"]))
            report.append("\n" + "="*80 + "\n")
        
        # Threat Intelligence
        if analysis_data.get("threat_data"):
            report.append(self._generate_threat_intelligence(analysis_data["threat_data"]))
            report.append("\n" + "="*80 + "\n")
        
        # Recommendations
        report.append(self._generate_recommendations(analysis_data))
        
        return "\n".join(report)
    
    def _generate_executive_summary(self, analysis_data: Dict) -> str:
        """Generate executive summary section."""
        address = analysis_data.get("address", "Unknown")
        currency = analysis_data.get("currency", "Unknown")
        trace_result = analysis_data.get("trace_result", {})
        risk_data = analysis_data.get("risk_data", {})
        threat_data = analysis_data.get("threat_data", {})
        
        summary = []
        summary.append("EXECUTIVE SUMMARY")
        summary.append("=" * 50)
        summary.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Address: {address}")
        summary.append(f"Blockchain: {currency.upper()}")
        summary.append("")
        
        # Key findings
        summary.append("KEY FINDINGS:")
        
        # Transaction summary
        if trace_result:
            transactions = trace_result.get("transactions", [])
            addresses = trace_result.get("addresses", [])
            total_volume = trace_result.get("total_volume", 0)
            
            summary.append(f"• Total Transactions: {len(transactions)}")
            summary.append(f"• Unique Addresses: {len(addresses)}")
            summary.append(f"• Total Volume: ${total_volume:,.2f}")
        
        # Risk summary
        if risk_data:
            risk_score = risk_data.get("risk_score", 0)
            risk_level = risk_data.get("risk_level", "Unknown")
            summary.append(f"• Risk Score: {risk_score:.2f} ({risk_level})")
        
        # Threat summary
        if threat_data:
            threat_score = threat_data.get("threat_score", 0)
            threat_level = threat_data.get("threat_level", "Unknown")
            summary.append(f"• Threat Score: {threat_score:.2f} ({threat_level})")
        
        return "\n".join(summary)
    
    def _generate_technical_analysis(self, analysis_data: Dict) -> str:
        """Generate technical analysis section."""
        trace_result = analysis_data.get("trace_result", {})
        
        if not trace_result:
            return "TECHNICAL ANALYSIS\nNo transaction data available for analysis."
        
        analysis = []
        analysis.append("TECHNICAL ANALYSIS")
        analysis.append("=" * 50)
        
        # Transaction details
        transactions = trace_result.get("transactions", [])
        addresses = trace_result.get("addresses", [])
        
        analysis.append(f"Transaction Analysis:")
        analysis.append(f"• Total Transactions Analyzed: {len(transactions)}")
        analysis.append(f"• Unique Addresses Involved: {len(addresses)}")
        analysis.append(f"• Analysis Depth: {trace_result.get('trace_depth', 'N/A')} levels")
        analysis.append(f"• Maximum Hops: {trace_result.get('max_hops', 'N/A')}")
        analysis.append("")
        
        # Transaction patterns
        if transactions:
            analysis.append("Transaction Patterns:")
            
            # Volume analysis
            values = [tx.get("value_usd", 0) for tx in transactions]
            if values:
                analysis.append(f"• Average Transaction Value: ${sum(values)/len(values):,.2f}")
                analysis.append(f"• Largest Transaction: ${max(values):,.2f}")
                analysis.append(f"• Smallest Transaction: ${min(values):,.2f}")
            
            # Timing analysis
            timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
            if timestamps:
                from datetime import datetime
                earliest = datetime.fromtimestamp(min(timestamps))
                latest = datetime.fromtimestamp(max(timestamps))
                analysis.append(f"• Analysis Period: {earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')}")
        
        # Suspicious patterns
        suspicious_patterns = trace_result.get("suspicious_patterns", [])
        if suspicious_patterns:
            analysis.append("")
            analysis.append("Suspicious Patterns Detected:")
            for pattern in suspicious_patterns:
                analysis.append(f"• {pattern}")
        
        return "\n".join(analysis)
    
    def _generate_risk_assessment(self, risk_data: Dict) -> str:
        """Generate risk assessment section."""
        assessment = []
        assessment.append("RISK ASSESSMENT")
        assessment.append("=" * 50)
        
        risk_score = risk_data.get("risk_score", 0)
        risk_level = risk_data.get("risk_level", "Unknown")
        risk_factors = risk_data.get("risk_factors", [])
        
        assessment.append(f"Overall Risk Score: {risk_score:.2f}")
        assessment.append(f"Risk Level: {risk_level}")
        assessment.append("")
        
        if risk_factors:
            assessment.append("Risk Factors Identified:")
            for i, factor in enumerate(risk_factors[:10], 1):  # Top 10 factors
                assessment.append(f"{i}. {factor.get('description', 'Unknown')}")
                assessment.append(f"   Risk Score: {factor.get('risk_score', 0):.2f}")
                assessment.append(f"   Type: {factor.get('type', 'Unknown')}")
                assessment.append("")
        
        # Recommendations
        recommendations = risk_data.get("recommendations", [])
        if recommendations:
            assessment.append("Risk Mitigation Recommendations:")
            for rec in recommendations:
                assessment.append(f"• {rec}")
        
        return "\n".join(assessment)
    
    def _generate_threat_intelligence(self, threat_data: Dict) -> str:
        """Generate threat intelligence section."""
        threat_intel = []
        threat_intel.append("THREAT INTELLIGENCE ANALYSIS")
        threat_intel.append("=" * 50)
        
        threat_score = threat_data.get("threat_score", 0)
        threat_level = threat_data.get("threat_level", "Unknown")
        blacklist_status = threat_data.get("blacklist_status", "Unknown")
        
        threat_intel.append(f"Threat Score: {threat_score:.2f}")
        threat_intel.append(f"Threat Level: {threat_level}")
        threat_intel.append(f"Blacklist Status: {blacklist_status}")
        threat_intel.append("")
        
        # Blacklist details
        blacklists = threat_data.get("blacklists", [])
        if blacklists:
            threat_intel.append("Blacklist Matches:")
            for blacklist in blacklists:
                threat_intel.append(f"• {blacklist.get('source', 'Unknown')}: {blacklist.get('reason', 'Unknown')}")
            threat_intel.append("")
        
        # Suspicious indicators
        suspicious_indicators = threat_data.get("suspicious_indicators", [])
        if suspicious_indicators:
            threat_intel.append("Suspicious Indicators:")
            for indicator in suspicious_indicators:
                threat_intel.append(f"• {indicator}")
            threat_intel.append("")
        
        # Historical incidents
        historical_incidents = threat_data.get("historical_incidents", [])
        if historical_incidents:
            threat_intel.append("Historical Incidents:")
            for incident in historical_incidents:
                threat_intel.append(f"• {incident}")
            threat_intel.append("")
        
        # Alerts
        alerts = threat_data.get("alerts", [])
        if alerts:
            threat_intel.append("Threat Alerts:")
            for alert in alerts:
                threat_intel.append(f"⚠️ {alert}")
        
        return "\n".join(threat_intel)
    
    def _generate_recommendations(self, analysis_data: Dict) -> str:
        """Generate recommendations section."""
        recommendations = []
        recommendations.append("RECOMMENDATIONS")
        recommendations.append("=" * 50)
        
        # Risk-based recommendations
        risk_data = analysis_data.get("risk_data", {})
        if risk_data:
            risk_level = risk_data.get("risk_level", "Unknown")
            risk_recommendations = risk_data.get("recommendations", [])
            
            if risk_level in ["HIGH", "CRITICAL"]:
                recommendations.append("IMMEDIATE ACTIONS REQUIRED:")
                recommendations.append("• Implement enhanced monitoring for this address")
                recommendations.append("• Consider blocking transactions from this address")
                recommendations.append("• Conduct immediate investigation")
                recommendations.append("")
            
            if risk_recommendations:
                recommendations.append("Risk Mitigation Actions:")
                for rec in risk_recommendations:
                    recommendations.append(f"• {rec}")
                recommendations.append("")
        
        # Threat-based recommendations
        threat_data = analysis_data.get("threat_data", {})
        if threat_data:
            threat_level = threat_data.get("threat_level", "Unknown")
            
            if threat_level in ["HIGH", "CRITICAL"]:
                recommendations.append("Threat Response Actions:")
                recommendations.append("• Add address to internal blacklist")
                recommendations.append("• Alert security team")
                recommendations.append("• Monitor for additional suspicious activity")
                recommendations.append("")
        
        # General recommendations
        recommendations.append("General Recommendations:")
        recommendations.append("• Continue monitoring address for changes in behavior")
        recommendations.append("• Update threat intelligence feeds regularly")
        recommendations.append("• Document findings for future reference")
        recommendations.append("• Share intelligence with relevant teams")
        
        return "\n".join(recommendations)
    
    def _executive_template(self, analysis_data: Dict) -> str:
        """Executive summary template."""
        return self._generate_executive_summary(analysis_data)
    
    def _technical_template(self, analysis_data: Dict) -> str:
        """Technical analysis template."""
        return self._generate_technical_analysis(analysis_data)
    
    def _risk_template(self, analysis_data: Dict) -> str:
        """Risk assessment template."""
        risk_data = analysis_data.get("risk_data", {})
        return self._generate_risk_assessment(risk_data)
    
    def _threat_template(self, analysis_data: Dict) -> str:
        """Threat intelligence template."""
        threat_data = analysis_data.get("threat_data", {})
        return self._generate_threat_intelligence(threat_data)
    
    def _compliance_template(self, analysis_data: Dict) -> str:
        """Compliance report template."""
        compliance = []
        compliance.append("COMPLIANCE REPORT")
        compliance.append("=" * 50)
        compliance.append(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        compliance.append(f"Address: {analysis_data.get('address', 'Unknown')}")
        compliance.append(f"Blockchain: {analysis_data.get('currency', 'Unknown').upper()}")
        compliance.append("")
        
        # Compliance checks
        compliance.append("COMPLIANCE CHECKS:")
        
        risk_data = analysis_data.get("risk_data", {})
        threat_data = analysis_data.get("threat_data", {})
        
        # Risk compliance
        if risk_data:
            risk_level = risk_data.get("risk_level", "Unknown")
            if risk_level in ["HIGH", "CRITICAL"]:
                compliance.append("❌ FAIL: High risk level detected")
            else:
                compliance.append("✅ PASS: Risk level acceptable")
        
        # Threat compliance
        if threat_data:
            threat_level = threat_data.get("threat_level", "Unknown")
            if threat_level in ["HIGH", "CRITICAL"]:
                compliance.append("❌ FAIL: High threat level detected")
            else:
                compliance.append("✅ PASS: Threat level acceptable")
        
        # Blacklist compliance
        if threat_data:
            blacklist_status = threat_data.get("blacklist_status", "Unknown")
            if blacklist_status == "BLACKLISTED":
                compliance.append("❌ FAIL: Address found in blacklists")
            else:
                compliance.append("✅ PASS: No blacklist matches")
        
        compliance.append("")
        compliance.append("COMPLIANCE RECOMMENDATIONS:")
        compliance.append("• Follow established due diligence procedures")
        compliance.append("• Document all findings and decisions")
        compliance.append("• Maintain audit trail of analysis")
        compliance.append("• Regular review of compliance status")
        
        return "\n".join(compliance)
    
    def export_report(self, report_content: str, format: str = "txt", filename: str = None) -> str:
        """Export report to file."""
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"chain_analyzer_report_{timestamp}.{format}"
            
            filepath = Path(filename)
            
            if format.lower() == "txt":
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(report_content)
            elif format.lower() == "json":
                # Convert report to JSON format
                report_data = {
                    "report_content": report_content,
                    "generated_at": datetime.now().isoformat(),
                    "format": "text"
                }
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            return str(filepath.absolute())
            
        except Exception as e:
            logger.error(f"Error exporting report: {e}")
            return "" 

"""
Reporter Module
===============

Provides comprehensive reporting capabilities:
- Report generation in multiple formats
- Summary reports
- Detailed analysis reports
- Export functionality
- Customizable templates
"""

import json
import csv
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class Reporter:
    """Advanced reporting for blockchain analysis results."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.report_config = config.get("export", {})
        self.output_dir = Path(self.report_config.get("output_directory", "reports"))
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_summary_report(self, analysis_data: Dict[str, Any], 
                              format: str = "json") -> Dict[str, Any]:
        """Generate a summary report of analysis results."""
        
        summary = {
            "report_type": "summary",
            "timestamp": datetime.now().isoformat(),
            "analysis_summary": {
                "address": analysis_data.get("address", ""),
                "currency": analysis_data.get("currency", ""),
                "total_transactions": len(analysis_data.get("transactions", [])),
                "total_addresses": len(analysis_data.get("addresses", [])),
                "total_volume_usd": sum(tx.get("value_usd", 0) for tx in analysis_data.get("transactions", [])),
                "analysis_duration": analysis_data.get("analysis_duration", 0),
                "trace_depth": analysis_data.get("trace_depth", 0),
                "max_hops": analysis_data.get("max_hops", 0)
            },
            "risk_assessment": {
                "overall_risk_level": "low",
                "risk_score": 0.0,
                "risk_factors": []
            },
            "threat_intelligence": {
                "blacklist_status": "clean",
                "threat_score": 0.0,
                "suspicious_patterns": []
            },
            "key_findings": [],
            "recommendations": []
        }
        
        # Add risk assessment if available
        if "risk_analysis" in analysis_data:
            risk_data = analysis_data["risk_analysis"]
            summary["risk_assessment"].update({
                "overall_risk_level": risk_data.get("risk_level", "low"),
                "risk_score": risk_data.get("risk_score", 0.0),
                "risk_factors": risk_data.get("risk_factors", [])
            })
        
        # Add threat intelligence if available
        if "threat_intelligence" in analysis_data:
            threat_data = analysis_data["threat_intelligence"]
            summary["threat_intelligence"].update({
                "blacklist_status": threat_data.get("blacklist_status", "clean"),
                "threat_score": threat_data.get("threat_score", 0.0),
                "suspicious_patterns": threat_data.get("suspicious_patterns", [])
            })
        
        # Generate key findings
        summary["key_findings"] = self._generate_key_findings(analysis_data)
        
        # Generate recommendations
        summary["recommendations"] = self._generate_recommendations(summary)
        
        return summary
    
    def generate_detailed_report(self, analysis_data: Dict[str, Any], 
                               format: str = "json") -> Dict[str, Any]:
        """Generate a detailed report with comprehensive analysis."""
        
        detailed_report = {
            "report_type": "detailed",
            "timestamp": datetime.now().isoformat(),
            "executive_summary": self._generate_executive_summary(analysis_data),
            "technical_analysis": self._generate_technical_analysis(analysis_data),
            "risk_assessment": self._generate_detailed_risk_assessment(analysis_data),
            "threat_intelligence": self._generate_detailed_threat_intelligence(analysis_data),
            "transaction_analysis": self._generate_transaction_analysis(analysis_data),
            "network_analysis": self._generate_network_analysis(analysis_data),
            "visualization_data": self._generate_visualization_data(analysis_data),
            "appendix": self._generate_appendix(analysis_data)
        }
        
        return detailed_report
    
    def export_report(self, report_data: Dict[str, Any], 
                     format: str = "json", 
                     filename: Optional[str] = None) -> str:
        """Export report in specified format."""
        
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                address = report_data.get("analysis_summary", {}).get("address", "unknown")
                filename = f"chainanalyzer_report_{address}_{timestamp}.{format}"
            
            filepath = self.output_dir / filename
            
            if format.lower() == "json":
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, indent=2, default=str)
            
            elif format.lower() == "csv":
                self._export_to_csv(report_data, filepath)
            
            elif format.lower() == "txt":
                self._export_to_txt(report_data, filepath)
            
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            logger.info(f"Report exported to: {filepath}")
            return str(filepath)
        
        except Exception as e:
            logger.error(f"Error exporting report: {e}")
            raise
    
    def _generate_key_findings(self, analysis_data: Dict[str, Any]) -> List[str]:
        """Generate key findings from analysis data."""
        
        findings = []
        
        # Transaction volume findings
        total_volume = sum(tx.get("value_usd", 0) for tx in analysis_data.get("transactions", []))
        if total_volume > 1000000:
            findings.append(f"High transaction volume: ${total_volume:,.2f}")
        elif total_volume > 100000:
            findings.append(f"Significant transaction volume: ${total_volume:,.2f}")
        
        # Transaction count findings
        tx_count = len(analysis_data.get("transactions", []))
        if tx_count > 100:
            findings.append(f"High transaction frequency: {tx_count} transactions")
        elif tx_count > 50:
            findings.append(f"Moderate transaction frequency: {tx_count} transactions")
        
        # Risk findings
        if "risk_analysis" in analysis_data:
            risk_level = analysis_data["risk_analysis"].get("risk_level", "low")
            if risk_level in ["high", "critical"]:
                findings.append(f"High risk address: {risk_level.upper()} risk level")
        
        # Threat findings
        if "threat_intelligence" in analysis_data:
            threat_score = analysis_data["threat_intelligence"].get("threat_score", 0)
            if threat_score > 0.7:
                findings.append(f"High threat score: {threat_score:.2f}")
        
        # Address network findings
        address_count = len(analysis_data.get("addresses", []))
        if address_count > 50:
            findings.append(f"Large address network: {address_count} connected addresses")
        
        if not findings:
            findings.append("No significant findings detected")
        
        return findings
    
    def _generate_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on summary data."""
        
        recommendations = []
        
        risk_level = summary["risk_assessment"]["risk_level"]
        threat_score = summary["threat_intelligence"]["threat_score"]
        
        if risk_level == "critical":
            recommendations.append("IMMEDIATE ACTION REQUIRED: Address poses critical risk")
            recommendations.append("Implement immediate blocking and monitoring")
            recommendations.append("Report to relevant authorities")
        elif risk_level == "high":
            recommendations.append("HIGH RISK: Implement enhanced monitoring")
            recommendations.append("Conduct additional due diligence")
            recommendations.append("Consider blocking high-value transactions")
        elif risk_level == "medium":
            recommendations.append("MEDIUM RISK: Monitor transactions closely")
            recommendations.append("Implement standard due diligence procedures")
        else:
            recommendations.append("LOW RISK: Standard monitoring procedures apply")
        
        if threat_score > 0.7:
            recommendations.append("HIGH THREAT: Address associated with malicious activity")
            recommendations.append("Implement threat intelligence monitoring")
        
        if summary["analysis_summary"]["total_volume_usd"] > 1000000:
            recommendations.append("HIGH VOLUME: Consider enhanced reporting requirements")
        
        return recommendations
    
    def _generate_executive_summary(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for detailed report."""
        
        return {
            "overview": f"Analysis of {analysis_data.get('currency', 'unknown')} address {analysis_data.get('address', 'unknown')}",
            "key_metrics": {
                "total_transactions": len(analysis_data.get("transactions", [])),
                "total_volume": sum(tx.get("value_usd", 0) for tx in analysis_data.get("transactions", [])),
                "connected_addresses": len(analysis_data.get("addresses", [])),
                "analysis_depth": analysis_data.get("trace_depth", 0)
            },
            "risk_overview": {
                "level": analysis_data.get("risk_analysis", {}).get("risk_level", "low"),
                "score": analysis_data.get("risk_analysis", {}).get("risk_score", 0.0)
            },
            "threat_overview": {
                "status": analysis_data.get("threat_intelligence", {}).get("blacklist_status", "clean"),
                "score": analysis_data.get("threat_intelligence", {}).get("threat_score", 0.0)
            }
        }
    
    def _generate_technical_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical analysis section."""
        
        return {
            "analysis_parameters": {
                "trace_depth": analysis_data.get("trace_depth", 0),
                "max_hops": analysis_data.get("max_hops", 0),
                "analysis_duration": analysis_data.get("analysis_duration", 0),
                "currency": analysis_data.get("currency", "unknown")
            },
            "data_quality": {
                "transaction_completeness": len(analysis_data.get("transactions", [])) > 0,
                "address_coverage": len(analysis_data.get("addresses", [])) > 0,
                "timestamp_availability": any(tx.get("timestamp") for tx in analysis_data.get("transactions", []))
            },
            "methodology": {
                "tracing_method": "Multi-hop transaction tracing",
                "risk_assessment": "Multi-factor risk scoring",
                "threat_intelligence": "Multi-source blacklist checking"
            }
        }
    
    def _generate_detailed_risk_assessment(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed risk assessment section."""
        
        risk_data = analysis_data.get("risk_analysis", {})
        
        return {
            "overall_assessment": {
                "risk_level": risk_data.get("risk_level", "low"),
                "risk_score": risk_data.get("risk_score", 0.0),
                "confidence": risk_data.get("confidence", 0.0)
            },
            "risk_factors": risk_data.get("risk_factors", []),
            "risk_details": risk_data.get("risk_details", {}),
            "recommendations": risk_data.get("recommendations", [])
        }
    
    def _generate_detailed_threat_intelligence(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed threat intelligence section."""
        
        threat_data = analysis_data.get("threat_intelligence", {})
        
        return {
            "overall_assessment": {
                "blacklist_status": threat_data.get("blacklist_status", "clean"),
                "threat_score": threat_data.get("threat_score", 0.0),
                "confidence": threat_data.get("confidence", 0.0)
            },
            "blacklist_matches": threat_data.get("blacklist_matches", []),
            "suspicious_patterns": threat_data.get("suspicious_patterns", []),
            "threat_indicators": threat_data.get("threat_indicators", []),
            "recommendations": threat_data.get("recommendations", [])
        }
    
    def _generate_transaction_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate transaction analysis section."""
        
        transactions = analysis_data.get("transactions", [])
        
        if not transactions:
            return {"message": "No transactions found"}
        
        # Calculate statistics
        volumes = [tx.get("value_usd", 0) for tx in transactions]
        timestamps = [tx.get("timestamp", 0) for tx in transactions if tx.get("timestamp")]
        
        return {
            "transaction_statistics": {
                "total_count": len(transactions),
                "total_volume": sum(volumes),
                "average_volume": sum(volumes) / len(volumes) if volumes else 0,
                "max_volume": max(volumes) if volumes else 0,
                "min_volume": min(volumes) if volumes else 0
            },
            "temporal_analysis": {
                "first_transaction": min(timestamps) if timestamps else None,
                "last_transaction": max(timestamps) if timestamps else None,
                "time_span_days": (max(timestamps) - min(timestamps)) / 86400 if len(timestamps) > 1 else 0
            },
            "sample_transactions": transactions[:10]  # First 10 transactions
        }
    
    def _generate_network_analysis(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate network analysis section."""
        
        addresses = analysis_data.get("addresses", [])
        relationships = analysis_data.get("relationships", {})
        
        return {
            "network_statistics": {
                "total_addresses": len(addresses),
                "connected_addresses": len([addr for addr in addresses if addr != analysis_data.get("address", "")]),
                "relationship_count": len(relationships.get("address_connections", {}))
            },
            "network_topology": {
                "central_addresses": [],
                "isolated_addresses": [],
                "high_degree_addresses": []
            },
            "relationship_details": relationships
        }
    
    def _generate_visualization_data(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate visualization data section."""
        
        return {
            "available_visualizations": [
                "transaction_flow",
                "address_network", 
                "risk_heatmap",
                "timeline"
            ],
            "visualization_config": {
                "interactive": True,
                "export_formats": ["json", "csv", "png", "svg"]
            }
        }
    
    def _generate_appendix(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate appendix with additional data."""
        
        return {
            "raw_data_summary": {
                "transactions_count": len(analysis_data.get("transactions", [])),
                "addresses_count": len(analysis_data.get("addresses", [])),
                "analysis_timestamp": analysis_data.get("timestamp", ""),
                "currency": analysis_data.get("currency", "")
            },
            "methodology_details": {
                "tracing_algorithm": "Multi-hop depth-first search",
                "risk_scoring": "Weighted multi-factor analysis",
                "threat_intelligence": "Multi-source aggregation"
            },
            "data_sources": [
                "Blockchain APIs (free tier)",
                "Public threat intelligence feeds",
                "Open-source blacklists"
            ]
        }
    
    def _export_to_csv(self, report_data: Dict[str, Any], filepath: Path):
        """Export report data to CSV format."""
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write summary data
            writer.writerow(["Report Type", "Summary Report"])
            writer.writerow(["Timestamp", report_data.get("timestamp", "")])
            writer.writerow([])
            
            # Write analysis summary
            summary = report_data.get("analysis_summary", {})
            writer.writerow(["Analysis Summary"])
            writer.writerow(["Address", summary.get("address", "")])
            writer.writerow(["Currency", summary.get("currency", "")])
            writer.writerow(["Total Transactions", summary.get("total_transactions", 0)])
            writer.writerow(["Total Volume USD", summary.get("total_volume_usd", 0)])
            writer.writerow([])
            
            # Write risk assessment
            risk = report_data.get("risk_assessment", {})
            writer.writerow(["Risk Assessment"])
            writer.writerow(["Risk Level", risk.get("overall_risk_level", "low")])
            writer.writerow(["Risk Score", risk.get("risk_score", 0.0)])
            writer.writerow([])
            
            # Write recommendations
            writer.writerow(["Recommendations"])
            for rec in report_data.get("recommendations", []):
                writer.writerow([rec])
    
    def _export_to_txt(self, report_data: Dict[str, Any], filepath: Path):
        """Export report data to text format."""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("ChainAnalyzer Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Report Type: {report_data.get('report_type', 'summary')}\n")
            f.write(f"Timestamp: {report_data.get('timestamp', '')}\n\n")
            
            # Analysis Summary
            summary = report_data.get("analysis_summary", {})
            f.write("Analysis Summary\n")
            f.write("-" * 20 + "\n")
            f.write(f"Address: {summary.get('address', '')}\n")
            f.write(f"Currency: {summary.get('currency', '')}\n")
            f.write(f"Total Transactions: {summary.get('total_transactions', 0)}\n")
            f.write(f"Total Volume USD: ${summary.get('total_volume_usd', 0):,.2f}\n\n")
            
            # Risk Assessment
            risk = report_data.get("risk_assessment", {})
            f.write("Risk Assessment\n")
            f.write("-" * 20 + "\n")
            f.write(f"Risk Level: {risk.get('overall_risk_level', 'low')}\n")
            f.write(f"Risk Score: {risk.get('risk_score', 0.0):.2f}\n\n")
            
            # Key Findings
            f.write("Key Findings\n")
            f.write("-" * 20 + "\n")
            for finding in report_data.get("key_findings", []):
                f.write(f"• {finding}\n")
            f.write("\n")
            
            # Recommendations
            f.write("Recommendations\n")
            f.write("-" * 20 + "\n")
            for rec in report_data.get("recommendations", []):
                f.write(f"• {rec}\n")

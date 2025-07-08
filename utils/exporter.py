"""
Export Manager Module
=====================

Handles exporting analysis results in various formats:
- JSON export
- CSV export
- PDF reports
- Excel spreadsheets
- Custom formats
"""

import json
import csv
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ExportManager:
    """Manages export of analysis results in various formats."""
    
    def __init__(self, output_directory: str = "exports"):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)
    
    def export_results(self, analysis_data: Dict, format: str, 
                      address: str, currency: str) -> str:
        """Export analysis results in specified format."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"analysis_{currency}_{address[:8]}_{timestamp}"
            
            if format.lower() == "json":
                return self._export_json(analysis_data, filename)
            elif format.lower() == "csv":
                return self._export_csv(analysis_data, filename)
            elif format.lower() == "pdf":
                return self._export_pdf(analysis_data, filename)
            elif format.lower() == "xlsx":
                return self._export_excel(analysis_data, filename)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting results: {e}")
            return ""
    
    def export_batch_results(self, results: List[Dict], format: str, 
                           currency: str) -> str:
        """Export batch analysis results."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"batch_analysis_{currency}_{timestamp}"
            
            if format.lower() == "json":
                return self._export_batch_json(results, filename)
            elif format.lower() == "csv":
                return self._export_batch_csv(results, filename)
            elif format.lower() == "xlsx":
                return self._export_batch_excel(results, filename)
            else:
                raise ValueError(f"Unsupported batch export format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting batch results: {e}")
            return ""
    
    def _export_json(self, analysis_data: Dict, filename: str) -> str:
        """Export results as JSON."""
        filepath = self.output_directory / f"{filename}.json"
        
        # Add export metadata
        export_data = {
            "export_metadata": {
                "exported_at": datetime.now().isoformat(),
                "format": "json",
                "version": "2.0.0"
            },
            "analysis_data": analysis_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Results exported to JSON: {filepath}")
        return str(filepath)
    
    def _export_csv(self, analysis_data: Dict, filename: str) -> str:
        """Export results as CSV."""
        filepath = self.output_directory / f"{filename}.csv"
        
        # Flatten analysis data for CSV
        csv_data = self._flatten_analysis_data(analysis_data)
        
        if csv_data:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                writer.writeheader()
                writer.writerows(csv_data)
        
        logger.info(f"Results exported to CSV: {filepath}")
        return str(filepath)
    
    def _export_pdf(self, analysis_data: Dict, filename: str) -> str:
        """Export results as PDF report."""
        filepath = self.output_directory / f"{filename}.pdf"
        
        # This would require a PDF library like reportlab
        # For now, create a simple text-based report
        report_content = self._generate_text_report(analysis_data)
        
        # Save as text file (PDF generation would be implemented here)
        text_filepath = self.output_directory / f"{filename}.txt"
        with open(text_filepath, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        logger.info(f"Results exported to text report: {text_filepath}")
        return str(text_filepath)
    
    def _export_excel(self, analysis_data: Dict, filename: str) -> str:
        """Export results as Excel spreadsheet."""
        filepath = self.output_directory / f"{filename}.xlsx"
        
        # This would require openpyxl or xlsxwriter
        # For now, create a CSV file with .xlsx extension
        csv_filepath = self.output_directory / f"{filename}.csv"
        csv_data = self._flatten_analysis_data(analysis_data)
        
        if csv_data:
            with open(csv_filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                writer.writeheader()
                writer.writerows(csv_data)
        
        logger.info(f"Results exported to CSV (Excel format): {csv_filepath}")
        return str(csv_filepath)
    
    def _export_batch_json(self, results: List[Dict], filename: str) -> str:
        """Export batch results as JSON."""
        filepath = self.output_directory / f"{filename}.json"
        
        export_data = {
            "export_metadata": {
                "exported_at": datetime.now().isoformat(),
                "format": "json",
                "version": "2.0.0",
                "total_addresses": len(results)
            },
            "batch_results": results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Batch results exported to JSON: {filepath}")
        return str(filepath)
    
    def _export_batch_csv(self, results: List[Dict], filename: str) -> str:
        """Export batch results as CSV."""
        filepath = self.output_directory / f"{filename}.csv"
        
        # Create summary CSV for batch results
        csv_data = []
        for result in results:
            address = result.get("address", "Unknown")
            
            # Extract key metrics
            trace_result = result.get("trace_result", {})
            threat_data = result.get("threat_data", {})
            risk_data = result.get("risk_data", {})
            
            row = {
                "address": address,
                "total_transactions": len(trace_result.get("transactions", [])),
                "total_volume": trace_result.get("total_volume", 0),
                "threat_score": threat_data.get("threat_score", 0),
                "threat_level": threat_data.get("threat_level", "Unknown"),
                "risk_score": risk_data.get("risk_score", 0),
                "risk_level": risk_data.get("risk_level", "Unknown"),
                "blacklist_status": threat_data.get("blacklist_status", "Unknown"),
                "suspicious_indicators": len(threat_data.get("suspicious_indicators", [])),
                "risk_factors": len(risk_data.get("risk_factors", []))
            }
            csv_data.append(row)
        
        if csv_data:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
                writer.writeheader()
                writer.writerows(csv_data)
        
        logger.info(f"Batch results exported to CSV: {filepath}")
        return str(filepath)
    
    def _export_batch_excel(self, results: List[Dict], filename: str) -> str:
        """Export batch results as Excel."""
        # Similar to CSV export for now
        return self._export_batch_csv(results, filename)
    
    def _flatten_analysis_data(self, analysis_data: Dict) -> List[Dict]:
        """Flatten analysis data for CSV export."""
        flattened = []
        
        address = analysis_data.get("address", "Unknown")
        currency = analysis_data.get("currency", "Unknown")
        trace_result = analysis_data.get("trace_result", {})
        threat_data = analysis_data.get("threat_data", {})
        risk_data = analysis_data.get("risk_data", {})
        
        # Create summary row
        summary_row = {
            "address": address,
            "currency": currency,
            "analysis_type": "summary",
            "total_transactions": len(trace_result.get("transactions", [])),
            "total_volume": trace_result.get("total_volume", 0),
            "threat_score": threat_data.get("threat_score", 0),
            "threat_level": threat_data.get("threat_level", "Unknown"),
            "risk_score": risk_data.get("risk_score", 0),
            "risk_level": risk_data.get("risk_level", "Unknown"),
            "blacklist_status": threat_data.get("blacklist_status", "Unknown")
        }
        flattened.append(summary_row)
        
        # Add transaction details
        for i, tx in enumerate(trace_result.get("transactions", [])):
            tx_row = {
                "address": address,
                "currency": currency,
                "analysis_type": "transaction",
                "transaction_index": i,
                "tx_hash": tx.get("tx_hash", ""),
                "value": tx.get("value_usd", 0),
                "timestamp": tx.get("timestamp", 0),
                "from_address": tx.get("from_address", ""),
                "to_address": tx.get("to_address", ""),
                "confirmations": tx.get("confirmations", 0)
            }
            flattened.append(tx_row)
        
        # Add threat indicators
        for i, indicator in enumerate(threat_data.get("suspicious_indicators", [])):
            indicator_row = {
                "address": address,
                "currency": currency,
                "analysis_type": "threat_indicator",
                "indicator_index": i,
                "indicator": indicator,
                "threat_score": threat_data.get("threat_score", 0)
            }
            flattened.append(indicator_row)
        
        # Add risk factors
        for i, factor in enumerate(risk_data.get("risk_factors", [])):
            factor_row = {
                "address": address,
                "currency": currency,
                "analysis_type": "risk_factor",
                "factor_index": i,
                "factor_type": factor.get("type", ""),
                "factor_description": factor.get("description", ""),
                "risk_score": factor.get("risk_score", 0)
            }
            flattened.append(factor_row)
        
        return flattened
    
    def _generate_text_report(self, analysis_data: Dict) -> str:
        """Generate a text-based report."""
        report = []
        
        # Header
        report.append("CHAINANALYZER ANALYSIS REPORT")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Address: {analysis_data.get('address', 'Unknown')}")
        report.append(f"Currency: {analysis_data.get('currency', 'Unknown')}")
        report.append("")
        
        # Summary
        trace_result = analysis_data.get("trace_result", {})
        threat_data = analysis_data.get("threat_data", {})
        risk_data = analysis_data.get("risk_data", {})
        
        report.append("SUMMARY")
        report.append("-" * 20)
        report.append(f"Total Transactions: {len(trace_result.get('transactions', []))}")
        report.append(f"Total Volume: ${trace_result.get('total_volume', 0):,.2f}")
        report.append(f"Threat Score: {threat_data.get('threat_score', 0):.2f}")
        report.append(f"Risk Score: {risk_data.get('risk_score', 0):.2f}")
        report.append("")
        
        # Threat Analysis
        if threat_data:
            report.append("THREAT ANALYSIS")
            report.append("-" * 20)
            report.append(f"Threat Level: {threat_data.get('threat_level', 'Unknown')}")
            report.append(f"Blacklist Status: {threat_data.get('blacklist_status', 'Unknown')}")
            
            indicators = threat_data.get("suspicious_indicators", [])
            if indicators:
                report.append("Suspicious Indicators:")
                for indicator in indicators:
                    report.append(f"  • {indicator}")
            report.append("")
        
        # Risk Assessment
        if risk_data:
            report.append("RISK ASSESSMENT")
            report.append("-" * 20)
            report.append(f"Risk Level: {risk_data.get('risk_level', 'Unknown')}")
            
            factors = risk_data.get("risk_factors", [])
            if factors:
                report.append("Risk Factors:")
                for factor in factors:
                    report.append(f"  • {factor.get('description', 'Unknown')}")
            report.append("")
        
        # Recommendations
        if risk_data:
            recommendations = risk_data.get("recommendations", [])
            if recommendations:
                report.append("RECOMMENDATIONS")
                report.append("-" * 20)
                for rec in recommendations:
                    report.append(f"• {rec}")
                report.append("")
        
        return "\n".join(report)
    
    def list_exports(self) -> List[Dict[str, Any]]:
        """List all exported files."""
        exports = []
        
        for filepath in self.output_directory.glob("*"):
            if filepath.is_file():
                stat = filepath.stat()
                exports.append({
                    "filename": filepath.name,
                    "filepath": str(filepath),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        
        return sorted(exports, key=lambda x: x["modified"], reverse=True)
    
    def cleanup_exports(self, days_old: int = 30):
        """Clean up old export files."""
        cutoff_date = datetime.now().timestamp() - (days_old * 24 * 3600)
        cleaned_count = 0
        
        for filepath in self.output_directory.glob("*"):
            if filepath.is_file() and filepath.stat().st_mtime < cutoff_date:
                try:
                    filepath.unlink()
                    cleaned_count += 1
                    logger.info(f"Cleaned up old export: {filepath.name}")
                except Exception as e:
                    logger.error(f"Error cleaning up {filepath.name}: {e}")
        
        logger.info(f"Cleanup completed: {cleaned_count} files removed")
        return cleaned_count 

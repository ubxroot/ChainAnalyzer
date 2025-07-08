"""
Exporters Module
================

Provides export functionality for analysis results:
- JSON export
- CSV export
- Text export
- Custom formats
- Batch export
"""

import json
import csv
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class DataExporter:
    """Advanced data export functionality for ChainAnalyzer."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.export_config = config.get("export", {})
        self.output_dir = Path(self.export_config.get("output_directory", "exports"))
        self.output_dir.mkdir(exist_ok=True)
    
    def export_data(self, data: Dict[str, Any], format: str = "json", 
                   filename: Optional[str] = None) -> str:
        """Export data in specified format."""
        
        try:
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"chainanalyzer_export_{timestamp}.{format}"
            
            filepath = self.output_dir / filename
            
            if format.lower() == "json":
                return self._export_to_json(data, filepath)
            elif format.lower() == "csv":
                return self._export_to_csv(data, filepath)
            elif format.lower() == "txt":
                return self._export_to_txt(data, filepath)
            else:
                raise ValueError(f"Unsupported export format: {format}")
        
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            raise
    
    def _export_to_json(self, data: Dict[str, Any], filepath: Path) -> str:
        """Export data to JSON format."""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Data exported to JSON: {filepath}")
        return str(filepath)
    
    def _export_to_csv(self, data: Dict[str, Any], filepath: Path) -> str:
        """Export data to CSV format."""
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write summary data
            writer.writerow(["Analysis Summary"])
            writer.writerow(["Address", data.get("address", "")])
            writer.writerow(["Currency", data.get("currency", "")])
            writer.writerow(["Total Transactions", len(data.get("transactions", []))])
            writer.writerow(["Total Volume USD", sum(tx.get("value_usd", 0) for tx in data.get("transactions", []))])
            writer.writerow([])
            
            # Write transactions
            writer.writerow(["Transactions"])
            writer.writerow(["Hash", "From", "To", "Value USD", "Timestamp"])
            
            for tx in data.get("transactions", []):
                writer.writerow([
                    tx.get("tx_hash", ""),
                    ", ".join(tx.get("from_addresses", [])),
                    ", ".join(tx.get("to_addresses", [])),
                    tx.get("value_usd", 0),
                    tx.get("timestamp", "")
                ])
            
            writer.writerow([])
            
            # Write addresses
            writer.writerow(["Addresses"])
            for addr in data.get("addresses", []):
                writer.writerow([addr])
        
        logger.info(f"Data exported to CSV: {filepath}")
        return str(filepath)
    
    def _export_to_txt(self, data: Dict[str, Any], filepath: Path) -> str:
        """Export data to text format."""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("ChainAnalyzer Export Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Address: {data.get('address', '')}\n")
            f.write(f"Currency: {data.get('currency', '')}\n\n")
            
            # Summary
            f.write("Summary\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Transactions: {len(data.get('transactions', []))}\n")
            f.write(f"Total Volume USD: ${sum(tx.get('value_usd', 0) for tx in data.get('transactions', [])):,.2f}\n")
            f.write(f"Connected Addresses: {len(data.get('addresses', []))}\n\n")
            
            # Transactions
            f.write("Transactions\n")
            f.write("-" * 20 + "\n")
            for i, tx in enumerate(data.get("transactions", []), 1):
                f.write(f"{i}. Hash: {tx.get('tx_hash', '')}\n")
                f.write(f"   From: {', '.join(tx.get('from_addresses', []))}\n")
                f.write(f"   To: {', '.join(tx.get('to_addresses', []))}\n")
                f.write(f"   Value: ${tx.get('value_usd', 0):,.2f}\n")
                f.write(f"   Timestamp: {tx.get('timestamp', '')}\n\n")
            
            # Addresses
            f.write("Connected Addresses\n")
            f.write("-" * 20 + "\n")
            for addr in data.get("addresses", []):
                f.write(f"{addr}\n")
        
        logger.info(f"Data exported to TXT: {filepath}")
        return str(filepath)
    
    def export_transactions(self, transactions: List[Dict[str, Any]], 
                          format: str = "json", filename: Optional[str] = None) -> str:
        """Export transaction data specifically."""
        
        export_data = {
            "export_type": "transactions",
            "timestamp": datetime.now().isoformat(),
            "transaction_count": len(transactions),
            "transactions": transactions
        }
        
        return self.export_data(export_data, format, filename)
    
    def export_addresses(self, addresses: List[str], 
                        format: str = "json", filename: Optional[str] = None) -> str:
        """Export address data specifically."""
        
        export_data = {
            "export_type": "addresses",
            "timestamp": datetime.now().isoformat(),
            "address_count": len(addresses),
            "addresses": addresses
        }
        
        return self.export_data(export_data, format, filename)
    
    def export_risk_analysis(self, risk_data: Dict[str, Any], 
                           format: str = "json", filename: Optional[str] = None) -> str:
        """Export risk analysis data."""
        
        export_data = {
            "export_type": "risk_analysis",
            "timestamp": datetime.now().isoformat(),
            "risk_data": risk_data
        }
        
        return self.export_data(export_data, format, filename)
    
    def export_threat_intelligence(self, threat_data: Dict[str, Any], 
                                 format: str = "json", filename: Optional[str] = None) -> str:
        """Export threat intelligence data."""
        
        export_data = {
            "export_type": "threat_intelligence",
            "timestamp": datetime.now().isoformat(),
            "threat_data": threat_data
        }
        
        return self.export_data(export_data, format, filename)
    
    def batch_export(self, data_list: List[Dict[str, Any]], 
                    format: str = "json", base_filename: Optional[str] = None) -> List[str]:
        """Export multiple datasets in batch."""
        
        exported_files = []
        
        for i, data in enumerate(data_list):
            if base_filename:
                filename = f"{base_filename}_{i+1}.{format}"
            else:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"batch_export_{timestamp}_{i+1}.{format}"
            
            try:
                filepath = self.export_data(data, format, filename)
                exported_files.append(filepath)
            except Exception as e:
                logger.error(f"Error exporting batch item {i+1}: {e}")
        
        logger.info(f"Batch export completed: {len(exported_files)} files exported")
        return exported_files
    
    def get_export_statistics(self) -> Dict[str, Any]:
        """Get export statistics."""
        
        export_files = list(self.output_dir.glob("*"))
        
        stats = {
            "total_exports": len(export_files),
            "export_directory": str(self.output_dir),
            "file_types": {},
            "recent_exports": []
        }
        
        # Count file types
        for file_path in export_files:
            file_ext = file_path.suffix.lower()
            stats["file_types"][file_ext] = stats["file_types"].get(file_ext, 0) + 1
        
        # Get recent exports
        recent_files = sorted(export_files, key=lambda x: x.stat().st_mtime, reverse=True)[:10]
        for file_path in recent_files:
            stats["recent_exports"].append({
                "filename": file_path.name,
                "size": file_path.stat().st_size,
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            })
        
        return stats
    
    def clear_exports(self):
        """Clear all export files."""
        
        for file_path in self.output_dir.glob("*"):
            if file_path.is_file():
                file_path.unlink()
        
        logger.info("All export files cleared")
    
    def compress_exports(self, archive_name: Optional[str] = None) -> str:
        """Compress all export files into an archive."""
        
        import zipfile
        
        if not archive_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"chainanalyzer_exports_{timestamp}.zip"
        
        archive_path = self.output_dir / archive_name
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.output_dir.glob("*"):
                if file_path.is_file() and file_path.suffix != '.zip':
                    zipf.write(file_path, file_path.name)
        
        logger.info(f"Exports compressed to: {archive_path}")
        return str(archive_path)

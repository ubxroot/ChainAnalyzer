# core/comprehensive_reporter.py
import json
from datetime import datetime
from typing import Dict, Any

class ComprehensiveReporter:
    """Comprehensive reporting service."""
    
    def __init__(self, config: dict):
        self.config = config
        
    def generate_comprehensive_report(self, result: Dict[str, Any]) -> str:
        """Generate comprehensive analysis report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        trace_data = result.get('trace_data', {})
        address = trace_data.get('address', 'unknown')
        
        report = {
            "analysis_metadata": {
                "timestamp": timestamp,
                "address": address,
                "currency": trace_data.get('currency', 'Unknown'),
                "analysis_type": "comprehensive_trace"
            },
            "trace_summary": trace_data,
            "risk_analysis": result.get('risk_analysis', {}),
            "threat_intelligence": result.get('threat_intel', {}),
            "patterns": result.get('patterns', []),
            "defi_analysis": result.get('defi_analysis', {}),
            "cross_chain": result.get('cross_chain', {})
        }
        
        filename = f"comprehensive_report_{address[:8]}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        return filename

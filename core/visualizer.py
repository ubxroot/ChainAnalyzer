"""
Transaction Visualizer Module
============================

Provides visualization capabilities for blockchain transaction analysis:
- Transaction flow diagrams
- Address relationship graphs
- Risk visualization
- Interactive charts and graphs
"""

import json
from typing import Dict, List, Optional, Any
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.align import Align

logger = logging.getLogger(__name__)

class TransactionVisualizer:
    """Advanced transaction visualization and flow analysis."""
    
    def __init__(self):
        self.console = Console()
    
    def create_flow_diagram(self, trace_result: Dict, currency: str) -> Dict:
        """Create transaction flow diagram."""
        try:
            visualization_data = {
                "type": "transaction_flow",
                "currency": currency,
                "nodes": [],
                "edges": [],
                "metadata": {}
            }
            
            # Extract nodes (addresses)
            addresses = trace_result.get("addresses", [])
            for addr in addresses:
                node = {
                    "id": addr,
                    "type": "address",
                    "label": f"{addr[:8]}...{addr[-6:]}",
                    "properties": self._get_address_properties(addr, trace_result)
                }
                visualization_data["nodes"].append(node)
            
            # Extract edges (transactions)
            transactions = trace_result.get("transactions", [])
            for tx in transactions:
                from_addrs = tx.get("from_addresses", [])
                to_addrs = tx.get("to_addresses", [])
                
                for from_addr in from_addrs:
                    for to_addr in to_addrs:
                        edge = {
                            "source": from_addr,
                            "target": to_addr,
                            "type": "transaction",
                            "properties": {
                                "tx_hash": tx.get("tx_hash", ""),
                                "value": tx.get("value_usd", 0),
                                "timestamp": tx.get("timestamp", 0),
                                "currency": currency
                            }
                        }
                        visualization_data["edges"].append(edge)
            
            # Add metadata
            visualization_data["metadata"] = {
                "total_transactions": len(transactions),
                "total_addresses": len(addresses),
                "total_volume": trace_result.get("total_volume", 0),
                "currency": currency
            }
            
            return visualization_data
            
        except Exception as e:
            logger.error(f"Error creating flow diagram: {e}")
            return {}
    
    def _get_address_properties(self, address: str, trace_result: Dict) -> Dict:
        """Get properties for an address node."""
        transactions = trace_result.get("transactions", [])
        
        # Count incoming and outgoing transactions
        incoming = 0
        outgoing = 0
        total_received = 0
        total_sent = 0
        
        for tx in transactions:
            if address in tx.get("to_addresses", []):
                incoming += 1
                total_received += tx.get("value_usd", 0)
            if address in tx.get("from_addresses", []):
                outgoing += 1
                total_sent += tx.get("value_usd", 0)
        
        return {
            "incoming_transactions": incoming,
            "outgoing_transactions": outgoing,
            "total_received": total_received,
            "total_sent": total_sent,
            "balance": total_received - total_sent
        }
    
    def display_flow_summary(self, trace_result: Dict, console: Console):
        """Display transaction flow summary in rich format."""
        try:
            # Create main layout
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body"),
                Layout(name="footer", size=3)
            )
            
            # Header
            header = Panel(
                Align.center(Text("🔄 Transaction Flow Analysis", style="bold blue")),
                border_style="blue"
            )
            layout["header"].update(header)
            
            # Body - Transaction summary table
            transactions = trace_result.get("transactions", [])
            addresses = trace_result.get("addresses", [])
            
            table = Table(title="📊 Flow Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Total Transactions", str(len(transactions)))
            table.add_row("Unique Addresses", str(len(addresses)))
            table.add_row("Total Volume", f"${trace_result.get('total_volume', 0):,.2f}")
            table.add_row("Trace Depth", str(trace_result.get("trace_depth", "N/A")))
            table.add_row("Max Hops", str(trace_result.get("max_hops", "N/A")))
            
            # Add suspicious patterns if any
            suspicious_patterns = trace_result.get("suspicious_patterns", [])
            if suspicious_patterns:
                table.add_row("Suspicious Patterns", str(len(suspicious_patterns)))
            
            layout["body"].update(table)
            
            # Footer - Key relationships
            if trace_result.get("relationships"):
                relationships = trace_result["relationships"]
                address_connections = relationships.get("address_connections", {})
                
                if address_connections:
                    footer_text = Text("🔗 Key Address Relationships\n", style="bold yellow")
                    for addr, connections in list(address_connections.items())[:5]:  # Show top 5
                        sends_to = len(connections.get("sends_to", []))
                        receives_from = len(connections.get("receives_from", []))
                        footer_text.append(f"• {addr[:8]}... → {sends_to} sends, {receives_from} receives\n")
                    
                    footer = Panel(footer_text, border_style="yellow")
                    layout["footer"].update(footer)
            
            console.print(layout)
            
        except Exception as e:
            logger.error(f"Error displaying flow summary: {e}")
            console.print(f"[red]Error displaying flow summary: {e}[/red]")
    
    def display_risk_visualization(self, risk_data: Dict, console: Console):
        """Display risk assessment visualization."""
        try:
            risk_score = risk_data.get("risk_score", 0.0)
            risk_level = risk_data.get("risk_level", "UNKNOWN")
            risk_factors = risk_data.get("risk_factors", [])
            
            # Create risk meter
            risk_meter = self._create_risk_meter(risk_score, risk_level)
            
            # Create risk factors table
            table = Table(title="⚠️ Risk Factors")
            table.add_column("Factor", style="cyan")
            table.add_column("Risk Score", style="red")
            table.add_column("Description", style="yellow")
            
            for factor in risk_factors[:10]:  # Show top 10
                table.add_row(
                    factor.get("type", "Unknown"),
                    f"{factor.get('risk_score', 0):.2f}",
                    factor.get("description", "No description")
                )
            
            console.print(risk_meter)
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying risk visualization: {e}")
            console.print(f"[red]Error displaying risk visualization: {e}[/red]")
    
    def _create_risk_meter(self, risk_score: float, risk_level: str) -> Panel:
        """Create a visual risk meter."""
        # Create risk bar
        bar_length = 50
        filled_length = int(risk_score * bar_length)
        
        risk_bar = "█" * filled_length + "░" * (bar_length - filled_length)
        
        # Color based on risk level
        color_map = {
            "MINIMAL": "green",
            "LOW": "bright_green",
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold red"
        }
        
        color = color_map.get(risk_level, "white")
        
        content = Text()
        content.append(f"Risk Score: {risk_score:.2f}\n", style=color)
        content.append(f"Risk Level: {risk_level}\n", style=color)
        content.append(f"[{risk_bar}]", style=color)
        
        return Panel(content, title="🎯 Risk Assessment", border_style=color)
    
    def export_visualization(self, visualization_data: Dict, format: str = "json") -> str:
        """Export visualization data in various formats."""
        try:
            if format.lower() == "json":
                return json.dumps(visualization_data, indent=2)
            elif format.lower() == "graphml":
                return self._convert_to_graphml(visualization_data)
            elif format.lower() == "dot":
                return self._convert_to_dot(visualization_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            logger.error(f"Error exporting visualization: {e}")
            return ""
    
    def _convert_to_graphml(self, visualization_data: Dict) -> str:
        """Convert visualization data to GraphML format."""
        graphml = '<?xml version="1.0" encoding="UTF-8"?>\n'
        graphml += '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n'
        graphml += '  <graph id="transaction_flow" edgedefault="directed">\n'
        
        # Add nodes
        for node in visualization_data.get("nodes", []):
            graphml += f'    <node id="{node["id"]}">\n'
            graphml += f'      <data key="label">{node["label"]}</data>\n'
            graphml += f'      <data key="type">{node["type"]}</data>\n'
            graphml += '    </node>\n'
        
        # Add edges
        for i, edge in enumerate(visualization_data.get("edges", [])):
            graphml += f'    <edge id="e{i}" source="{edge["source"]}" target="{edge["target"]}">\n'
            graphml += f'      <data key="value">{edge["properties"]["value"]}</data>\n'
            graphml += '    </edge>\n'
        
        graphml += '  </graph>\n'
        graphml += '</graphml>'
        
        return graphml
    
    def _convert_to_dot(self, visualization_data: Dict) -> str:
        """Convert visualization data to DOT format."""
        dot = 'digraph transaction_flow {\n'
        dot += '  rankdir=LR;\n'
        dot += '  node [shape=box];\n'
        
        # Add nodes
        for node in visualization_data.get("nodes", []):
            dot += f'  "{node["id"]}" [label="{node["label"]}"];\n'
        
        # Add edges
        for edge in visualization_data.get("edges", []):
            value = edge["properties"]["value"]
            dot += f'  "{edge["source"]}" -> "{edge["target"]}" [label="${value:,.0f}"];\n'
        
        dot += '}'
        
        return dot 

# core/advanced_visualizer.py
import matplotlib.pyplot as plt
import networkx as nx
from typing import Dict, Any
import os

class AdvancedVisualizer:
    """Advanced visualization service."""
    
    def __init__(self, config: dict):
        self.config = config
        
    def create_comprehensive_visualization(self, result: Dict[str, Any]) -> str:
        """Create comprehensive visualization."""
        trace_data = result.get('trace_data', {})
        transactions = trace_data.get('transactions', [])
        
        if not transactions:
            return "No transactions to visualize"
            
        # Create a simple network graph
        G = nx.DiGraph()
        
        for tx in transactions:
            G.add_edge(tx.get('from', ''), tx.get('to', ''), 
                      weight=tx.get('value', 0))
        
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightblue', 
                node_size=1000, font_size=8, arrows=True)
        
        # Save the plot
        filename = f"transaction_graph_{trace_data.get('address', 'unknown')[:8]}.png"
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"📊 Visualization saved as: {filename}")
        return filename

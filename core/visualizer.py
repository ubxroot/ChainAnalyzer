"""
Visualizer Module
=================

Provides transaction flow visualization and analysis:
- Transaction flow diagrams
- Address relationship mapping
- Network graph generation
- Interactive visualizations
- Export capabilities
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class Visualizer:
    """Advanced visualization for blockchain transaction analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.visualization_config = config.get("visualization", {})
    
    def create_transaction_flow(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create transaction flow visualization data."""
        
        flow_data = {
            "type": "transaction_flow",
            "timestamp": datetime.now().isoformat(),
            "nodes": [],
            "edges": [],
            "metadata": {
                "total_transactions": 0,
                "total_addresses": 0,
                "total_volume": 0
            }
        }
        
        try:
            transactions = transaction_data.get("transactions", [])
            addresses = transaction_data.get("addresses", [])
            
            # Create nodes for addresses
            for address in addresses:
                node = {
                    "id": address,
                    "type": "address",
                    "label": address[:10] + "..." + address[-10:],
                    "properties": {
                        "full_address": address,
                        "transaction_count": 0,
                        "total_volume": 0
                    }
                }
                flow_data["nodes"].append(node)
            
            # Create edges for transactions
            for tx in transactions:
                from_addrs = tx.get("from_addresses", [])
                to_addrs = tx.get("to_addresses", [])
                value = tx.get("value_usd", 0)
                
                for from_addr in from_addrs:
                    for to_addr in to_addrs:
                        edge = {
                            "source": from_addr,
                            "target": to_addr,
                            "type": "transaction",
                            "properties": {
                                "tx_hash": tx.get("tx_hash", ""),
                                "value": value,
                                "timestamp": tx.get("timestamp", 0),
                                "currency": transaction_data.get("currency", "unknown")
                            }
                        }
                        flow_data["edges"].append(edge)
            
            # Update metadata
            flow_data["metadata"]["total_transactions"] = len(transactions)
            flow_data["metadata"]["total_addresses"] = len(addresses)
            flow_data["metadata"]["total_volume"] = sum(tx.get("value_usd", 0) for tx in transactions)
            
        except Exception as e:
            logger.error(f"Error creating transaction flow: {e}")
            flow_data["error"] = str(e)
        
        return flow_data
    
    def create_address_network(self, address_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create address network visualization."""
        
        network_data = {
            "type": "address_network",
            "timestamp": datetime.now().isoformat(),
            "nodes": [],
            "edges": [],
            "communities": [],
            "metadata": {
                "central_addresses": [],
                "isolated_addresses": [],
                "high_degree_addresses": []
            }
        }
        
        try:
            addresses = address_data.get("addresses", [])
            relationships = address_data.get("relationships", {})
            
            # Create nodes
            for address in addresses:
                node = {
                    "id": address,
                    "type": "address",
                    "label": address[:10] + "..." + address[-10:],
                    "properties": {
                        "full_address": address,
                        "degree": 0,
                        "in_degree": 0,
                        "out_degree": 0
                    }
                }
                network_data["nodes"].append(node)
            
            # Create edges from relationships
            address_connections = relationships.get("address_connections", {})
            for addr, connections in address_connections.items():
                # Outgoing connections
                for target in connections.get("sends_to", []):
                    edge = {
                        "source": addr,
                        "target": target,
                        "type": "sends_to",
                        "properties": {
                            "direction": "outgoing"
                        }
                    }
                    network_data["edges"].append(edge)
                
                # Incoming connections
                for source in connections.get("receives_from", []):
                    edge = {
                        "source": source,
                        "target": addr,
                        "type": "receives_from",
                        "properties": {
                            "direction": "incoming"
                        }
                    }
                    network_data["edges"].append(edge)
            
            # Calculate node properties
            self._calculate_node_properties(network_data)
            
            # Identify communities
            network_data["communities"] = self._identify_communities(network_data)
            
            # Update metadata
            self._update_network_metadata(network_data)
            
        except Exception as e:
            logger.error(f"Error creating address network: {e}")
            network_data["error"] = str(e)
        
        return network_data
    
    def create_risk_heatmap(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk heatmap visualization."""
        
        heatmap_data = {
            "type": "risk_heatmap",
            "timestamp": datetime.now().isoformat(),
            "data": [],
            "metadata": {
                "max_risk": 0,
                "min_risk": 1,
                "avg_risk": 0,
                "high_risk_count": 0
            }
        }
        
        try:
            addresses = risk_data.get("addresses", [])
            
            for address_info in addresses:
                address = address_info.get("address", "")
                risk_score = address_info.get("risk_score", 0)
                
                heatmap_entry = {
                    "address": address,
                    "risk_score": risk_score,
                    "risk_level": address_info.get("risk_level", "low"),
                    "coordinates": {
                        "x": hash(address) % 100,  # Simple hash-based positioning
                        "y": hash(address[::-1]) % 100
                    }
                }
                heatmap_data["data"].append(heatmap_entry)
            
            # Calculate metadata
            if heatmap_data["data"]:
                risk_scores = [entry["risk_score"] for entry in heatmap_data["data"]]
                heatmap_data["metadata"]["max_risk"] = max(risk_scores)
                heatmap_data["metadata"]["min_risk"] = min(risk_scores)
                heatmap_data["metadata"]["avg_risk"] = sum(risk_scores) / len(risk_scores)
                heatmap_data["metadata"]["high_risk_count"] = len([s for s in risk_scores if s > 0.7])
            
        except Exception as e:
            logger.error(f"Error creating risk heatmap: {e}")
            heatmap_data["error"] = str(e)
        
        return heatmap_data
    
    def create_timeline_visualization(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create timeline visualization of transactions."""
        
        timeline_data = {
            "type": "timeline",
            "timestamp": datetime.now().isoformat(),
            "events": [],
            "metadata": {
                "start_time": None,
                "end_time": None,
                "total_events": 0
            }
        }
        
        try:
            transactions = transaction_data.get("transactions", [])
            
            # Sort transactions by timestamp
            sorted_txs = sorted(transactions, key=lambda x: x.get("timestamp", 0))
            
            for tx in sorted_txs:
                event = {
                    "timestamp": tx.get("timestamp", 0),
                    "type": "transaction",
                    "title": f"Transaction {tx.get('tx_hash', '')[:10]}...",
                    "description": f"Value: ${tx.get('value_usd', 0):,.2f}",
                    "properties": {
                        "tx_hash": tx.get("tx_hash", ""),
                        "value": tx.get("value_usd", 0),
                        "from_addresses": tx.get("from_addresses", []),
                        "to_addresses": tx.get("to_addresses", [])
                    }
                }
                timeline_data["events"].append(event)
            
            # Update metadata
            if timeline_data["events"]:
                timestamps = [event["timestamp"] for event in timeline_data["events"]]
                timeline_data["metadata"]["start_time"] = min(timestamps)
                timeline_data["metadata"]["end_time"] = max(timestamps)
                timeline_data["metadata"]["total_events"] = len(timeline_data["events"])
            
        except Exception as e:
            logger.error(f"Error creating timeline visualization: {e}")
            timeline_data["error"] = str(e)
        
        return timeline_data
    
    def _calculate_node_properties(self, network_data: Dict[str, Any]):
        """Calculate node properties like degree centrality."""
        
        # Create adjacency lists
        in_edges = {}
        out_edges = {}
        
        for edge in network_data["edges"]:
            source = edge["source"]
            target = edge["target"]
            
            if target not in in_edges:
                in_edges[target] = []
            in_edges[target].append(source)
            
            if source not in out_edges:
                out_edges[source] = []
            out_edges[source].append(target)
        
        # Update node properties
        for node in network_data["nodes"]:
            node_id = node["id"]
            
            in_degree = len(in_edges.get(node_id, []))
            out_degree = len(out_edges.get(node_id, []))
            total_degree = in_degree + out_degree
            
            node["properties"]["in_degree"] = in_degree
            node["properties"]["out_degree"] = out_degree
            node["properties"]["degree"] = total_degree
    
    def _identify_communities(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify communities in the network using simple clustering."""
        
        communities = []
        visited = set()
        
        for node in network_data["nodes"]:
            if node["id"] in visited:
                continue
            
            # Start a new community
            community = {
                "id": f"community_{len(communities)}",
                "nodes": [],
                "size": 0,
                "properties": {}
            }
            
            # BFS to find connected nodes
            queue = [node["id"]]
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                
                visited.add(current)
                community["nodes"].append(current)
                
                # Find neighbors
                for edge in network_data["edges"]:
                    if edge["source"] == current and edge["target"] not in visited:
                        queue.append(edge["target"])
                    elif edge["target"] == current and edge["source"] not in visited:
                        queue.append(edge["source"])
            
            community["size"] = len(community["nodes"])
            communities.append(community)
        
        return communities
    
    def _update_network_metadata(self, network_data: Dict[str, Any]):
        """Update network metadata with analysis results."""
        
        nodes = network_data["nodes"]
        
        # Find central addresses (high degree)
        high_degree = [node["id"] for node in nodes if node["properties"]["degree"] > 10]
        network_data["metadata"]["high_degree_addresses"] = high_degree
        
        # Find isolated addresses (degree 0)
        isolated = [node["id"] for node in nodes if node["properties"]["degree"] == 0]
        network_data["metadata"]["isolated_addresses"] = isolated
        
        # Find central addresses (highest degree)
        if nodes:
            max_degree = max(node["properties"]["degree"] for node in nodes)
            central = [node["id"] for node in nodes if node["properties"]["degree"] == max_degree]
            network_data["metadata"]["central_addresses"] = central
    
    def export_visualization(self, visualization_data: Dict[str, Any], format: str = "json") -> str:
        """Export visualization data in various formats."""
        
        try:
            if format.lower() == "json":
                return json.dumps(visualization_data, indent=2, default=str)
            elif format.lower() == "csv":
                return self._export_to_csv(visualization_data)
            elif format.lower() == "dot":
                return self._export_to_dot(visualization_data)
            else:
                raise ValueError(f"Unsupported export format: {format}")
        
        except Exception as e:
            logger.error(f"Error exporting visualization: {e}")
            return f"Error: {str(e)}"
    
    def _export_to_csv(self, visualization_data: Dict[str, Any]) -> str:
        """Export visualization data to CSV format."""
        
        csv_lines = []
        
        if visualization_data["type"] == "transaction_flow":
            # Export nodes
            csv_lines.append("type,id,label,properties")
            for node in visualization_data.get("nodes", []):
                props = json.dumps(node.get("properties", {}))
                csv_lines.append(f"node,{node['id']},{node['label']},{props}")
            
            # Export edges
            csv_lines.append("\ntype,source,target,properties")
            for edge in visualization_data.get("edges", []):
                props = json.dumps(edge.get("properties", {}))
                csv_lines.append(f"edge,{edge['source']},{edge['target']},{props}")
        
        return "\n".join(csv_lines)
    
    def _export_to_dot(self, visualization_data: Dict[str, Any]) -> str:
        """Export visualization data to DOT format for Graphviz."""
        
        dot_lines = ["digraph G {"]
        
        if visualization_data["type"] == "transaction_flow":
            # Add nodes
            for node in visualization_data.get("nodes", []):
                dot_lines.append(f'  "{node["id"]}" [label="{node["label"]}"];')
            
            # Add edges
            for edge in visualization_data.get("edges", []):
                dot_lines.append(f'  "{edge["source"]}" -> "{edge["target"]}";')
        
        dot_lines.append("}")
        return "\n".join(dot_lines)
    
    def get_visualization_statistics(self, visualization_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get statistics about the visualization."""
        
        stats = {
            "type": visualization_data.get("type", "unknown"),
            "timestamp": visualization_data.get("timestamp", ""),
            "node_count": 0,
            "edge_count": 0,
            "metadata": {}
        }
        
        if "nodes" in visualization_data:
            stats["node_count"] = len(visualization_data["nodes"])
        
        if "edges" in visualization_data:
            stats["edge_count"] = len(visualization_data["edges"])
        
        if "metadata" in visualization_data:
            stats["metadata"] = visualization_data["metadata"]
        
        return stats

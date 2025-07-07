# core/visualizer.py

from typing import List, Dict, Any
from rich.console import Console
from rich.tree import Tree
from rich.text import Text

def visualize_flow(trace_result: List[Dict[str, Any]], console: Console):
    """
    Provides a basic textual visualization of the transaction flow.
    For more advanced graph visualization (e.g., using Graphviz),
    additional libraries and logic would be required.
    """
    if not trace_result:
        console.print("[dim]No data to visualize.[/dim]")
        return

    console.print("\n[bold blue]📊 Transaction Flow Visualization (Textual)[/bold blue]")
    
    # Create a dictionary to hold nodes for the graph
    nodes = {} # {address: Tree_Node_Object}
    edges = set() # To prevent duplicate edges

    # First pass: Create all unique address nodes
    for tx in trace_result:
        from_addr = tx.get("from_address", "N/A")
        to_addr = tx.get("to_address", "N/A")

        if from_addr != "N/A" and from_addr not in nodes:
            nodes[from_addr] = Tree(f"[blue]{from_addr[:10]}...[/blue]")
        if to_addr != "N/A" and to_addr not in nodes:
            nodes[to_addr] = Tree(f"[yellow]{to_addr[:10]}...[/yellow]")

    # Second pass: Connect nodes with transactions as branches
    # This approach assumes a somewhat linear flow for better tree representation.
    # For complex, highly branched graphs, a true graph library (like networkx + graphviz) is needed.

    # Find potential root addresses (addresses that are primarily 'from' addresses and not 'to' addresses in other transactions)
    all_from_addresses = {tx.get("from_address") for tx in trace_result if tx.get("from_address") != "N/A"}
    all_to_addresses = {tx.get("to_address") for tx in trace_result if tx.get("to_address") != "N/A"}
    
    root_addresses = all_from_addresses - all_to_addresses
    if not root_addresses and trace_result: # Fallback if no clear root (e.g., circular transactions)
        root_addresses = {trace_result[0].get("from_address")}

    if not root_addresses:
        console.print("[dim]Could not determine a clear starting point for visualization.[/dim]")
        return

    # Build the tree from each root
    for root_addr in sorted(list(root_addresses)):
        if root_addr == "N/A": continue # Skip N/A as a root

        root_tree = Tree(f"[bold white]Starting Address:[/bold white] [blue]{root_addr}[/blue]")
        
        # Use a queue for BFS-like traversal to build the tree
        q = deque([(root_tree, root_addr, 0)]) # (parent_node, current_address, current_depth)
        
        visited_nodes_for_tree = set() # To prevent infinite loops in cyclic graphs for tree display
        visited_nodes_for_tree.add(root_addr)

        while q:
            parent_node, current_addr_in_tree, current_depth = q.popleft()

            if current_depth >= 5: # Limit visual depth to avoid overly large trees
                parent_node.add("[dim]... (max depth reached)[/dim]")
                continue

            # Find transactions where current_addr_in_tree is the 'from' address
            for tx in trace_result:
                if tx.get("from_address") == current_addr_in_tree:
                    txid_short = tx.get("txid", "N/A")[:8]
                    amount = tx.get("amount", "N/A")
                    currency = tx.get("currency", "N/A")
                    to_addr = tx.get("to_address", "N/A")
                    
                    tx_node_label = f"[green]TX {txid_short}...[/green] ([white]{amount} {currency}[/white]) to [yellow]{to_addr[:10]}...[/yellow] (Depth: {tx.get('depth')})"
                    tx_node = parent_node.add(tx_node_label)
                    
                    if to_addr != "N/A" and to_addr not in visited_nodes_for_tree:
                        visited_nodes_for_tree.add(to_addr)
                        q.append((tx_node, to_addr, current_depth + 1))
        
        console.print(root_tree)

    console.print("[dim]Note: This is a simplified textual visualization. For interactive graphs, consider integrating with external tools like Graphviz (requires 'graphviz' package) or web-based libraries (D3.js, vis.js).[/dim]")


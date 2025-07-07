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
    
    # Create a tree structure to represent the flow
    # We'll try to build a simple tree based on 'from' and 'to' addresses
    # This is a simplified representation and might not capture complex branching perfectly.

    # Map addresses to their transactions
    address_tx_map = {}
    for tx in trace_result:
        txid = tx.get("txid", "UNKNOWN_TX")
        from_addr = tx.get("from_address", "N/A")
        to_addr = tx.get("to_address", "N/A")
        amount = tx.get("amount", "N/A")
        currency = tx.get("currency", "BTC") # Assuming BTC for now, or pass from main
        depth = tx.get("depth", 0)

        tx_description = f"TX: [cyan]{txid[:8]}...[/cyan] | [blue]{from_addr[:8]}...[/blue] -> [yellow]{to_addr[:8]}...[/yellow] | [green]{amount} {currency}[/green] (Depth: {depth})"
        
        if from_addr not in address_tx_map:
            address_tx_map[from_addr] = []
        address_tx_map[from_addr].append(tx_description)

        if to_addr not in address_tx_map:
            address_tx_map[to_addr] = []
        # No need to add to_addr's transactions here, they will be processed when 'to_addr' becomes 'current_address'

    # Find the initial address (or a common starting point for the tree)
    # This is a heuristic and might need refinement for complex graphs
    root_address = trace_result[0].get("from_address") if trace_result else "Unknown Start"
    if not root_address:
        for tx in trace_result:
            if tx.get("from_address"):
                root_address = tx["from_address"]
                break

    if not root_address:
        console.print("[dim]Could not determine a clear starting point for visualization.[/dim]")
        return

    tree = Tree(f"[bold white]Root Address:[/bold white] [blue]{root_address}[/blue]")

    # Simple recursive function to add nodes to the tree
    def add_to_tree(current_node: Tree, addr: str, current_depth: int):
        if current_depth > 5: # Limit tree depth for display
            return
        
        # Add transactions originating from this address
        for tx in trace_result:
            if tx.get("from_address") == addr:
                tx_id_short = tx.get("txid", "N/A")[:8]
                amount = tx.get("amount", "N/A")
                to_addr_short = tx.get("to_address", "N/A")[:8]
                tx_node = current_node.add(f"[green]TX {tx_id_short}...[/green] ([white]{amount}[/white]) to [yellow]{to_addr_short}...[/yellow] (Depth: {tx.get('depth')})")
                
                # Recursively add the 'to' address as a child for further transactions
                if tx.get("to_address") and tx.get("to_address") != addr:
                    add_to_tree(tx_node, tx["to_address"], current_depth + 1)

    add_to_tree(tree, root_address, 0)
    console.print(tree)

    console.print("[dim]Note: This is a simplified textual visualization. For interactive graphs, consider integrating with tools like Graphviz or D3.js.[/dim]")


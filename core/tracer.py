import requests
import json
from collections import deque
from typing import List, Dict, Any
from rich.console import Console # Import Console for logging within the worker
from rich.markup import escape # Import escape for rich.print

# Placeholder for API endpoints. In a real tool, you'd use actual blockchain explorer APIs.
# For demonstration, we'll use a mock API or a very basic public explorer.
# Example: Bitcoin Testnet API (BlockCypher)
# For real Bitcoin/Ethereum, you'd need more robust APIs like Blockchair, Etherscan, etc.
# IMPORTANT: Public APIs often have rate limits. For production, consider paid APIs.
API_ENDPOINTS = {
    "bitcoin": {
        "address_info": "https://blockchain.info/rawaddr/{address}",
        "tx_info": "https://blockchain.info/rawtx/{txid}"
    },
    "ethereum": {
        "address_info": "https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={api_key}",
        "tx_info": "https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={txid}&apikey={api_key}"
    }
    # Add more currencies as needed
}

def fetch_address_transactions(address: str, currency: str, api_key: str, console: Console) -> List[Dict[str, Any]]:
    """Fetches a list of transactions for a given address from a blockchain explorer API."""
    endpoint_config = API_ENDPOINTS.get(currency.lower())
    if not endpoint_config:
        console.print(f"[red]Error: Unsupported currency '{currency}'.[/red]")
        return []

    url = endpoint_config["address_info"].format(address=address, api_key=api_key)
    
    # Specific warning for Etherscan if API key is default
    if currency.lower() == "ethereum" and api_key == "YOUR_ETHERSCAN_API_KEY":
        console.print("[yellow]Warning: Etherscan API key not set in config. Ethereum tracing may fail or be rate-limited.[/yellow]")

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        transactions = []
        if currency.lower() == "bitcoin":
            # Blockchain.info for Bitcoin returns 'txs' for transactions
            for tx in data.get('txs', []):
                txid = tx.get('hash')
                # Summing output values for amount, assuming simple transfers
                # Note: This is a simplification. For accurate amounts, you'd need to
                # consider inputs/outputs relative to the traced address.
                amount = sum(out.get('value', 0) for out in tx.get('out', [])) / 10**8 # Convert satoshis to BTC
                
                # Determine from/to addresses (simplified: just first input/output)
                from_addr_list = [inp['prev_out']['addr'] for inp in tx['inputs'] if 'prev_out' in inp and 'addr' in inp['prev_out']]
                to_addr_list = [out['addr'] for out in tx['out'] if 'addr' in out]

                from_addr = ", ".join(from_addr_list) if from_addr_list else "N/A"
                to_addr = ", ".join(to_addr_list) if to_addr_list else "N/A"

                transactions.append({
                    "txid": txid,
                    "amount": amount,
                    "from_address": from_addr,
                    "to_address": to_addr,
                    "raw_data": tx # Keep raw data for verbose output
                })
        elif currency.lower() == "ethereum":
            # Etherscan for Ethereum returns 'result' for transactions
            for tx in data.get('result', []):
                # Etherscan amounts are in Wei, convert to Ether
                amount = int(tx.get('value', 0)) / 10**18
                transactions.append({
                    "txid": tx.get('hash'),
                    "amount": amount,
                    "from_address": tx.get('from'),
                    "to_address": tx.get('to'),
                    "raw_data": tx
                })
        return transactions
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Error fetching transactions for {address}: {escape(str(e))}[/red]")
        return []
    except json.JSONDecodeError:
        console.print(f"[red]Error: Could not decode JSON response for {address}.[/red]")
        return []
    except Exception as e:
        console.print(f"[red]An unexpected error occurred while fetching transactions for {address}: {escape(str(e))}[/red]")
        return []

def trace_crypto(start_address: str, currency: str, verbose: bool, depth: int, console: Console) -> List[Dict[str, Any]]:
    """
    Traces cryptocurrency transactions from a starting address up to a specified depth.
    Uses a breadth-first search (BFS) approach.
    """
    traced_transactions = []
    visited_addresses = set()
    queue = deque([(start_address, 0)]) # (address, current_depth)

    # Load API key from config (assuming config is loaded in main)
    # This is a simplified way to get API key. In a real app, you'd pass config or use a global.
    from utils.config import load_config
    config = load_config()
    api_key = config.get("api_keys", {}).get(currency.lower(), "YOUR_ETHERSCAN_API_KEY") # Default placeholder

    console.print(f"[dim]Starting BFS trace from {start_address} (max depth: {depth})...[/dim]")

    while queue and queue[0][1] <= depth:
        current_address, current_depth = queue.popleft()

        if current_address in visited_addresses:
            continue

        visited_addresses.add(current_address)
        console.print(f"[dim]  Processing address: {current_address} (Depth: {current_depth})[/dim]")

        txs = fetch_address_transactions(current_address, currency, api_key, console)
        if not txs:
            continue

        for tx in txs:
            # Add transaction to traced_transactions
            tx_info = {
                "type": "TX", # All are transactions for now
                "txid": tx.get("txid"),
                "amount": tx.get("amount"),
                "from_address": tx.get("from_address"),
                "to_address": tx.get("to_address"),
                "depth": current_depth,
                "currency": currency.upper(), # Add currency to tx_info
                "raw_data": tx.get("raw_data") if verbose else {} # Only include raw data if verbose
            }
            traced_transactions.append(tx_info)

            # Add connected addresses to the queue for further tracing
            # Trace both inputs and outputs for a comprehensive view
            if current_depth < depth:
                # For Bitcoin, from_address can be multiple. For simplicity, we just take the first.
                # For Ethereum, 'from' and 'to' are usually single.
                from_addrs_to_queue = tx_info["from_address"].split(", ") if ", " in tx_info["from_address"] else [tx_info["from_address"]]
                to_addrs_to_queue = tx_info["to_address"].split(", ") if ", " in tx_info["to_address"] else [tx_info["to_address"]]

                for addr in from_addrs_to_queue:
                    if addr != "N/A" and addr not in visited_addresses and addr != current_address:
                        queue.append((addr, current_depth + 1))
                for addr in to_addrs_to_queue:
                    if addr != "N/A" and addr not in visited_addresses and addr != current_address:
                        queue.append((addr, current_depth + 1))
    
    return traced_transactions


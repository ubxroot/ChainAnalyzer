# utils/risk.py

from typing import List, Dict, Any
import logging

logger = logging.getLogger("ChainAnalyzer") # Use the logger from utils.logger

def assess_risk(trace_result: List[Dict[str, Any]], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Performs a mock risk assessment based on transaction trace results.
    In a real scenario, this would involve complex heuristics,
    machine learning, and known illicit address databases.
    """
    risk_score = 0
    risk_factors = []

    if not trace_result:
        return {"score": 0, "factors": ["No transactions to assess."]}

    num_transactions = len(trace_result)
    
    # Get unique addresses involved in the trace
    unique_addresses = set()
    for tx in trace_result:
        if tx.get("from_address") != "N/A":
            unique_addresses.add(tx["from_address"])
        if tx.get("to_address") != "N/A":
            unique_addresses.add(tx["to_address"])

    # Factor 1: High number of transactions
    if num_transactions > 10: # Arbitrary threshold
        risk_score += 10
        risk_factors.append(f"High volume of transactions ({num_transactions}).")
    
    # Factor 2: Deep trace depth (could indicate layering/tumbling)
    max_depth = max(tx.get("depth", 0) for tx in trace_result)
    high_risk_depth_threshold = config.get("risk_thresholds", {}).get("high_risk_depth", 5)
    if max_depth >= high_risk_depth_threshold:
        risk_score += 15
        risk_factors.append(f"Deep transaction trace depth ({max_depth} hops) detected.")

    # Factor 3: High number of unique addresses (could indicate spreading funds)
    if unique_addresses and len(unique_addresses) > 10: # Arbitrary threshold
        risk_score += 10
        risk_factors.append(f"High number of unique addresses involved ({len(unique_addresses)}).")

    # Factor 4: Presence of certain patterns (mock for demonstration)
    # In a real tool, this would involve checking against known illicit addresses/clusters
    # For demonstration, let's use a few hardcoded mock illicit addresses
    mock_illicit_addresses = [
        "1FzW2z2M422F5fA55P55Q55R55S55T55U55V", # Bitcoin mock
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" # Ethereum mock
    ]
    
    illicit_involved = False
    for tx in trace_result:
        if tx.get("from_address") in mock_illicit_addresses or \
           tx.get("to_address") in mock_illicit_addresses:
            risk_score += 50 # High impact for illicit involvement
            risk_factors.append(f"Transaction involving known mock illicit address (TXID: {tx.get('txid', 'N/A')[:8]}...).")
            illicit_involved = True
            break 
    
    # Cap risk score at 100
    risk_score = min(risk_score, 100)

    logger.info(f"Risk assessment complete. Score: {risk_score}, Factors: {risk_factors}")
    return {"score": risk_score, "factors": risk_factors}


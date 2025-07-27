#!/usr/bin/env python3
"""
ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Transaction Forensics Tool
=============================================================================

Professional-grade cryptocurrency transaction analysis tool with:
- Multi-blockchain support with clean, readable output
- Advanced threat intelligence and risk scoring
- Real-time monitoring and alerting
- Simplified, professional display format
"""

import typer
import asyncio
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import sys
import logging

# Import core modules
from core.advanced_tracer import AdvancedMultiChainTracer
from core.ml_threat_intel import MLThreatIntelligence
from core.advanced_risk_analyzer import AdvancedRiskAnalyzer
from core.advanced_visualizer import AdvancedVisualizer
from core.comprehensive_reporter import ComprehensiveReporter
from core.realtime_monitor import RealtimeTransactionMonitor
from core.defi_analyzer import DeFiAnalyzer
from core.cross_chain_tracker import CrossChainTracker
from core.pattern_detector import PatternDetector
from core.address_clustering import AddressClustering

# Import utility modules
from utils.enhanced_config import EnhancedConfigManager
from utils.advanced_logger import AdvancedLogger
from utils.multi_api_client import MultiAPIClient
from utils.database_manager import DatabaseManager
from utils.cache_manager import CacheManager
from utils.encryption_utils import EncryptionUtils
from utils.performance_monitor import PerformanceMonitor

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'
    DIM = '\033[2m'

# Initialize Typer app
app = typer.Typer(
    name="chainanalyzer-pro",
    help="Advanced Multi-Blockchain Transaction Forensics Tool v3.5",
    add_completion=False,
    rich_markup_mode=None
)

logger = logging.getLogger(__name__)

def print_simple_banner():
    """Print compact ChainAnalyzer logo banner for terminal."""
    print(f"{Colors.BOLD}{Colors.BLUE}")
    
    # Compact ChainAnalyzer Logo
    logo = """
 ▄████▄   ██░ ██  ▄▄▄       ██▓ ███▄    █  ▄▄▄       ███▄    █  ▄▄▄       ██▓   ▓██   ██▓▒███████▒▓█████  ██▀███  
▒██▀ ▀█  ▓██░ ██▒▒████▄    ▓██▒ ██ ▀█   █ ▒████▄     ██ ▀█   █ ▒████▄    ▓██▒    ▒██  ██▒▒ ▒ ▒ ▄▀░▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒██▀▀██░▒██  ▀█▄  ▒██▒▓██  ▀█ ██▒▒██  ▀█▄  ▓██  ▀█ ██▒▒██  ▀█▄  ▒██░     ▒██ ██░░ ▒ ▄▀▒░ ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒░▓█ ░██ ░██▄▄▄▄██ ░██░▓██▒  ▐▌██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██░     ░ ▐██▓░  ▄▀▒   ░▒▓█  ▄ ▒██▀▀█▄  
▒ ▓███▀ ░░▓█▒░██▓ ▓█   ▓██▒░██░▒██░   ▓██░ ▓█   ▓██▒▒██░   ▓██░ ▓█   ▓██▒░██████▒ ░ ██▒▓░▒███████▒░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░▓  ░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░▓  ░  ██▒▒▒ ░▒▒ ▓░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒    ▒ ░▒░ ░  ▒   ▒▒ ░ ▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░ ▒  ░▓██ ░▒░ ░░▒ ▒ ░ ▒ ░ ░  ░  ░▒ ░ ▒░
░         ░  ░░ ░  ░   ▒    ▒ ░   ░   ░ ░   ░   ▒      ░   ░ ░   ░   ▒     ░ ░   ▒ ▒ ░░  ░ ░ ░ ░ ░   ░     ░░   ░ 
░ ░       ░  ░  ░      ░  ░ ░           ░       ░  ░         ░       ░  ░    ░  ░░ ░       ░ ░       ░  ░   ░     
░                                                                                ░ ░     ░                        
"""
    
    print(logo)
    print(f"{Colors.END}")
    
    # Header with attribution
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*100}")
    print(f"  Advanced Multi-Blockchain Transaction Forensics Tool v3.5")
    print(f"  {'By ubxroot':>85}")
    print(f"{'='*100}{Colors.END}")
    
    # Feature highlights
    print(f"{Colors.GREEN}✓ Multi-Chain Analysis  ✓ Threat Intelligence  ✓ DeFi Protocols  ✓ Risk Scoring{Colors.END}")
    print()


def display_simple_results(result: Dict[str, Any]):
    """Display simplified results for Kali Linux terminal."""
    
    trace_data = result.get('trace_data', {})
    risk_data = result.get('risk_analysis', {})
    
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  CHAINANALYZER ANALYSIS RESULTS")
    print(f"{'='*60}{Colors.END}")
    
    # Basic Information
    print(f"\n{Colors.CYAN}[INFO] Basic Information:{Colors.END}")
    print(f"  Target Address: {Colors.GREEN}{trace_data.get('address', 'N/A')}{Colors.END}")
    print(f"  Blockchain: {Colors.YELLOW}{trace_data.get('currency', 'N/A').upper()}{Colors.END}")
    print(f"  Transactions Found: {Colors.MAGENTA}{len(trace_data.get('transactions', []))}{Colors.END}")
    print(f"  Analysis Time: {Colors.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    
    # Risk Assessment
    print(f"\n{Colors.RED}[RISK] Risk Assessment:{Colors.END}")
    risk_score = risk_data.get('risk_score', 0)
    threat_level = risk_data.get('threat_level', 'Unknown')
    
    # Risk level coloring
    if threat_level == "LOW":
        risk_color = Colors.GREEN
    elif threat_level == "MEDIUM":
        risk_color = Colors.YELLOW
    elif threat_level == "HIGH":
        risk_color = Colors.RED
    else:
        risk_color = Colors.WHITE
    
    print(f"  Risk Score: {risk_color}{risk_score:.2f}/1.0{Colors.END}")
    print(f"  Threat Level: {risk_color}{threat_level}{Colors.END}")
    print(f"  Connected Addresses: {Colors.CYAN}{risk_data.get('interacting_address_count', 0)}{Colors.END}")
    
    # Suspicious patterns
    if risk_data.get('suspicious_patterns'):
        print(f"  Suspicious Patterns: {Colors.RED}{len(risk_data['suspicious_patterns'])}{Colors.END}")
        for i, pattern in enumerate(risk_data['suspicious_patterns'][:3], 1):
            print(f"    {i}. {Colors.RED}{pattern}{Colors.END}")
    else:
        print(f"  Suspicious Patterns: {Colors.GREEN}None detected{Colors.END}")
    
    # Transaction Timeline
    transactions = trace_data.get('transactions', [])
    if transactions:
        print(f"\n{Colors.CYAN}[TXN] Recent Transactions:{Colors.END}")
        print(f"  {'Hash':<20} {'From->To':<25} {'Value':<12} {'Time':<20}")
        print(f"  {'-'*80}")
        
        for i, tx in enumerate(transactions[:5], 1):  # Show first 5 transactions
            tx_hash = tx.get('hash', 'N/A')[:16] + "..."
            
            from_addr = tx.get('from_address', tx.get('from', 'N/A'))[:6] + "..."
            to_addr = tx.get('to_address', tx.get('to', 'N/A'))[:6] + "..."
            direction = f"{from_addr}->{to_addr}"
            
            value = tx.get('value', 0)
            if isinstance(value, (int, float)):
                value_display = f"{value:.4f}"
            else:
                value_display = str(value)[:10]
            
            timestamp = tx.get('timestamp', 'N/A')
            if isinstance(timestamp, str) and len(timestamp) > 16:
                time_display = timestamp[:16]
            else:
                time_display = str(timestamp)[:16]
            
            print(f"  {tx_hash:<20} {direction:<25} {value_display:<12} {time_display}")
        
        if len(transactions) > 5:
            print(f"  ... and {len(transactions) - 5} more transactions")
    
    # Financial Summary
    total_volume = risk_data.get('total_volume_usd', 0)
    if total_volume > 0:
        print(f"\n{Colors.GREEN}[USD] Financial Summary:{Colors.END}")
        print(f"  Total Volume: {Colors.GREEN}${total_volume:,.2f} USD{Colors.END}")
        if transactions:
            avg_value = total_volume / len(transactions)
            print(f"  Average TX Size: {Colors.CYAN}${avg_value:,.2f} USD{Colors.END}")
    
    # Threat Intelligence
    threat_intel = result.get('threat_intel', {})
    if threat_intel:
        print(f"\n{Colors.YELLOW}[INTEL] Threat Intelligence:{Colors.END}")
        print(f"  Threat Score: {Colors.RED}{threat_intel.get('threat_score', 0):.2f}/1.0{Colors.END}")
        print(f"  Blacklist Status: {threat_intel.get('blacklist_status', 'Unknown')}")
        
        if threat_intel.get('blacklist_matches'):
            print(f"  Blacklist Matches:")
            for match in threat_intel['blacklist_matches'][:3]:
                print(f"    - {Colors.RED}{match.get('source', 'Unknown')}: {match.get('type', 'Unknown')}{Colors.END}")
    
    # DeFi Analysis
    defi_data = result.get('defi_analysis', {})
    if defi_data and defi_data.get('defi_protocols'):
        print(f"\n{Colors.MAGENTA}[DEFI] Protocol Interactions:{Colors.END}")
        protocols = defi_data.get('defi_protocols', [])
        print(f"  Active Protocols: {Colors.MAGENTA}{', '.join(protocols)}{Colors.END}")
        print(f"  Total DeFi Value: {Colors.GREEN}${defi_data.get('total_defi_value', 0):,.2f}{Colors.END}")
        print(f"  Liquidity Positions: {Colors.CYAN}{defi_data.get('liquidity_positions', 0)}{Colors.END}")
    
    # Cross-Chain Analysis
    cross_chain = result.get('cross_chain', {})
    if cross_chain and cross_chain.get('chains_detected'):
        print(f"\n{Colors.BLUE}[BRIDGE] Cross-Chain Activity:{Colors.END}")
        chains = cross_chain.get('chains_detected', [])
        print(f"  Chains Detected: {Colors.BLUE}{', '.join(chains)}{Colors.END}")
        print(f"  Bridge Transactions: {Colors.CYAN}{len(cross_chain.get('bridge_transactions', []))}{Colors.END}")
        print(f"  Cross-Chain Value: {Colors.GREEN}${cross_chain.get('total_cross_chain_value', 0):,.2f}{Colors.END}")
    
    # Footer
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  Analysis Complete - Use --export for detailed report")
    print(f"{'='*60}{Colors.END}\n")

def display_comprehensive_results(result: Dict[str, Any], output_format: str, 
                                export: bool, visualize: bool, config: dict):
    """Display comprehensive analysis results in simple format."""
    
    display_simple_results(result)
    
    if visualize:
        try:
            visualizer = AdvancedVisualizer(config)
            filename = visualizer.create_comprehensive_visualization(result)
            print(f"{Colors.CYAN}[+] Visualization saved: {filename}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Visualization failed: {str(e)}{Colors.END}")
    
    if export:
        try:
            reporter = ComprehensiveReporter(config)
            report_path = reporter.generate_comprehensive_report(result)
            print(f"{Colors.GREEN}[+] Report exported: {report_path}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Export failed: {str(e)}{Colors.END}")

@app.command()
def trace(
    target: str = typer.Argument(..., help="Address, transaction hash, or ENS name"),
    blockchain: str = typer.Option("ethereum", "--chain", "-c", 
                                  help="Blockchain (ethereum, bitcoin, solana, polygon, bsc, etc.)"),
    depth: int = typer.Option(10, "--depth", "-d", help="Analysis depth (1-50)"),
    intelligence: bool = typer.Option(True, "--intel", help="Enable AI threat intelligence"),
    osint: bool = typer.Option(True, "--osint", help="Enable OSINT collection"),
    anonymous: bool = typer.Option(False, "--tor", help="Use Tor for anonymous analysis"),
    maltego: bool = typer.Option(False, "--maltego", help="Generate Maltego transform"),
    export_format: str = typer.Option("json", "--export", "-e", 
                                    help="Export format (json, csv, pdf, maltego, wireshark)"),
    output_dir: str = typer.Option("./reports", "--output", "-o", help="Output directory"),
    real_time: bool = typer.Option(False, "--monitor", help="Enable real-time monitoring"),
    profile: str = typer.Option("standard", "--profile", help="Analysis profile (quick, standard, deep, forensic)"),
    visualize: bool = typer.Option(False, "--visualize", help="Generate advanced visualizations"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output mode")
):
    """Advanced blockchain forensic analysis with OSINT and threat intelligence."""
    
    if not quiet:
        print_simple_banner()
    
    try:
        # Initialize enhanced components
        config = EnhancedConfigManager().load_config()
        perf_monitor = PerformanceMonitor()
        db_manager = DatabaseManager(config)
        cache_manager = CacheManager(config)
        
        with perf_monitor.measure("total_analysis"):
            # Display analysis parameters
            if not quiet:
                print(f"{Colors.CYAN}[INIT] Analysis Parameters:{Colors.END}")
                print(f"  Target: {Colors.GREEN}{target}{Colors.END}")
                print(f"  Chain: {Colors.YELLOW}{blockchain.upper()}{Colors.END}")
                print(f"  Depth: {Colors.MAGENTA}{depth}{Colors.END}")
                print(f"  Profile: {Colors.BLUE}{profile}{Colors.END}")
                print()
            
            # Initialize advanced services
            tracer = AdvancedMultiChainTracer(config, db_manager, cache_manager)
            risk_analyzer = AdvancedRiskAnalyzer(config)
            pattern_detector = PatternDetector(config) if True else None
            defi_analyzer = DeFiAnalyzer(config) if True else None
            cross_chain_tracker = CrossChainTracker(config) if False else None
            threat_intel_service = MLThreatIntelligence(config) if intelligence else None
            
            # Progress indicators
            if not quiet:
                print(f"{Colors.YELLOW}[>] Starting blockchain trace...{Colors.END}")
            
            analysis_result = asyncio.run(perform_simple_analysis(
                tracer, target, blockchain, 10, depth,
                risk_analyzer, pattern_detector, defi_analyzer,
                cross_chain_tracker, threat_intel_service,
                profile, quiet
            ))
            
            if not quiet:
                print(f"{Colors.GREEN}[✓] Analysis complete{Colors.END}")
            
            # Generate and display results
            if quiet:
                # Minimal output for quiet mode
                risk_score = analysis_result.get('risk_analysis', {}).get('risk_score', 0)
                threat_level = analysis_result.get('risk_analysis', {}).get('threat_level', 'Unknown')
                tx_count = len(analysis_result.get('trace_data', {}).get('transactions', []))
                print(f"Target: {target} | Risk: {risk_score:.2f} | Level: {threat_level} | TXs: {tx_count}")
            else:
                display_comprehensive_results(
                    analysis_result, "simple", export_format != "json", visualize, config
                )
            
            # Performance summary
            if not quiet:
                try:
                    perf_summary = perf_monitor.get_summary()
                    total_time = perf_summary.get('total_analysis', 0.0)
                    print(f"{Colors.DIM}[i] Completed in {total_time:.2f}s{Colors.END}")
                except Exception:
                    print(f"{Colors.DIM}[i] Analysis completed{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {str(e)}{Colors.END}")
        if not quiet:
            logger.exception("Critical error during trace analysis")
        sys.exit(1)

async def perform_simple_analysis(
    tracer, address, currency, max_hops, depth,
    risk_analyzer, pattern_detector, defi_analyzer,
    cross_chain_tracker, threat_intel_service,
    performance_mode, quiet
) -> Dict[str, Any]:
    """Perform comprehensive blockchain analysis with simple progress."""
    
    result = {}
    
    try:
        # Step 1: Basic transaction tracing
        if not quiet:
            print(f"{Colors.CYAN}[1/6] Tracing transactions...{Colors.END}")
        trace_data = await tracer.advanced_trace(address, currency, max_hops, depth)
        result['trace_data'] = trace_data
        
        # Step 2: Risk analysis
        if not quiet:
            print(f"{Colors.YELLOW}[2/6] Analyzing risk factors...{Colors.END}")
        risk_data = await risk_analyzer.comprehensive_risk_analysis(trace_data)
        result['risk_analysis'] = risk_data
        
        # Step 3: Pattern detection
        if pattern_detector:
            if not quiet:
                print(f"{Colors.MAGENTA}[3/6] Detecting patterns...{Colors.END}")
            patterns = await pattern_detector.detect_patterns(trace_data)
            result['patterns'] = patterns
        
        # Step 4: DeFi analysis
        if defi_analyzer:
            if not quiet:
                print(f"{Colors.BLUE}[4/6] Analyzing DeFi interactions...{Colors.END}")
            defi_data = await defi_analyzer.analyze_address_defi(address, currency)
            result['defi_analysis'] = defi_data
        
        # Step 5: Cross-chain tracking
        if cross_chain_tracker:
            if not quiet:
                print(f"{Colors.GREEN}[5/6] Cross-chain analysis...{Colors.END}")
            cross_chain_data = await cross_chain_tracker.track_cross_chain(address)
            result['cross_chain'] = cross_chain_data
        
        # Step 6: Threat intelligence
        if threat_intel_service:
            if not quiet:
                print(f"{Colors.RED}[6/6] Threat intelligence check...{Colors.END}")
            threat_data = await threat_intel_service.comprehensive_threat_check(address)
            result['threat_intel'] = threat_data
        
        return result
        
    except Exception as e:
        logger.exception(f"Error in analysis: {e}")
        raise

@app.callback()
def main():
    """ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Transaction Forensics Suite"""
    pass

if __name__ == "__main__":
    app()

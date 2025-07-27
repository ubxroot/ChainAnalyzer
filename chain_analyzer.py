#!/usr/bin/env python3
"""
ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Transaction Forensics Tool
=============================================================================

Professional-grade cryptocurrency transaction analysis tool with PyTorch ML backend
"""

import typer
import asyncio
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import sys
import logging
import numpy as np

# Import core modules (updated for PyTorch)
from core.pytorch_threat_intel import PyTorchThreatIntelligence
from core.advanced_tracer import AdvancedMultiChainTracer
from core.pytorch_risk_analyzer import PyTorchRiskAnalyzer
from core.advanced_visualizer import AdvancedVisualizer
from core.comprehensive_reporter import ComprehensiveReporter
from core.realtime_monitor import RealtimeTransactionMonitor
from core.defi_analyzer import DeFiAnalyzer
from core.cross_chain_tracker import CrossChainTracker
from core.pytorch_pattern_detector import PyTorchPatternDetector
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
    help="Advanced Multi-Blockchain Transaction Forensics Tool v3.5 with PyTorch",
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
    
    # Header with attribution and PyTorch info
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*100}")
    print(f"  Advanced Multi-Blockchain Transaction Forensics Tool v3.5")
    print(f"  {'By ubxroot':>85}")
    print(f"  {'Powered by PyTorch ' + torch.__version__:>85}")
    print(f"{'='*100}{Colors.END}")
    
    # Feature highlights with PyTorch capabilities
    print(f"{Colors.GREEN}✓ Multi-Chain Analysis  ✓ PyTorch ML Engine  ✓ DeFi Protocols  ✓ Smart Risk Scoring")
    print(f"✓ Real-time Detection   ✓ Pattern Recognition ✓ Cross-Chain     ✓ Advanced Analytics{Colors.END}")
    
    # Display PyTorch/CUDA info
    if torch.cuda.is_available():
        print(f"{Colors.YELLOW}⚡ GPU Acceleration: ENABLED (CUDA {torch.version.cuda}){Colors.END}")
    else:
        print(f"{Colors.DIM}⚡ GPU Acceleration: CPU-only mode{Colors.END}")
    print()

def display_simple_results(result: Dict[str, Any]):
    """Display simplified results for Kali Linux terminal with PyTorch metrics."""
    
    trace_data = result.get('trace_data', {})
    risk_data = result.get('risk_analysis', {})
    
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  CHAINANALYZER ANALYSIS RESULTS (PyTorch ML)")
    print(f"{'='*60}{Colors.END}")
    
    # Basic Information
    print(f"\n{Colors.CYAN}[INFO] Basic Information:{Colors.END}")
    print(f"  Target Address: {Colors.GREEN}{trace_data.get('address', 'N/A')}{Colors.END}")
    print(f"  Blockchain: {Colors.YELLOW}{trace_data.get('currency', 'N/A').upper()}{Colors.END}")
    print(f"  Transactions Found: {Colors.MAGENTA}{len(trace_data.get('transactions', []))}{Colors.END}")
    print(f"  Analysis Time: {Colors.DIM}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
    
    # PyTorch ML Analysis Results
    ml_results = result.get('pytorch_analysis', {})
    if ml_results:
        print(f"\n{Colors.MAGENTA}[ML] PyTorch Analysis:{Colors.END}")
        print(f"  Neural Network Confidence: {Colors.GREEN}{ml_results.get('confidence', 0):.3f}{Colors.END}")
        print(f"  Pattern Recognition Score: {Colors.CYAN}{ml_results.get('pattern_score', 0):.3f}{Colors.END}")
        print(f"  Anomaly Detection: {Colors.RED if ml_results.get('anomaly_detected') else Colors.GREEN}{'DETECTED' if ml_results.get('anomaly_detected') else 'NONE'}{Colors.END}")
    
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
    
    # ML-Detected Suspicious patterns
    if risk_data.get('suspicious_patterns'):
        print(f"  ML-Detected Patterns: {Colors.RED}{len(risk_data['suspicious_patterns'])}{Colors.END}")
        for i, pattern in enumerate(risk_data['suspicious_patterns'][:3], 1):
            confidence = pattern.get('confidence', 0) if isinstance(pattern, dict) else 0.8
            pattern_name = pattern.get('name', pattern) if isinstance(pattern, dict) else pattern
            print(f"    {i}. {Colors.RED}{pattern_name}{Colors.END} {Colors.DIM}(confidence: {confidence:.2f}){Colors.END}")
    else:
        print(f"  ML-Detected Patterns: {Colors.GREEN}None detected{Colors.END}")
    
    # Transaction Timeline
    transactions = trace_data.get('transactions', [])
    if transactions:
        print(f"\n{Colors.CYAN}[TXN] Recent Transactions:{Colors.END}")
        print(f"  {'Hash':<20} {'From->To':<25} {'Value':<12} {'Time':<20}")
        print(f"  {'-'*80}")
        
        for i, tx in enumerate(transactions[:5], 1):
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
    
    # Footer with PyTorch info
    print(f"\n{Colors.BOLD}{'='*60}")
    print(f"  PyTorch ML Analysis Complete - Use --export for detailed report")
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
    intelligence: bool = typer.Option(True, "--intel", help="Enable PyTorch AI threat intelligence"),
    osint: bool = typer.Option(True, "--osint", help="Enable OSINT collection"),
    export_format: str = typer.Option("json", "--export", "-e", 
                                    help="Export format (json, csv, pdf)"),
    profile: str = typer.Option("standard", "--profile", help="Analysis profile (quick, standard, deep, forensic)"),
    gpu: bool = typer.Option(False, "--gpu", help="Force GPU acceleration if available"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output mode")
):
    """Advanced blockchain forensic analysis with PyTorch ML engine."""
    
    if not quiet:
        print_simple_banner()
    
    try:
        # Check PyTorch setup
        device = torch.device("cuda" if gpu and torch.cuda.is_available() else "cpu")
        if not quiet:
            print(f"{Colors.CYAN}[ML] Using PyTorch device: {device}{Colors.END}")
        
        # Initialize components
        config = EnhancedConfigManager().load_config()
        config['ml_device'] = str(device)  # Add device info to config
        
        perf_monitor = PerformanceMonitor()
        db_manager = DatabaseManager(config)
        cache_manager = CacheManager(config)
        
        with perf_monitor.measure("total_analysis"):
            if not quiet:
                print(f"{Colors.CYAN}[INIT] Analysis Parameters:{Colors.END}")
                print(f"  Target: {Colors.GREEN}{target}{Colors.END}")
                print(f"  Chain: {Colors.YELLOW}{blockchain.upper()}{Colors.END}")
                print(f"  Depth: {Colors.MAGENTA}{depth}{Colors.END}")
                print(f"  ML Profile: {Colors.BLUE}{profile}{Colors.END}")
                print()
            
            # Initialize PyTorch-based services
            tracer = AdvancedMultiChainTracer(config, db_manager, cache_manager)
            risk_analyzer = PyTorchRiskAnalyzer(config, device)
            pattern_detector = PyTorchPatternDetector(config, device) if True else None
            threat_intel_service = PyTorchThreatIntelligence(config, device) if intelligence else None
            
            # Progress indicators
            if not quiet:
                print(f"{Colors.YELLOW}[>] Starting PyTorch-powered analysis...{Colors.END}")
            
            analysis_result = asyncio.run(perform_pytorch_analysis(
                tracer, target, blockchain, 10, depth,
                risk_analyzer, pattern_detector, threat_intel_service,
                profile, quiet, device
            ))
            
            if not quiet:
                print(f"{Colors.GREEN}[✓] PyTorch analysis complete{Colors.END}")
            
            # Display results
            if quiet:
                risk_score = analysis_result.get('risk_analysis', {}).get('risk_score', 0)
                threat_level = analysis_result.get('risk_analysis', {}).get('threat_level', 'Unknown')
                tx_count = len(analysis_result.get('trace_data', {}).get('transactions', []))
                ml_confidence = analysis_result.get('pytorch_analysis', {}).get('confidence', 0)
                print(f"Target: {target} | Risk: {risk_score:.2f} | Level: {threat_level} | TXs: {tx_count} | ML: {ml_confidence:.3f}")
            else:
                display_comprehensive_results(
                    analysis_result, "simple", export_format != "json", False, config
                )
            
            # Performance summary
            if not quiet:
                try:
                    perf_summary = perf_monitor.get_summary()
                    total_time = perf_summary.get('total_analysis', 0.0)
                    print(f"{Colors.DIM}[i] PyTorch analysis completed in {total_time:.2f}s{Colors.END}")
                except Exception:
                    print(f"{Colors.DIM}[i] Analysis completed{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {str(e)}{Colors.END}")
        if not quiet:
            logger.exception("Critical error during PyTorch analysis")
        sys.exit(1)

async def perform_pytorch_analysis(
    tracer, address, currency, max_hops, depth,
    risk_analyzer, pattern_detector, threat_intel_service,
    performance_mode, quiet, device
) -> Dict[str, Any]:
    """Perform comprehensive blockchain analysis with PyTorch ML."""
    
    result = {}
    
    try:
        # Step 1: Basic transaction tracing
        if not quiet:
            print(f"{Colors.CYAN}[1/5] Tracing transactions...{Colors.END}")
        trace_data = await tracer.advanced_trace(address, currency, max_hops, depth)
        result['trace_data'] = trace_data
        
        # Step 2: PyTorch risk analysis
        if not quiet:
            print(f"{Colors.YELLOW}[2/5] PyTorch risk analysis...{Colors.END}")
        risk_data = await risk_analyzer.pytorch_risk_analysis(trace_data)
        result['risk_analysis'] = risk_data
        
        # Step 3: PyTorch pattern detection
        if pattern_detector:
            if not quiet:
                print(f"{Colors.MAGENTA}[3/5] ML pattern detection...{Colors.END}")
            patterns = await pattern_detector.detect_patterns_pytorch(trace_data)
            result['patterns'] = patterns
            
            # Add PyTorch-specific analysis results
            result['pytorch_analysis'] = {
                'confidence': patterns.get('overall_confidence', 0.0),
                'pattern_score': patterns.get('pattern_score', 0.0),
                'anomaly_detected': patterns.get('anomaly_detected', False),
                'device_used': str(device)
            }
        
        # Step 4: PyTorch threat intelligence
        if threat_intel_service:
            if not quiet:
                print(f"{Colors.RED}[4/5] AI threat intelligence...{Colors.END}")
            threat_data = await threat_intel_service.pytorch_threat_check(address)
            result['threat_intel'] = threat_data
        
        # Step 5: Final ML aggregation
        if not quiet:
            print(f"{Colors.GREEN}[5/5] ML result aggregation...{Colors.END}")
        
        return result
        
    except Exception as e:
        logger.exception(f"Error in PyTorch analysis: {e}")
        raise

@app.callback()
def main():
    """ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Forensics with PyTorch ML"""
    pass

if __name__ == "__main__":
    app()

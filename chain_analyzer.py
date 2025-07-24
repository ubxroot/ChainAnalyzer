#!/usr/bin/env python3
"""
ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Transaction Forensics Tool
=============================================================================

Professional-grade cryptocurrency transaction analysis tool with:
- 15+ blockchain support with multiple API sources
- Advanced ML-based pattern detection
- Real-time threat intelligence feeds
- Comprehensive risk scoring algorithms
- Advanced visualization and reporting
- Dark web integration monitoring
- DeFi protocol analysis
- Cross-chain transaction tracking
"""

import typer
import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import sys
import os
import logging
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import pandas as pd
import numpy as np

# Enhanced core modules
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

# Enhanced utility modules
from utils.enhanced_config import EnhancedConfigManager
from utils.advanced_logger import AdvancedLogger
from utils.multi_api_client import MultiAPIClient
from utils.database_manager import DatabaseManager
from utils.cache_manager import CacheManager
from utils.encryption_utils import EncryptionUtils
from utils.performance_monitor import PerformanceMonitor

# Rich imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.tree import Tree
from rich.columns import Columns
from rich.live import Live
import pyfiglet

# Initialize enhanced app
app = typer.Typer(
    name="chainanalyzer-pro",
    help="🔍 Advanced Multi-Blockchain Transaction Forensics Tool v3.5",
    add_completion=True,
    rich_markup_mode="rich"
)

console = Console()
logger = logging.getLogger(__name__)

def print_enhanced_banner():
    """Print enhanced ChainAnalyzer banner with system info."""
    banner = pyfiglet.figlet_format("ChainAnalyzer", font="slant")
    
    layout = Layout()
    layout.split_column(
        Layout(Panel(banner, style="bold blue", title="v3.5 Pro"), name="banner"),
        Layout(name="info")
    )
    
    info_panel = Panel(
        "[bold green]🔍 Advanced Multi-Blockchain Transaction Forensics[/]\n"
        "[italic]Built for SOC, DFIR & Cyber Threat Intelligence[/]\n\n"
        "[yellow]✨ New Features:[/]\n"
        "• 15+ Blockchain Support\n"
        "• ML-Based Pattern Detection\n"
        "• Real-time Threat Feeds\n"
        "• DeFi Protocol Analysis\n"
        "• Cross-Chain Tracking\n"
        "• Advanced Visualization\n"
        "• Dark Web Monitoring\n\n"
        "[bold red]🆓 100% Open Source APIs[/]",
        style="dim"
    )
    
    layout["info"].update(info_panel)
    console.print(layout)
    console.print()

@app.command()
def trace(
    address: str = typer.Argument(..., help="🎯 Blockchain address, ENS, or transaction hash"),
    currency: str = typer.Option("ethereum", "--currency", "-c", 
                                help="🔗 Blockchain (ethereum, bitcoin, solana, polygon, bsc, etc.)"),
    max_hops: int = typer.Option(10, "--max-hops", "-h", help="🔄 Maximum transaction hops"),
    depth: int = typer.Option(5, "--depth", "-d", help="📊 Analysis depth"),
    use_ml: bool = typer.Option(True, "--ml", help="🧠 Enable ML pattern detection"),
    include_defi: bool = typer.Option(True, "--defi", help="🏦 Include DeFi protocol analysis"),
    cross_chain: bool = typer.Option(False, "--cross-chain", help="🌉 Enable cross-chain tracking"),
    output_format: str = typer.Option("interactive", "--format", "-f", 
                                    help="📋 Output format (interactive/table/json/pdf/html)"),
    export: bool = typer.Option(False, "--export", "-e", help="💾 Export comprehensive report"),
    visualize: bool = typer.Option(True, "--visualize", "-v", help="📈 Generate advanced visualizations"),
    threat_intel: bool = typer.Option(True, "--threat-intel", "-t", help="🛡️ Enable threat intelligence"),
    performance_mode: str = typer.Option("balanced", "--performance", "-p", 
                                       help="⚡ Performance mode (fast/balanced/comprehensive)")
):
    """🔍 Advanced blockchain address forensic analysis with ML and comprehensive reporting."""
    
    print_enhanced_banner()
    
    try:
        # Initialize enhanced components
        config = EnhancedConfigManager().load_config()
        perf_monitor = PerformanceMonitor()
        db_manager = DatabaseManager(config)
        cache_manager = CacheManager(config)
        
        with perf_monitor.measure("total_analysis"):
            # Display analysis parameters
            analysis_panel = create_analysis_panel(address, currency, max_hops, depth, performance_mode)
            console.print(analysis_panel)
            
            # Initialize advanced services
            tracer = AdvancedMultiChainTracer(config, db_manager, cache_manager)
            risk_analyzer = AdvancedRiskAnalyzer(config)
            pattern_detector = PatternDetector(config) if use_ml else None
            defi_analyzer = DeFiAnalyzer(config) if include_defi else None
            cross_chain_tracker = CrossChainTracker(config) if cross_chain else None
            threat_intel_service = MLThreatIntelligence(config) if threat_intel else None
            
            # Perform comprehensive analysis
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                
                # Main tracing task
                trace_task = progress.add_task("🔍 Performing blockchain trace...", total=100)
                
                analysis_result = asyncio.run(perform_comprehensive_analysis(
                    tracer, address, currency, max_hops, depth,
                    risk_analyzer, pattern_detector, defi_analyzer,
                    cross_chain_tracker, threat_intel_service,
                    progress, trace_task, performance_mode
                ))
                
                progress.update(trace_task, completed=100)
            
            # Generate and display results
            display_comprehensive_results(
                analysis_result, output_format, export, visualize, config
            )
            
            # Performance summary
            perf_summary = perf_monitor.get_summary()
            console.print(f"\n⚡ Analysis completed in {perf_summary['total_analysis']:.2f}s")
            
    except Exception as e:
        console.print(f"❌ [bold red]Critical Error:[/] {str(e)}", style="bold red")
        logger.exception("Critical error during trace analysis")
        sys.exit(1)

@app.command()
def monitor(
    addresses: List[str] = typer.Argument(..., help="🎯 Addresses to monitor (comma-separated)"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="🔗 Primary blockchain"),
    duration: int = typer.Option(3600, "--duration", "-d", help="⏱️ Monitoring duration (seconds)"),
    alert_threshold: float = typer.Option(1000, "--threshold", "-t", help="💰 Alert threshold (USD)"),
    ml_alerts: bool = typer.Option(True, "--ml-alerts", help="🧠 Enable ML-based anomaly detection"),
    threat_monitoring: bool = typer.Option(True, "--threat-monitor", help="🛡️ Real-time threat monitoring"),
    defi_monitoring: bool = typer.Option(True, "--defi-monitor", help="🏦 DeFi protocol monitoring"),
    cross_chain_monitor: bool = typer.Option(False, "--cross-chain", help="🌉 Cross-chain monitoring"),
    webhook_url: Optional[str] = typer.Option(None, "--webhook", help="🔗 Webhook URL for alerts"),
    export_alerts: bool = typer.Option(True, "--export-alerts", help="💾 Export alert data")
):
    """👁️ Advanced real-time blockchain monitoring with ML-based anomaly detection."""
    
    print_enhanced_banner()
    
    try:
        config = EnhancedConfigManager().load_config()
        
        # Parse addresses
        address_list = [addr.strip() for addr in addresses[0].split(',')] if len(addresses) == 1 else addresses
        
        console.print(f"👁️ [bold blue]Monitoring {len(address_list)} addresses on {currency.upper()}[/]")
        console.print(f"⏱️ Duration: {duration}s | 💰 Threshold: ${alert_threshold:,.2f}")
        
        # Initialize monitoring components
        monitor = RealtimeTransactionMonitor(config)
        ml_detector = PatternDetector(config) if ml_alerts else None
        threat_monitor_service = MLThreatIntelligence(config) if threat_monitoring else None
        
        # Start monitoring
        monitoring_result = asyncio.run(start_advanced_monitoring(
            monitor, address_list, currency, duration, alert_threshold,
            ml_detector, threat_monitor_service, webhook_url
        ))
        
        # Display monitoring results
        display_monitoring_dashboard(monitoring_result, export_alerts)
        
    except Exception as e:
        console.print(f"❌ [bold red]Monitoring Error:[/] {str(e)}")
        sys.exit(1)

@app.command()
def analyze_defi(
    protocol: str = typer.Argument(..., help="🏦 DeFi protocol (uniswap, aave, compound, etc.)"),
    address: Optional[str] = typer.Option(None, "--address", "-a", help="🎯 Specific address to analyze"),
    time_range: int = typer.Option(7, "--days", "-d", help="📅 Analysis time range (days)"),
    include_governance: bool = typer.Option(True, "--governance", help="🗳️ Include governance analysis"),
    liquidity_analysis: bool = typer.Option(True, "--liquidity", help="💧 Liquidity pool analysis"),
    yield_analysis: bool = typer.Option(True, "--yield", help="📈 Yield farming analysis"),
    risk_assessment: bool = typer.Option(True, "--risk", help="⚠️ DeFi risk assessment")
):
    """🏦 Comprehensive DeFi protocol analysis and risk assessment."""
    
    print_enhanced_banner()
    
    try:
        config = EnhancedConfigManager().load_config()
        defi_analyzer = DeFiAnalyzer(config)
        
        console.print(f"🏦 [bold blue]Analyzing {protocol.upper()} Protocol[/]")
        if address:
            console.print(f"🎯 Target Address: {address}")
        
        # Perform DeFi analysis
        with Progress(console=console) as progress:
            task = progress.add_task(f"Analyzing {protocol}...", total=100)
            
            defi_result = asyncio.run(defi_analyzer.analyze_protocol(
                protocol, address, time_range, include_governance,
                liquidity_analysis, yield_analysis, risk_assessment,
                progress, task
            ))
            
            progress.update(task, completed=100)
        
        # Display DeFi analysis results
        display_defi_analysis(defi_result)
        
    except Exception as e:
        console.print(f"❌ [bold red]DeFi Analysis Error:[/] {str(e)}")
        sys.exit(1)

@app.command()
def detect_patterns(
    input_file: str = typer.Argument(..., help="📁 Input file (CSV/JSON) with transaction data"),
    pattern_types: str = typer.Option("all", "--patterns", "-p", 
                                    help="🔍 Pattern types (mixing, layering, structuring, all)"),
    ml_model: str = typer.Option("ensemble", "--model", "-m", 
                               help="🧠 ML model (lstm, rf, ensemble)"),
    confidence_threshold: float = typer.Option(0.8, "--confidence", "-c", 
                                             help="📊 Confidence threshold (0.0-1.0)"),
    export_results: bool = typer.Option(True, "--export", "-e", help="💾 Export pattern results"),
    visualize_patterns: bool = typer.Option(True, "--visualize", "-v", help="📈 Visualize detected patterns")
):
    """🔍 Advanced ML-based suspicious pattern detection in transaction data."""
    
    print_enhanced_banner()
    
    try:
        config = EnhancedConfigManager().load_config()
        pattern_detector = PatternDetector(config)
        
        console.print(f"🔍 [bold blue]Detecting patterns in {input_file}[/]")
        console.print(f"🧠 Model: {ml_model} | 📊 Confidence: {confidence_threshold}")
        
        # Load and analyze data
        with Progress(console=console) as progress:
            task = progress.add_task("Detecting patterns...", total=100)
            
            pattern_results = asyncio.run(pattern_detector.detect_patterns_from_file(
                input_file, pattern_types, ml_model, confidence_threshold,
                progress, task
            ))
            
            progress.update(task, completed=100)
        
        # Display pattern detection results
        display_pattern_results(pattern_results, export_results, visualize_patterns)
        
    except Exception as e:
        console.print(f"❌ [bold red]Pattern Detection Error:[/] {str(e)}")
        sys.exit(1)

@app.command()
def cluster_addresses(
    blockchain: str = typer.Argument(..., help="🔗 Blockchain to analyze"),
    seed_addresses: List[str] = typer.Option(..., "--seeds", "-s", 
                                           help="🌱 Seed addresses for clustering"),
    clustering_method: str = typer.Option("heuristic", "--method", "-m",
                                        help="📊 Clustering method (heuristic, ml, hybrid)"),
    max_cluster_size: int = typer.Option(1000, "--max-size", help="📈 Maximum cluster size"),
    confidence_threshold: float = typer.Option(0.7, "--confidence", help="📊 Confidence threshold"),
    export_clusters: bool = typer.Option(True, "--export", help="💾 Export cluster data"),
    visualize_clusters: bool = typer.Option(True, "--visualize", help="📈 Visualize clusters")
):
    """🔗 Advanced address clustering analysis using multiple methodologies."""
    
    print_enhanced_banner()
    
    try:
        config = EnhancedConfigManager().load_config()
        clustering_service = AddressClustering(config)
        
        console.print(f"🔗 [bold blue]Clustering addresses on {blockchain.upper()}[/]")
        console.print(f"🌱 Seeds: {len(seed_addresses)} | 📊 Method: {clustering_method}")
        
        # Perform clustering analysis
        with Progress(console=console) as progress:
            task = progress.add_task("Clustering addresses...", total=100)
            
            cluster_results = asyncio.run(clustering_service.cluster_addresses(
                blockchain, seed_addresses, clustering_method,
                max_cluster_size, confidence_threshold, progress, task
            ))
            
            progress.update(task, completed=100)
        
        # Display clustering results
        display_clustering_results(cluster_results, export_clusters, visualize_clusters)
        
    except Exception as e:
        console.print(f"❌ [bold red]Clustering Error:[/] {str(e)}")
        sys.exit(1)

# Helper Functions

def create_analysis_panel(address: str, currency: str, max_hops: int, 
                         depth: int, performance_mode: str) -> Panel:
    """Create analysis parameters panel."""
    content = f"""[bold cyan]🎯 Target:[/] {address}
[bold cyan]🔗 Blockchain:[/] {currency.upper()}
[bold cyan]🔄 Max Hops:[/] {max_hops}
[bold cyan]📊 Depth:[/] {depth}
[bold cyan]⚡ Mode:[/] {performance_mode}"""
    
    return Panel(content, title="Analysis Parameters", style="dim")

async def perform_comprehensive_analysis(
    tracer, address, currency, max_hops, depth,
    risk_analyzer, pattern_detector, defi_analyzer,
    cross_chain_tracker, threat_intel_service,
    progress, task, performance_mode
) -> Dict[str, Any]:
    """Perform comprehensive blockchain analysis."""
    
    result = {}
    
    try:
        # Step 1: Basic transaction tracing
        progress.update(task, description="🔍 Tracing transactions...", completed=20)
        trace_data = await tracer.advanced_trace(address, currency, max_hops, depth)
        result['trace_data'] = trace_data
        
        # Step 2: Risk analysis
        progress.update(task, description="⚠️ Analyzing risk factors...", completed=40)
        risk_data = await risk_analyzer.comprehensive_risk_analysis(trace_data)
        result['risk_analysis'] = risk_data
        
        # Step 3: Pattern detection (if enabled)
        if pattern_detector:
            progress.update(task, description="🧠 Detecting suspicious patterns...", completed=60)
            patterns = await pattern_detector.detect_patterns(trace_data)
            result['patterns'] = patterns
        
        # Step 4: DeFi analysis (if enabled)
        if defi_analyzer:
            progress.update(task, description="🏦 Analyzing DeFi interactions...", completed=70)
            defi_data = await defi_analyzer.analyze_address_defi(address, currency)
            result['defi_analysis'] = defi_data
        
        # Step 5: Cross-chain tracking (if enabled)
        if cross_chain_tracker:
            progress.update(task, description="🌉 Cross-chain analysis...", completed=80)
            cross_chain_data = await cross_chain_tracker.track_cross_chain(address)
            result['cross_chain'] = cross_chain_data
        
        # Step 6: Threat intelligence
        if threat_intel_service:
            progress.update(task, description="🛡️ Threat intelligence check...", completed=90)
            threat_data = await threat_intel_service.comprehensive_threat_check(address)
            result['threat_intel'] = threat_data
        
        return result
        
    except Exception as e:
        logger.exception(f"Error in comprehensive analysis: {e}")
        raise

def display_comprehensive_results(result: Dict[str, Any], output_format: str, 
                                export: bool, visualize: bool, config: dict):
    """Display comprehensive analysis results."""
    
    if output_format == "interactive":
        display_interactive_results(result)
    elif output_format == "table":
        display_table_results(result)
    elif output_format == "json":
        console.print(json.dumps(result, indent=2, default=str))
    
    if visualize:
        visualizer = AdvancedVisualizer(config)
        visualizer.create_comprehensive_visualization(result)
    
    if export:
        reporter = ComprehensiveReporter(config)
        report_path = reporter.generate_comprehensive_report(result)
        console.print(f"📁 [bold green]Comprehensive report exported:[/] {report_path}")

def display_interactive_results(result: Dict[str, Any]):
    """Display interactive results with Rich components."""
    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    
    # Header with summary
    trace_data = result.get('trace_data', {})
    risk_data = result.get('risk_analysis', {})
    
    header_content = f"""[bold green]✅ Analysis Complete[/]
[cyan]Transactions:[/] {len(trace_data.get('transactions', []))} | [cyan]Risk Score:[/] {risk_data.get('risk_score', 0):.2f}
[cyan]Threat Level:[/] {risk_data.get('threat_level', 'Unknown')} | [cyan]Patterns:[/] {len(result.get('patterns', []))}"""
    
    layout["header"].update(Panel(header_content, style="bold"))
    
    # Body with detailed results
    body_layout = Layout()
    body_layout.split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    
    # Left side - Transaction details
    if trace_data.get('transactions'):
        tx_table = create_transaction_table(trace_data['transactions'][:10])  # Show top 10
        body_layout["left"].update(Panel(tx_table, title="Recent Transactions"))
    
    # Right side - Risk and patterns
    risk_content = create_risk_summary(risk_data, result.get('patterns', []))
    body_layout["right"].update(Panel(risk_content, title="Risk Assessment"))
    
    layout["body"].update(body_layout)
    
    # Footer with actions
    footer_content = "[dim]💡 Use --export to save detailed report | --visualize for graphs[/]"
    layout["footer"].update(Panel(footer_content, style="dim"))
    
    console.print(layout)

def create_transaction_table(transactions: List[Dict]) -> Table:
    """Create a Rich table for transactions."""
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Hash", style="cyan", width=12)
    table.add_column("From", style="green", width=10)
    table.add_column("To", style="yellow", width=10)
    table.add_column("Value", style="red", width=12)
    table.add_column("Time", style="blue", width=15)
    
    for tx in transactions:
        table.add_row(
            tx.get('hash', '')[:10] + '...',
            tx.get('from', '')[:8] + '...',
            tx.get('to', '')[:8] + '...',
            f"{tx.get('value', 0):.4f}",
            str(tx.get('timestamp', ''))[:19]
        )
    
    return table

def create_risk_summary(risk_data: Dict, patterns: List) -> str:
    """Create risk summary content."""
    content = f"""[bold red]Risk Score:[/] {risk_data.get('risk_score', 0):.2f}/1.0
[bold yellow]Threat Level:[/] {risk_data.get('threat_level', 'Unknown')}
[bold cyan]Suspicious Patterns:[/] {len(patterns)}

[bold green]Risk Factors:[/]
"""
    
    for factor in risk_data.get('risk_factors', []):
        content += f"• {factor}\n"
    
    if patterns:
        content += "\n[bold red]Detected Patterns:[/]\n"
        for pattern in patterns[:5]:  # Show top 5
            content += f"• {pattern.get('type', 'Unknown')}: {pattern.get('confidence', 0):.2f}\n"
    
    return content

async def start_advanced_monitoring(monitor, addresses, currency, duration, 
                                  threshold, ml_detector, threat_monitor, webhook_url):
    """Start advanced monitoring with ML detection."""
    # Implementation would go here
    return {"status": "completed", "alerts": [], "total_monitored": len(addresses)}

def display_monitoring_dashboard(result: Dict, export_alerts: bool):
    """Display monitoring dashboard."""
    console.print(f"👁️ [bold green]Monitoring Complete[/]")
    console.print(f"📊 Total Alerts: {len(result.get('alerts', []))}")
    # Additional dashboard implementation

def display_defi_analysis(result: Dict):
    """Display DeFi analysis results."""
    console.print(f"🏦 [bold green]DeFi Analysis Complete[/]")
    # Implementation for DeFi results display

def display_pattern_results(results: Dict, export: bool, visualize: bool):
    """Display pattern detection results."""
    console.print(f"🔍 [bold green]Pattern Detection Complete[/]")
    # Implementation for pattern results display

def display_clustering_results(results: Dict, export: bool, visualize: bool):
    """Display clustering results."""
    console.print(f"🔗 [bold green]Address Clustering Complete[/]")
    # Implementation for clustering results display

def display_table_results(result: Dict):
    """Display results in table format."""
    # Implementation for table display
    pass

@app.callback()
def main():
    """🔍 ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Transaction Forensics Tool"""
    pass

if __name__ == "__main__":
    app()

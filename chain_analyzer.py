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

# Rich imports for beautiful CLI
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
import pyfiglet

# Initialize Typer app
app = typer.Typer(
    name="chainanalyzer-pro",
    help="🔍 Advanced Multi-Blockchain Transaction Forensics Tool v3.5",
    add_completion=True,
    rich_markup_mode="rich"
)

# Initialize Rich console
console = Console()
logger = logging.getLogger(__name__)

def print_enhanced_banner():
    """Print enhanced ChainAnalyzer banner with system info."""
    banner = pyfiglet.figlet_format("ChainAnalyzer", font="slant")
    
    console.print(Panel(banner, style="bold blue", title="v3.5 Pro"))
    
    info_content = """[bold green]🔍 Advanced Multi-Blockchain Transaction Forensics[/]
[italic]Built for SOC, DFIR & Cyber Threat Intelligence[/]

[yellow]✨ Features:[/]
• 15+ Blockchain Support
• ML-Based Pattern Detection  
• Real-time Threat Feeds
• DeFi Protocol Analysis
• Cross-Chain Tracking
• Advanced Visualization
• Clean, Professional Output

[bold red]🆓 100% Open Source APIs[/]"""
    
    console.print(Panel(info_content, style="dim"))
    console.print()

def display_interactive_results(result: Dict[str, Any]):
    """Display simplified, clear results without excessive boxes."""
    
    trace_data = result.get('trace_data', {})
    risk_data = result.get('risk_analysis', {})
    
    # Main header with essential info
    console.print()
    console.print("="*80, style="bold blue")
    console.print(f"🔍 CHAINANALYZER ANALYSIS RESULTS", style="bold blue", justify="center")
    console.print("="*80, style="bold blue")
    console.print()
    
    # Basic Information Section
    console.print("📋 [bold cyan]BASIC INFORMATION[/bold cyan]")
    console.print("-" * 40)
    console.print(f"Target Address: [green]{trace_data.get('address', 'N/A')}[/green]")
    console.print(f"Blockchain: [yellow]{trace_data.get('currency', 'N/A')}[/yellow]")
    console.print(f"Total Transactions Found: [magenta]{len(trace_data.get('transactions', []))}[/magenta]")
    console.print(f"Analysis Date: [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")
    console.print()
    
    # Risk Assessment Section
    console.print("⚠️  [bold red]RISK ASSESSMENT[/bold red]")
    console.print("-" * 40)
    risk_score = risk_data.get('risk_score', 0)
    threat_level = risk_data.get('threat_level', 'Unknown')
    
    # Color code the risk level
    if threat_level == "LOW":
        risk_color = "green"
    elif threat_level == "MEDIUM":
        risk_color = "yellow"
    elif threat_level == "HIGH":
        risk_color = "red"
    else:
        risk_color = "white"
    
    console.print(f"Risk Score: [{risk_color}]{risk_score:.2f}/1.0[/{risk_color}]")
    console.print(f"Threat Level: [{risk_color}]{threat_level}[/{risk_color}]")
    console.print(f"Interacting Addresses: [cyan]{risk_data.get('interacting_address_count', 0)}[/cyan]")
    
    if risk_data.get('suspicious_patterns'):
        console.print(f"Suspicious Patterns Detected: [red]{len(risk_data['suspicious_patterns'])}[/red]")
        for i, pattern in enumerate(risk_data['suspicious_patterns'][:3], 1):
            console.print(f"  {i}. [red]{pattern}[/red]")
    else:
        console.print("Suspicious Patterns: [green]None detected[/green]")
    console.print()
    
    # Transaction Timeline Section
    transactions = trace_data.get('transactions', [])
    if transactions:
        console.print("📊 [bold cyan]TRANSACTION TIMELINE[/bold cyan]")
        console.print("-" * 80)
        console.print(f"{'#':<3} {'Transaction Hash':<20} {'From → To':<30} {'Value':<12} {'Timestamp':<20}")
        console.print("-" * 80)
        
        for i, tx in enumerate(transactions[:10], 1):  # Show first 10 transactions
            # Format hash
            tx_hash = tx.get('hash', 'N/A')
            hash_display = tx_hash[:18] + "..." if len(tx_hash) > 18 else tx_hash
            
            # Format addresses
            from_addr = tx.get('from_address', tx.get('from', 'N/A'))
            to_addr = tx.get('to_address', tx.get('to', 'N/A'))
            from_display = from_addr[:8] + "..." if len(from_addr) > 8 else from_addr
            to_display = to_addr[:8] + "..." if len(to_addr) > 8 else to_addr
            direction = f"{from_display} → {to_display}"
            
            # Format value
            value = tx.get('value', 0)
            if isinstance(value, (int, float)):
                value_display = f"{value:.4f}"
            else:
                value_display = str(value)
            
            # Format timestamp
            timestamp = tx.get('timestamp', 'N/A')
            if isinstance(timestamp, str) and len(timestamp) > 19:
                time_display = timestamp[:19]
            else:
                time_display = str(timestamp)
            
            console.print(f"{i:<3} {hash_display:<20} {direction:<30} {value_display:<12} {time_display:<20}")
        
        if len(transactions) > 10:
            console.print(f"\n... and {len(transactions) - 10} more transactions")
        console.print()
    
    # Financial Summary Section
    total_volume = risk_data.get('total_volume_usd', 0)
    if total_volume > 0:
        console.print("💰 [bold green]FINANCIAL SUMMARY[/bold green]")
        console.print("-" * 40)
        console.print(f"Total Transaction Volume: [green]${total_volume:,.2f} USD[/green]")
        
        # Calculate average transaction size
        if transactions:
            avg_value = total_volume / len(transactions)
            console.print(f"Average Transaction Size: [cyan]${avg_value:,.2f} USD[/cyan]")
        console.print()
    
    # Threat Intelligence Section
    threat_intel = result.get('threat_intel', {})
    if threat_intel:
        console.print("🛡️  [bold yellow]THREAT INTELLIGENCE[/bold yellow]")
        console.print("-" * 40)
        console.print(f"Threat Score: [red]{threat_intel.get('threat_score', 0):.2f}/1.0[/red]")
        console.print(f"Blacklist Status: {threat_intel.get('blacklist_status', 'Unknown')}")
        
        if threat_intel.get('blacklist_matches'):
            console.print("Blacklist Matches:")
            for match in threat_intel['blacklist_matches'][:3]:
                console.print(f"  • [red]{match.get('source', 'Unknown')}: {match.get('type', 'Unknown')}[/red]")
        console.print()
    
    # DeFi Analysis Section
    defi_data = result.get('defi_analysis', {})
    if defi_data and defi_data.get('defi_protocols'):
        console.print("🏦 [bold magenta]DEFI PROTOCOL INTERACTIONS[/bold magenta]")
        console.print("-" * 40)
        protocols = defi_data.get('defi_protocols', [])
        console.print(f"Active Protocols: [magenta]{', '.join(protocols)}[/magenta]")
        console.print(f"Total DeFi Value: [green]${defi_data.get('total_defi_value', 0):,.2f}[/green]")
        console.print(f"Liquidity Positions: [cyan]{defi_data.get('liquidity_positions', 0)}[/cyan]")
        console.print()
    
    # Cross-Chain Analysis Section
    cross_chain = result.get('cross_chain', {})
    if cross_chain and cross_chain.get('chains_detected'):
        console.print("🌉 [bold blue]CROSS-CHAIN ACTIVITY[/bold blue]")
        console.print("-" * 40)
        chains = cross_chain.get('chains_detected', [])
        console.print(f"Chains Detected: [blue]{', '.join(chains)}[/blue]")
        console.print(f"Bridge Transactions: [cyan]{len(cross_chain.get('bridge_transactions', []))}[/cyan]")
        console.print(f"Total Cross-Chain Value: [green]${cross_chain.get('total_cross_chain_value', 0):,.2f}[/green]")
        console.print()
    
    # Analysis Summary Footer
    console.print("="*80, style="bold blue")
    console.print(f"✅ [bold green]Analysis Complete[/bold green] | Use --export for detailed report | --visualize for graphs")
    console.print("="*80, style="bold blue")
    console.print()

@app.command()
def trace(
    target: str = typer.Argument(..., help="🎯 Address, transaction hash, or ENS name"),
    blockchain: str = typer.Option("ethereum", "--chain", "-c", 
                                  help="🔗 Blockchain (ethereum, bitcoin, solana, polygon, bsc, etc.)"),
    depth: int = typer.Option(10, "--depth", "-d", help="📊 Analysis depth (1-50)"),
    intelligence: bool = typer.Option(True, "--intel", help="🧠 Enable AI threat intelligence"),
    export_format: str = typer.Option("json", "--export", "-e", 
                                    help="📁 Export format (json, csv, pdf)"),
    output_dir: str = typer.Option("./reports", "--output", "-o", help="📂 Output directory"),
    visualize: bool = typer.Option(True, "--visualize", help="📈 Generate visualizations")
):
    """🔍 Advanced blockchain forensic analysis with clean, readable output."""
    
    print_enhanced_banner()
    
    try:
        # Initialize enhanced components
        config = EnhancedConfigManager().load_config()
        perf_monitor = PerformanceMonitor()
        db_manager = DatabaseManager(config)
        cache_manager = CacheManager(config)
        
        with perf_monitor.measure("total_analysis"):
            # Display analysis parameters
            console.print(f"🎯 [bold blue]Target:[/] {target}")
            console.print(f"🔗 [bold blue]Blockchain:[/] {blockchain.upper()}")
            console.print(f"📊 [bold blue]Depth:[/] {depth}")
            console.print()
            
            # Initialize advanced services
            tracer = AdvancedMultiChainTracer(config, db_manager, cache_manager)
            risk_analyzer = AdvancedRiskAnalyzer(config)
            threat_intel_service = MLThreatIntelligence(config) if intelligence else None
            
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
                    tracer, target, blockchain, depth,
                    risk_analyzer, threat_intel_service,
                    progress, trace_task
                ))
                
                progress.update(trace_task, completed=100)
            
            # Generate and display results
            display_interactive_results(analysis_result)
            
            if visualize:
                visualizer = AdvancedVisualizer(config)
                filename = visualizer.create_comprehensive_visualization(analysis_result)
                console.print(f"📊 Visualization saved as: [cyan]{filename}[/cyan]")
            
            # Performance summary
            try:
                perf_summary = perf_monitor.get_summary()
                total_time = perf_summary.get('total_analysis', 0.0)
                console.print(f"⚡ Analysis completed in {total_time:.2f}s")
            except Exception:
                console.print(f"⚡ Analysis completed successfully")
                
    except Exception as e:
        console.print(f"❌ [bold red]Critical Error:[/] {str(e)}", style="bold red")
        logger.exception("Critical error during trace analysis")
        sys.exit(1)

async def perform_comprehensive_analysis(
    tracer, address, currency, depth,
    risk_analyzer, threat_intel_service,
    progress, task
) -> Dict[str, Any]:
    """Perform comprehensive blockchain analysis."""
    
    result = {}
    
    try:
        # Step 1: Basic transaction tracing
        progress.update(task, description="🔍 Tracing transactions...", completed=20)
        trace_data = await tracer.advanced_trace(address, currency, 10, depth)
        result['trace_data'] = trace_data
        
        # Step 2: Risk analysis
        progress.update(task, description="⚠️ Analyzing risk factors...", completed=60)
        risk_data = await risk_analyzer.comprehensive_risk_analysis(trace_data)
        result['risk_analysis'] = risk_data
        
        # Step 3: Threat intelligence
        if threat_intel_service:
            progress.update(task, description="🛡️ Threat intelligence check...", completed=90)
            threat_data = await threat_intel_service.comprehensive_threat_check(address)
            result['threat_intel'] = threat_data
        
        return result
        
    except Exception as e:
        logger.exception(f"Error in comprehensive analysis: {e}")
        raise

@app.callback()
def main():
    """🛡️ ChainAnalyzer v3.5 Pro - Advanced Multi-Blockchain Transaction Forensics Suite"""
    pass

if __name__ == "__main__":
    app()

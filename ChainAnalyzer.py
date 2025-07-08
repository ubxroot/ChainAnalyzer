#!/usr/bin/env python3
"""
ChainAnalyzer - Advanced Multi-Blockchain Transaction Forensics Tool
====================================================================

A professional-grade cryptocurrency transaction analysis tool designed for:
- Security Operations Centers (SOC)
- Digital Forensics and Incident Response (DFIR)
- Cyber Threat Intelligence teams

Features:
- Multi-blockchain tracing (Bitcoin, Ethereum, Solana, Tron, Polygon, BSC)
- Advanced threat intelligence and risk scoring
- Rich CLI output with tables and visualizations
- SOC/DFIR ready reporting and alerting
- Real-time monitoring capabilities
- Cross-platform support (Linux-first, Windows, macOS)

Author: UBXROOT Security Team
Version: 2.0.0
License: MIT
"""

import typer
import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
import sys
import os

# Rich imports for professional CLI output
from rich import print
from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.live import Live
from rich.align import Align

# Core imports
from core.tracer import MultiChainTracer
from core.threat_intel import ThreatIntelligence
from core.risk_analyzer import RiskAnalyzer
from core.visualizer import TransactionVisualizer
from core.reporter import ReportGenerator
from core.monitor import RealTimeMonitor
from utils.logger import setup_logger
from utils.config import ConfigManager
from utils.database import DatabaseManager
from utils.api_client import APIClient
from utils.exporters import ExportManager

# ASCII Art and branding
import pyfiglet

# Initialize Typer app and Rich console
app = typer.Typer(
    help="🕵️ ChainAnalyzer - Advanced Multi-Blockchain Transaction Forensics Tool",
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()

# Global configuration
config_manager = ConfigManager()
logger = setup_logger()

# ASCII Banner
def create_banner() -> Text:
    """Create professional ASCII banner for ChainAnalyzer."""
    banner_text = Text()
    
    # Main title
    title = pyfiglet.figlet_format("ChainAnalyzer", font="slant")
    banner_text.append(title, style="bold blue")
    
    # Subtitle
    banner_text.append("\nAdvanced Multi-Blockchain Transaction Forensics\n", style="bright_cyan")
    banner_text.append("SOC • DFIR • Threat Intelligence Ready\n", style="yellow")
    banner_text.append("v2.0.0 | UBXROOT Security Team\n", style="dim white")
    
    return banner_text

CHAIN_ANALYZER_BANNER = create_banner()

@app.command()
def trace(
    currency: str = typer.Option(..., "--currency", "-c", help="Blockchain to trace (bitcoin, ethereum, solana, tron, polygon, bsc)"),
    address: str = typer.Argument(..., help="Wallet address to trace"),
    max_hops: int = typer.Option(5, "--hops", "-h", help="Maximum transaction hops to trace"),
    depth: int = typer.Option(3, "--depth", "-d", help="Tracing depth (1-10)"),
    realtime: bool = typer.Option(False, "--realtime", "-r", help="Enable real-time monitoring"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv, pdf"),
    visualize: bool = typer.Option(True, "--visualize", "-v", help="Generate transaction flow visualization"),
    export: bool = typer.Option(False, "--export", "-e", help="Export results to file"),
    threat_check: bool = typer.Option(True, "--threat-check", help="Perform threat intelligence analysis"),
    risk_assessment: bool = typer.Option(True, "--risk", help="Perform risk assessment"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output mode")
):
    """
    🕵️ Comprehensive blockchain transaction tracing and analysis.
    
    Supports multiple blockchains with advanced threat intelligence,
    risk scoring, and professional reporting capabilities.
    """
    console.print(CHAIN_ANALYZER_BANNER)
    
    # Initialize components
    config = config_manager.load_config()
    tracer = MultiChainTracer(config)
    threat_intel = ThreatIntelligence(config)
    risk_analyzer = RiskAnalyzer(config)
    visualizer = TransactionVisualizer()
    reporter = ReportGenerator()
    export_manager = ExportManager()
    
    # Display trace information
    console.print(f"\n[bold blue]🔍 Starting Trace Analysis[/bold blue]")
    console.print(f"[green]Blockchain:[/green] {currency.upper()}")
    console.print(f"[green]Address:[/green] {address}")
    console.print(f"[green]Max Hops:[/green] {max_hops}")
    console.print(f"[green]Depth:[/green] {depth}")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Task 1: Validate address
            task1 = progress.add_task("Validating address...", total=None)
            if not tracer.validate_address(address, currency):
                console.print(f"[red]❌ Invalid {currency} address: {address}[/red]")
                return
            progress.update(task1, completed=True)
            
            # Task 2: Trace transactions
            task2 = progress.add_task("Tracing transactions...", total=None)
            trace_result = tracer.trace_transactions(address, currency, max_hops, depth, verbose)
            progress.update(task2, completed=True)
            
            if not trace_result:
                console.print("[yellow]⚠️ No transactions found for this address.[/yellow]")
                return
            
            # Task 3: Threat intelligence analysis
            if threat_check:
                task3 = progress.add_task("Performing threat intelligence analysis...", total=None)
                threat_data = threat_intel.analyze_address(address, currency, trace_result)
                progress.update(task3, completed=True)
            
            # Task 4: Risk assessment
            if risk_assessment:
                task4 = progress.add_task("Assessing risk...", total=None)
                risk_data = risk_analyzer.assess_risk(address, currency, trace_result, threat_data if threat_check else None)
                progress.update(task4, completed=True)
            
            # Task 5: Generate visualization
            if visualize:
                task5 = progress.add_task("Generating visualization...", total=None)
                viz_data = visualizer.create_flow_diagram(trace_result, currency)
                progress.update(task5, completed=True)
        
        # Display results
        display_results(trace_result, threat_data if threat_check else None, 
                       risk_data if risk_assessment else None, output_format)
        
        # Generate report
        report_data = {
            "address": address,
            "currency": currency,
            "trace_result": trace_result,
            "threat_data": threat_data if threat_check else None,
            "risk_data": risk_data if risk_assessment else None,
            "timestamp": datetime.now().isoformat(),
            "analysis_parameters": {
                "max_hops": max_hops,
                "depth": depth,
                "threat_check": threat_check,
                "risk_assessment": risk_assessment
            }
        }
        
        # Export if requested
        if export:
            export_path = export_manager.export_results(report_data, output_format, address, currency)
            console.print(f"[green]📁 Results exported to: {export_path}[/green]")
        
        # Real-time monitoring
        if realtime:
            start_monitoring(address, currency, config)
            
    except Exception as e:
        console.print(f"[bold red]❌ Error during analysis: {str(e)}[/bold red]")
        logger.error(f"Trace error: {e}", exc_info=True)
        sys.exit(1)

@app.command()
def monitor(
    address: str = typer.Argument(..., help="Address to monitor"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain to monitor"),
    duration: int = typer.Option(3600, "--duration", "-d", help="Monitoring duration in seconds"),
    alert_threshold: float = typer.Option(1000.0, "--threshold", "-t", help="Alert threshold in USD"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for alerts")
):
    """
    🔄 Real-time transaction monitoring with alerting.
    
    Monitors addresses for new transactions and generates alerts
    based on configurable thresholds and threat intelligence.
    """
    console.print(CHAIN_ANALYZER_BANNER)
    
    config = config_manager.load_config()
    monitor = RealTimeMonitor(config)
    
    console.print(f"\n[bold blue]🔄 Starting Real-time Monitoring[/bold blue]")
    console.print(f"[green]Address:[/green] {address}")
    console.print(f"[green]Currency:[/green] {currency.upper()}")
    console.print(f"[green]Duration:[/green] {duration} seconds")
    console.print(f"[green]Alert Threshold:[/green] ${alert_threshold:,.2f}")
    
    try:
        monitor.start_monitoring(address, currency, duration, alert_threshold, output_file)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Monitoring stopped by user.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]❌ Monitoring error: {str(e)}[/bold red]")
        logger.error(f"Monitoring error: {e}", exc_info=True)

@app.command()
def threat_intel(
    address: str = typer.Argument(..., help="Address to analyze"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed threat information"),
    update_feeds: bool = typer.Option(False, "--update-feeds", help="Update threat intelligence feeds")
):
    """
    🛡️ Advanced threat intelligence analysis.
    
    Performs comprehensive threat intelligence analysis including:
    - Blacklist checking
    - Suspicious activity detection
    - Historical threat data
    - Risk scoring
    """
    console.print(CHAIN_ANALYZER_BANNER)
    
    config = config_manager.load_config()
    threat_intel = ThreatIntelligence(config)
    
    console.print(f"\n[bold blue]🛡️ Threat Intelligence Analysis[/bold blue]")
    console.print(f"[green]Address:[/green] {address}")
    console.print(f"[green]Currency:[/green] {currency.upper()}")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            if update_feeds:
                task1 = progress.add_task("Updating threat intelligence feeds...", total=None)
                threat_intel.update_feeds()
                progress.update(task1, completed=True)
            
            task2 = progress.add_task("Analyzing threat intelligence...", total=None)
            threat_data = threat_intel.comprehensive_analysis(address, currency, detailed)
            progress.update(task2, completed=True)
        
        display_threat_intel_results(threat_data, detailed)
        
    except Exception as e:
        console.print(f"[bold red]❌ Threat intelligence error: {str(e)}[/bold red]")
        logger.error(f"Threat intel error: {e}", exc_info=True)

@app.command()
def batch_analyze(
    file_path: str = typer.Argument(..., help="CSV file with addresses to analyze"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain"),
    output_format: str = typer.Option("csv", "--format", "-f", help="Output format: csv, json, xlsx"),
    max_concurrent: int = typer.Option(5, "--concurrent", help="Maximum concurrent analyses")
):
    """
    📊 Batch analysis of multiple addresses.
    
    Analyzes multiple addresses from a CSV file and generates
    comprehensive reports for SOC/DFIR teams.
    """
    console.print(CHAIN_ANALYZER_BANNER)
    
    config = config_manager.load_config()
    tracer = MultiChainTracer(config)
    threat_intel = ThreatIntelligence(config)
    risk_analyzer = RiskAnalyzer(config)
    export_manager = ExportManager()
    
    console.print(f"\n[bold blue]📊 Batch Analysis[/bold blue]")
    console.print(f"[green]Input File:[/green] {file_path}")
    console.print(f"[green]Currency:[/green] {currency.upper()}")
    console.print(f"[green]Max Concurrent:[/green] {max_concurrent}")
    
    try:
        results = batch_process_addresses(file_path, currency, max_concurrent, 
                                        tracer, threat_intel, risk_analyzer)
        
        # Export batch results
        output_path = export_manager.export_batch_results(results, output_format, currency)
        console.print(f"[green]📁 Batch results exported to: {output_path}[/green]")
        
    except Exception as e:
        console.print(f"[bold red]❌ Batch analysis error: {str(e)}[/bold red]")
        logger.error(f"Batch analysis error: {e}", exc_info=True)

@app.command()
def config(
    action: str = typer.Argument("show", help="Action: show, set, reset"),
    key: Optional[str] = typer.Argument(None, help="Configuration key"),
    value: Optional[str] = typer.Argument(None, help="Configuration value")
):
    """
    ⚙️ Configuration management.
    
    Manage ChainAnalyzer configuration including API keys,
    threat intelligence feeds, and analysis parameters.
    """
    console.print(CHAIN_ANALYZER_BANNER)
    
    if action == "show":
        config = config_manager.load_config()
        display_config(config)
    elif action == "set" and key and value:
        config_manager.set_config(key, value)
        console.print(f"[green]✅ Configuration updated: {key} = {value}[/green]")
    elif action == "reset":
        config_manager.reset_config()
        console.print("[green]✅ Configuration reset to defaults[/green]")
    else:
        console.print("[red]❌ Invalid configuration action[/red]")

def display_results(trace_result: Dict, threat_data: Optional[Dict], 
                   risk_data: Optional[Dict], output_format: str):
    """Display analysis results in the specified format."""
    
    if output_format == "json":
        results = {
            "trace_result": trace_result,
            "threat_data": threat_data,
            "risk_data": risk_data
        }
        console.print(json.dumps(results, indent=2))
        return
    
    # Create summary table
    table = Table(title="📊 Analysis Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    # Trace statistics
    if trace_result:
        table.add_row("Total Transactions", str(len(trace_result.get("transactions", []))))
        table.add_row("Unique Addresses", str(len(trace_result.get("addresses", []))))
        table.add_row("Total Volume", f"${trace_result.get('total_volume', 0):,.2f}")
    
    # Threat intelligence
    if threat_data:
        table.add_row("Threat Score", str(threat_data.get("threat_score", "N/A")))
        table.add_row("Blacklist Status", threat_data.get("blacklist_status", "Clean"))
        table.add_row("Suspicious Indicators", str(len(threat_data.get("suspicious_indicators", []))))
    
    # Risk assessment
    if risk_data:
        table.add_row("Risk Score", str(risk_data.get("risk_score", "N/A")))
        table.add_row("Risk Level", risk_data.get("risk_level", "Unknown"))
        table.add_row("Risk Factors", str(len(risk_data.get("risk_factors", []))))
    
    console.print(table)
    
    # Display alerts if any
    if threat_data and threat_data.get("alerts"):
        console.print("\n[bold red]⚠️ THREAT ALERTS[/bold red]")
        for alert in threat_data["alerts"]:
            console.print(f"[red]• {alert}[/red]")

def display_threat_intel_results(threat_data: Dict, detailed: bool):
    """Display threat intelligence analysis results."""
    
    # Main threat summary
    table = Table(title="🛡️ Threat Intelligence Summary")
    table.add_column("Indicator", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details", style="yellow")
    
    table.add_row("Overall Threat Score", str(threat_data.get("threat_score", "N/A")), 
                  threat_data.get("threat_level", "Unknown"))
    table.add_row("Blacklist Status", threat_data.get("blacklist_status", "Unknown"), 
                  str(len(threat_data.get("blacklists", []))))
    table.add_row("Suspicious Indicators", str(len(threat_data.get("suspicious_indicators", []))), 
                  "See details below")
    table.add_row("Historical Incidents", str(len(threat_data.get("historical_incidents", []))), 
                  "See details below")
    
    console.print(table)
    
    if detailed:
        # Detailed suspicious indicators
        if threat_data.get("suspicious_indicators"):
            console.print("\n[bold yellow]🔍 Suspicious Indicators[/bold yellow]")
            for indicator in threat_data["suspicious_indicators"]:
                console.print(f"[yellow]• {indicator}[/yellow]")
        
        # Historical incidents
        if threat_data.get("historical_incidents"):
            console.print("\n[bold red]📜 Historical Incidents[/bold red]")
            for incident in threat_data["historical_incidents"]:
                console.print(f"[red]• {incident}[/red]")

def display_config(config: Dict):
    """Display current configuration."""
    table = Table(title="⚙️ Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in config.items():
        if isinstance(value, dict):
            table.add_row(key, "Nested configuration")
        else:
            # Mask sensitive values
            if "key" in key.lower() or "secret" in key.lower():
                value = "*" * len(str(value))
            table.add_row(key, str(value))
    
    console.print(table)

def batch_process_addresses(file_path: str, currency: str, max_concurrent: int,
                          tracer: MultiChainTracer, threat_intel: ThreatIntelligence,
                          risk_analyzer: RiskAnalyzer) -> List[Dict]:
    """Process multiple addresses in batch."""
    import pandas as pd
    
    # Read addresses from CSV
    df = pd.read_csv(file_path)
    addresses = df['address'].tolist() if 'address' in df.columns else df.iloc[:, 0].tolist()
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("Processing addresses...", total=len(addresses))
        
        for address in addresses:
            try:
                # Trace transactions
                trace_result = tracer.trace_transactions(address, currency, 3, 2, False)
                
                # Threat intelligence
                threat_data = threat_intel.analyze_address(address, currency, trace_result)
                
                # Risk assessment
                risk_data = risk_analyzer.assess_risk(address, currency, trace_result, threat_data)
                
                results.append({
                    "address": address,
                    "trace_result": trace_result,
                    "threat_data": threat_data,
                    "risk_data": risk_data
                })
                
            except Exception as e:
                logger.error(f"Error processing {address}: {e}")
                results.append({
                    "address": address,
                    "error": str(e)
                })
            
            progress.advance(task)
    
    return results

def start_monitoring(address: str, currency: str, config: Dict):
    """Start real-time monitoring."""
    monitor = RealTimeMonitor(config)
    
    console.print(f"\n[bold blue]🔄 Starting Real-time Monitoring[/bold blue]")
    console.print(f"[green]Address:[/green] {address}")
    console.print(f"[green]Currency:[/green] {currency.upper()}")
    console.print("[yellow]Press Ctrl+C to stop monitoring[/yellow]\n")
    
    try:
        monitor.start_monitoring(address, currency, 3600, 1000.0)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Monitoring stopped.[/yellow]")

if __name__ == "__main__":
    app() 

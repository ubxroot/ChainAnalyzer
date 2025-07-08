#!/usr/bin/env python3
"""
ChainAnalyzer - Advanced Multi-Blockchain Transaction Forensics Tool
====================================================================

Professional-grade cryptocurrency transaction analysis tool designed for:
- Security Operations Centers (SOC)
- Digital Forensics and Incident Response (DFIR)
- Cyber Threat Intelligence teams

Features:
- Multi-blockchain support (Bitcoin, Ethereum, Solana, Tron, Polygon, BSC)
- Threat intelligence and risk scoring
- Real-time monitoring and alerting
- Rich CLI output and reporting
- Free APIs only - no paid subscriptions required
"""

import typer
import asyncio
import json
from pathlib import Path
from typing import Optional, List
from datetime import datetime
import sys

# Import core modules
from core.tracer import MultiChainTracer
from core.threat_intel import ThreatIntelligence
from core.risk_analyzer import RiskAnalyzer
from core.visualizer import Visualizer
from core.reporter import Reporter
from core.monitor import TransactionMonitor

# Import utility modules
from utils.config import ConfigManager
from utils.logger import ChainAnalyzerLogger
from utils.exporters import DataExporter
from utils.api_client import APIClient

# Rich imports for beautiful CLI
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.align import Align
import pyfiglet

# Initialize Typer app
app = typer.Typer(
    name="chain-analyzer",
    help="Advanced Multi-Blockchain Transaction Forensics Tool",
    add_completion=False
)

# Initialize Rich console
console = Console()

def print_banner():
    """Print ChainAnalyzer banner."""
    banner = pyfiglet.figlet_format("ChainAnalyzer", font="slant")
    console.print(Panel(banner, style="bold blue"))
    console.print("Advanced Multi-Blockchain Transaction Forensics Tool", style="bold green")
    console.print("Built for Security Operations Centers (SOC) & DFIR Teams", style="italic")
    console.print("🆓 FREE APIs Only - No Paid Subscriptions Required", style="bold yellow")
    console.print()

def load_config() -> dict:
    """Load configuration."""
    config_manager = ConfigManager()
    return config_manager.load_config()

def setup_logging(config: dict) -> ChainAnalyzerLogger:
    """Setup logging."""
    return ChainAnalyzerLogger(config)

@app.command()
def trace(
    address: str = typer.Argument(..., help="Blockchain address to trace"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain currency"),
    max_hops: int = typer.Option(5, "--max-hops", "-h", help="Maximum transaction hops"),
    depth: int = typer.Option(3, "--depth", "-d", help="Tracing depth"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format (table/json/csv)"),
    export: bool = typer.Option(False, "--export", "-e", help="Export results to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Trace transactions for a blockchain address."""
    
    print_banner()
    
    try:
        # Load configuration
        config = load_config()
        logger = setup_logging(config)
        
        console.print(f"🔍 Tracing {currency.upper()} address: {address}", style="bold blue")
        console.print(f"📊 Max hops: {max_hops}, Depth: {depth}", style="dim")
        console.print()
        
        # Initialize tracer
        tracer = MultiChainTracer(config)
        
        # Perform tracing
        start_time = datetime.now()
        result = tracer.trace_transactions(address, currency, max_hops, depth, verbose)
        end_time = datetime.now()
        
        if not result:
            console.print("❌ No transactions found or error occurred", style="bold red")
            return
        
        # Calculate analysis duration
        duration = (end_time - start_time).total_seconds()
        result["analysis_duration"] = duration
        
        # Display results
        display_trace_results(result, output_format, export, logger)
        
    except Exception as e:
        console.print(f"❌ Error during tracing: {e}", style="bold red")
        sys.exit(1)

@app.command()
def threat_intel(
    address: str = typer.Argument(..., help="Blockchain address to analyze"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain currency"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Detailed analysis"),
    update_feeds: bool = typer.Option(False, "--update-feeds", "-u", help="Update threat feeds"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format")
):
    """Analyze threat intelligence for a blockchain address."""
    
    print_banner()
    
    try:
        config = load_config()
        logger = setup_logging(config)
        
        console.print(f"🛡️ Threat Intelligence Analysis for {currency.upper()}: {address}", style="bold blue")
        console.print()
        
        # Initialize threat intelligence
        threat_intel = ThreatIntelligence(config)
        
        # Perform analysis
        async def analyze():
            async with threat_intel:
                if update_feeds:
                    console.print("🔄 Updating threat feeds...", style="yellow")
                    update_result = await threat_intel.update_threat_feeds()
                    console.print(f"✅ Updated {len(update_result['sources_updated'])} sources", style="green")
                
                result = await threat_intel.analyze_address(address, currency)
                return result
        
        result = asyncio.run(analyze())
        
        # Display results
        display_threat_intel_results(result, detailed, output_format)
        
    except Exception as e:
        console.print(f"❌ Error during threat intelligence analysis: {e}", style="bold red")
        sys.exit(1)

@app.command()
def monitor(
    address: str = typer.Argument(..., help="Blockchain address to monitor"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain currency"),
    duration: int = typer.Option(3600, "--duration", "-d", help="Monitoring duration in seconds"),
    threshold: float = typer.Option(1000, "--threshold", "-t", help="Alert threshold in USD"),
    output: str = typer.Option("", "--output", "-o", help="Output file for alerts")
):
    """Monitor blockchain address for new transactions."""
    
    print_banner()
    
    try:
        config = load_config()
        logger = setup_logging(config)
        
        console.print(f"👁️ Monitoring {currency.upper()}: {address}", style="bold blue")
        console.print(f"⏱️ Duration: {duration}s, Threshold: ${threshold:,.2f}", style="dim")
        console.print()
        
        # Initialize monitor
        monitor = TransactionMonitor(config)
        
        # Setup monitoring
        addresses = [{
            "address": address,
            "currency": currency,
            "thresholds": {
                "volume": threshold,
                "frequency": 10,
                "suspicious_patterns": True
            }
        }]
        
        # Start monitoring
        async def start_monitoring():
            async with monitor:
                result = await monitor.start_monitoring(addresses, duration)
                return result
        
        result = asyncio.run(start_monitoring())
        
        # Display monitoring results
        display_monitoring_results(result, output)
        
    except Exception as e:
        console.print(f"❌ Error during monitoring: {e}", style="bold red")
        sys.exit(1)

@app.command()
def batch_analyze(
    file_path: str = typer.Argument(..., help="CSV file with addresses to analyze"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain currency"),
    format: str = typer.Option("csv", "--format", "-f", help="Output format"),
    concurrent: int = typer.Option(5, "--concurrent", "-n", help="Number of concurrent analyses")
):
    """Batch analyze multiple addresses from a file."""
    
    print_banner()
    
    try:
        config = load_config()
        logger = setup_logging(config)
        
        console.print(f"📋 Batch Analysis: {file_path}", style="bold blue")
        console.print(f"🔗 Currency: {currency.upper()}, Concurrent: {concurrent}", style="dim")
        console.print()
        
        # Read addresses from file
        addresses = read_addresses_from_file(file_path)
        
        if not addresses:
            console.print("❌ No addresses found in file", style="bold red")
            return
        
        console.print(f"📊 Analyzing {len(addresses)} addresses...", style="yellow")
        
        # Perform batch analysis
        results = perform_batch_analysis(addresses, currency, concurrent, config)
        
        # Export results
        export_batch_results(results, format)
        
    except Exception as e:
        console.print(f"❌ Error during batch analysis: {e}", style="bold red")
        sys.exit(1)

@app.command()
def config(
    action: str = typer.Argument(..., help="Config action (show/set/reset)"),
    key: Optional[str] = typer.Argument(None, help="Config key (for set action)"),
    value: Optional[str] = typer.Argument(None, help="Config value (for set action)")
):
    """Manage ChainAnalyzer configuration."""
    
    print_banner()
    
    try:
        config_manager = ConfigManager()
        
        if action == "show":
            display_config(config_manager)
        elif action == "set":
            if not key or not value:
                console.print("❌ Key and value required for set action", style="bold red")
                return
            config_manager.set_config(key, value)
            console.print(f"✅ Configuration updated: {key} = {value}", style="green")
        elif action == "reset":
            config_manager.reset_config()
            console.print("✅ Configuration reset to defaults", style="green")
        else:
            console.print(f"❌ Unknown action: {action}", style="bold red")
    
    except Exception as e:
        console.print(f"❌ Error managing configuration: {e}", style="bold red")
        sys.exit(1)

def display_trace_results(result: dict, output_format: str, export: bool, logger: ChainAnalyzerLogger):
    """Display trace results in specified format."""
    
    if output_format == "table":
        # Create summary table
        table = Table(title="Transaction Trace Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Address", result["address"])
        table.add_row("Currency", result["currency"])
        table.add_row("Total Transactions", str(len(result["transactions"])))
        table.add_row("Connected Addresses", str(len(result["addresses"])))
        table.add_row("Total Volume USD", f"${result['total_volume']:,.2f}")
        table.add_row("Analysis Duration", f"{result['analysis_duration']:.2f}s")
        table.add_row("Trace Depth", str(result["trace_depth"]))
        table.add_row("Max Hops", str(result["max_hops"]))
        
        console.print(table)
        
        # Display suspicious patterns if any
        if result.get("suspicious_patterns"):
            console.print("\n🚨 Suspicious Patterns Detected:", style="bold red")
            for pattern in result["suspicious_patterns"]:
                console.print(f"  • {pattern}", style="red")
        
        # Display relationships if any
        if result.get("relationships", {}).get("address_connections"):
            console.print(f"\n🔗 Address Relationships: {len(result['relationships']['address_connections'])} connections")
    
    elif output_format == "json":
        console.print(json.dumps(result, indent=2, default=str))
    
    elif output_format == "csv":
        # Export to CSV
        exporter = DataExporter(load_config())
        filepath = exporter.export_data(result, "csv")
        console.print(f"📁 Results exported to: {filepath}", style="green")
    
    # Export if requested
    if export:
        exporter = DataExporter(load_config())
        filepath = exporter.export_data(result, output_format)
        console.print(f"📁 Results exported to: {filepath}", style="green")

def display_threat_intel_results(result: dict, detailed: bool, output_format: str):
    """Display threat intelligence results."""
    
    if output_format == "table":
        # Create threat intelligence table
        table = Table(title="Threat Intelligence Analysis")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Address", result["address"])
        table.add_row("Currency", result["currency"])
        table.add_row("Threat Score", f"{result['threat_score']:.2f}")
        table.add_row("Risk Level", result["risk_level"].upper())
        table.add_row("Blacklist Status", result["blacklist_status"])
        table.add_row("Suspicious Patterns", str(len(result["suspicious_patterns"])))
        
        console.print(table)
        
        # Display detailed information if requested
        if detailed:
            if result["blacklist_matches"]:
                console.print("\n🚨 Blacklist Matches:", style="bold red")
                for match in result["blacklist_matches"]:
                    console.print(f"  • {match['source']}: {match['type']} - {match['details']}", style="red")
            
            if result["suspicious_patterns"]:
                console.print("\n⚠️ Suspicious Patterns:", style="bold yellow")
                for pattern in result["suspicious_patterns"]:
                    console.print(f"  • {pattern}", style="yellow")
            
            if result["recommendations"]:
                console.print("\n💡 Recommendations:", style="bold green")
                for rec in result["recommendations"]:
                    console.print(f"  • {rec}", style="green")
    
    elif output_format == "json":
        console.print(json.dumps(result, indent=2, default=str))

def display_monitoring_results(result: dict, output_file: str):
    """Display monitoring results."""
    
    table = Table(title="Monitoring Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Status", result["status"])
    table.add_row("Monitored Addresses", str(result["monitored_addresses"]))
    table.add_row("Total Alerts", str(result["total_alerts"]))
    
    console.print(table)
    
    # Display address summaries
    if result.get("address_summaries"):
        console.print("\n📊 Address Summaries:", style="bold blue")
        for address, summary in result["address_summaries"].items():
            console.print(f"  {address}: {summary['transaction_count']} txs, ${summary['total_volume']:,.2f}, {summary['alert_count']} alerts")
    
    # Export to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        console.print(f"📁 Monitoring results exported to: {output_file}", style="green")

def display_config(config_manager: ConfigManager):
    """Display current configuration."""
    
    config = config_manager.load_config()
    summary = config_manager.get_config_summary()
    
    table = Table(title="ChainAnalyzer Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Enabled Blockchains", ", ".join(summary["enabled_blockchains"]))
    table.add_row("Free APIs Enabled", str(summary["free_apis_enabled"]))
    table.add_row("Monitoring Enabled", str(summary["monitoring_enabled"]))
    table.add_row("Threat Intelligence", str(summary["threat_intelligence_enabled"]))
    table.add_row("Log Level", summary["log_level"])
    
    console.print(table)

def read_addresses_from_file(file_path: str) -> List[str]:
    """Read addresses from CSV file."""
    
    addresses = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                address = line.strip()
                if address and not address.startswith('#'):
                    addresses.append(address)
    except Exception as e:
        console.print(f"❌ Error reading file: {e}", style="bold red")
    
    return addresses

def perform_batch_analysis(addresses: List[str], currency: str, concurrent: int, config: dict) -> List[dict]:
    """Perform batch analysis of addresses."""
    
    results = []
    
    # This would implement concurrent analysis
    # For now, just return empty results
    console.print("⚠️ Batch analysis not yet implemented", style="yellow")
    
    return results

def export_batch_results(results: List[dict], format: str):
    """Export batch analysis results."""
    
    if not results:
        console.print("❌ No results to export", style="bold red")
        return
    
    try:
        exporter = DataExporter(load_config())
        filepath = exporter.batch_export(results, format)
        console.print(f"📁 Batch results exported: {len(filepath)} files", style="green")
    except Exception as e:
        console.print(f"❌ Error exporting batch results: {e}", style="bold red")

@app.callback()
def main():
    """ChainAnalyzer - Advanced Multi-Blockchain Transaction Forensics Tool."""
    pass

if __name__ == "__main__":
    app()

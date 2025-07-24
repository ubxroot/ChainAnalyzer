#!/usr/bin/env python3
"""
ChainAnalyzer - Simplified Version for Testing
"""

import typer
import asyncio
from rich.console import Console
from rich.panel import Panel
import pyfiglet

# Import only the modules we've created
from core.advanced_tracer import AdvancedMultiChainTracer
from utils.enhanced_config import EnhancedConfigManager

console = Console()
app = typer.Typer(name="chainanalyzer-simple", help="Simplified ChainAnalyzer")

def print_banner():
    """Print simple banner."""
    banner = pyfiglet.figlet_format("ChainAnalyzer", font="slant")
    console.print(Panel(banner, style="bold blue"))
    console.print("Simplified Multi-Blockchain Transaction Forensics Tool", style="bold green")
    console.print()

@app.command()
def trace(
    address: str = typer.Argument(..., help="Blockchain address to trace"),
    currency: str = typer.Option("ethereum", "--currency", "-c", help="Blockchain currency"),
    max_hops: int = typer.Option(5, "--max-hops", "-h", help="Maximum transaction hops"),
    depth: int = typer.Option(3, "--depth", "-d", help="Tracing depth")
):
    """Simple trace command."""
    
    print_banner()
    
    try:
        config = EnhancedConfigManager().load_config()
        
        console.print(f"🔍 Tracing {currency.upper()} address: {address}", style="bold blue")
        console.print(f"📊 Max hops: {max_hops}, Depth: {depth}", style="dim")
        console.print()
        
        # Initialize tracer
        tracer = AdvancedMultiChainTracer(config, None, None)
        
        # Perform simple trace
        result = asyncio.run(tracer.advanced_trace(address, currency, max_hops, depth))
        
        # Display simple results
        console.print("✅ [bold green]Analysis Complete[/]")
        console.print(f"📊 Total Transactions: {result['total_transactions']}")
        console.print(f"💰 Total Value: {result['total_value']}")
        console.print(f"🔗 Currency: {result['currency']}")
        
    except Exception as e:
        console.print(f"❌ [bold red]Error:[/] {str(e)}")

if __name__ == "__main__":
    app()

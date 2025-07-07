#!/usr/bin/env python3
# This script is designed to be run directly on Kali Linux.
# Ensure all required packages (typer, rich, requests, pyfiglet) are installed globally:
# sudo pip install typer rich requests pyfiglet

import typer
import json
from rich import print
from rich.console import Console # Import Console for use with trace_crypto and general output
from rich.text import Text # <--- ADDED: Import Text class from rich
import sys # For clean exit

# Import core and utils modules
from core.tracer import trace_crypto
from core.visualizer import visualize_flow
from utils.logger import setup_logger
from utils.config import load_config
from utils.risk import assess_risk
from utils.alerting import check_alerts

# Initialize Typer app and Rich console
app = typer.Typer(help="🕵️ ChainAnalyzer - Advanced Multi-Blockchain Transaction Tracer")
console = Console() # Initialize console for consistent rich output

# --- ASCII Banner (Re-added for direct execution) ---
import pyfiglet # Ensure pyfiglet is imported for the banner
CHAIN_ANALYZER_BANNER = Text()
CHAIN_ANALYZER_BANNER.append(pyfiglet.figlet_format("ChainAnalyzer", font="standard"), style="bold blue")
CHAIN_ANALYZER_BANNER.append("\n")
CHAIN_ANALYZER_BANNER.append("Advanced Cryptocurrency Transaction Analysis\n", style="bright_cyan")
CHAIN_ANALYZER_BANNER.append("github.com/ubxroot/ChainAnalyzer (Placeholder)\n", style="dim white")


@app.command()
def trace(
    currency: str = typer.Option(..., help="Currency (e.g., bitcoin, ethereum, solana, tron)"),
    address: str = typer.Argument(..., help="Wallet address to trace"),
    max_hops: int = typer.Option(5, help="Maximum number of transaction hops to trace"),
    realtime: bool = typer.Option(False, help="Enable real-time monitoring mode (currently not implemented)"),
    output_format: str = typer.Option("human", help="Output format: human or json"),
    visualize: bool = typer.Option(True, help="Visualize transaction flow graph (basic visualization)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose output including raw transaction details.")
):
    """
    Comprehensive address tracing and analysis across multiple blockchains.
    """
    console.print(CHAIN_ANALYZER_BANNER) # Display banner at the start of the command
    
    logger = setup_logger()
    config = load_config()

    print(f"\n[bold blue]ChainAnalyzer:[/bold blue] Tracing [green]{currency.upper()}[/green] address: [yellow]{address}[/yellow]\n")
    logger.info(f"Starting trace for {currency.upper()} address: {address} with max_hops={max_hops}")

    try:
        # Pass console object to tracer for consistent logging
        result = trace_crypto(address, currency, verbose, max_hops, console)
        
        if not result:
            print("[yellow]No transactions found for this address or tracing depth.[/yellow]")
            logger.warning(f"No transactions found for {address}")
            return

        risk_report = assess_risk(result, config)
        alerts = check_alerts(risk_report, config)

        output = {
            "address": address,
            "currency": currency,
            "trace_result": result,
            "risk_score": risk_report.get("score"),
            "alerts": alerts,
        }

        if visualize:
            visualize_flow(result, console) # Pass console to visualizer

        if output_format == "json":
            print(json.dumps(output, indent=2))
        else:
            print("\n[bold green]✅ Trace Complete[/bold green]")
            print(f"[bold]Risk Score:[/bold] {risk_report.get('score', 'N/A')}")
            if alerts:
                print(f"[red]⚠️ Alerts:[/red] {alerts}")
            else:
                print("[green]No alerts detected.[/green]")

    except Exception as e:
        print(f"[bold red]❌ An unexpected error occurred during tracing: {escape(str(e))}[/bold red]")
        logger.error(f"Error during trace: {e}", exc_info=True)
        sys.exit(1) # Use sys.exit for clean exit in direct execution

# --- Banner Function ---
def show_banner():
    """Displays a stylized banner for the ChainAnalyzer tool."""
    banner = pyfiglet.figlet_format("UBXROOT", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]ChainAnalyzer – Blue Team ChainAnalyzer v1.0[/bright_yellow]\n")
# --- Entry point for the command-line application ---
if __name__ == "__main__":
    show_banner() # Display the banner when the script starts
    app()

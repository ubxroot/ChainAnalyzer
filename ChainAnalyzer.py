#!/usr/bin/env python3

import typer
from rich import print
from core.tracer import trace_crypto
from utils.logger import setup_logger
from utils.config import load_blacklist

app = typer.Typer(help="🔍 ChainAnalyzer - Crypto Transaction Tracer for Forensics")

ASCII_BANNER = r"""
[bold red]
██    ██ ██████  ██   ██ ██████  ██████  ██████  ████████
██    ██ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██    ██   
██    ██ ██████  ███████ ██████  ██████  ██   ██    ██   
██    ██ ██      ██   ██ ██   ██ ██   ██ ██   ██    ██   
 ██████  ██      ██   ██ ██████  ██████  ██████     ██    [bold white]ubxroot[/bold white]
[/bold red]
"""

@app.command()
def trace(
    currency: str = typer.Option(..., help="Currency to trace: bitcoin or ethereum"),
    address: str = typer.Argument(..., help="Wallet address to trace"),
    max_hops: int = typer.Option(3, help="Maximum number of transaction hops to trace"),
):
    """
    Trace the transaction flow for a given crypto address.
    """
    print(ASCII_BANNER)
    logger = setup_logger()
    print(f"\n[bold blue]ChainAnalyzer:[/bold blue] Tracing [green]{currency.upper()}[/green] address: [yellow]{address}[/yellow]\n")

    if currency.lower() not in ["bitcoin", "ethereum"]:
        print("[red]❌ Unsupported currency. Please use 'bitcoin' or 'ethereum'.[/red]")
        raise typer.Exit()

    try:
        blacklist = load_blacklist()
        result = trace_crypto(currency, address, max_hops, blacklist, logger)
        print("\n[bold green]✅ Trace Complete[/bold green]")
        print(f"\n[bold]Risk Score:[/bold] {result.get('risk_score', 'N/A')}")
        print(f"[bold]Hops Traced:[/bold] {result.get('hops', 'N/A')}")
    except Exception as e:
        print(f"[red]⚠️ Error:[/red] {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    print(ASCII_BANNER)
    app()

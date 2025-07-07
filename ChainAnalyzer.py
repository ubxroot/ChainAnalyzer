#!/usr/bin/env python3

import typer
import json
from rich import print
from core.tracer import trace_crypto
from utils.logger import setup_logger
from utils.config import load_blacklist

app = typer.Typer(help="🔍 ChainAnalyzer - Crypto Transaction Tracer for Forensics")

@app.command()
def trace(
    currency: str = typer.Option(..., help="Currency to trace: bitcoin or ethereum"),
    address: str = typer.Argument(..., help="Wallet address to trace"),
    max_hops: int = typer.Option(3, help="Maximum number of transaction hops to trace"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    output_format: str = typer.Option("human", "--output", "-o", help="Output format: human or json")
):
    """
    Trace the transaction flow for a given crypto address.
    """
    logger = setup_logger(verbose)
    logger.info(f"Trace started for {currency} address: {address} | Max hops: {max_hops}")

    print(f"\n[bold blue]ChainAnalyzer:[/bold blue] Tracing [green]{currency.upper()}[/green] address: [yellow]{address}[/yellow]\n")

    if currency.lower() not in ["bitcoin", "ethereum"]:
        print("[red]❌ Unsupported currency. Please use 'bitcoin' or 'ethereum'.[/red]")
        logger.error("Unsupported currency input.")
        raise typer.Exit()

    try:
        blacklist = load_blacklist()
        result = trace_crypto(currency, address, max_hops, blacklist, logger)

        logger.info("Trace completed successfully.")

        if output_format.lower() == "json":
            print(json.dumps(result, indent=2))
        else:
            print("\n[bold green]✅ Trace Complete[/bold green]")
            print(f"\n[bold]Risk Score:[/bold] {result.get('risk_score', 'N/A')}")
            print(f"[bold]Hops Traced:[/bold] {result.get('hops', 'N/A')}")
            metadata = result.get("metadata")
            if metadata:
                print(f"[bold]Additional Info:[/bold] {metadata}")

    except Exception as e:
        print(f"[red]⚠️ Error:[/red] {e}")
        logger.exception("An error occurred during tracing.")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()

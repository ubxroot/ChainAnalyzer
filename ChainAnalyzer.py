# ChainAnalyzer Main Entry Point (GitHub-ready)
# Language: Python (primary), with hooks to external graphing/AI modules (multi-language capable)

import typer
import json
from rich import print
from core.tracer import trace_crypto
from core.visualizer import visualize_flow
from utils.logger import setup_logger
from utils.config import load_config
from utils.risk import assess_risk
from utils.alerting import check_alerts

app = typer.Typer(help="\U0001F50D ChainAnalyzer - Advanced Multi-Blockchain Transaction Tracer")

@app.command()
def trace(
    currency: str = typer.Option(..., help="Currency (e.g., bitcoin, ethereum, solana, tron)"),
    address: str = typer.Argument(..., help="Wallet address to trace"),
    max_hops: int = typer.Option(5, help="Maximum number of transaction hops to trace"),
    realtime: bool = typer.Option(False, help="Enable real-time monitoring mode"),
    output_format: str = typer.Option("human", help="Output format: human or json"),
    visualize: bool = typer.Option(True, help="Visualize transaction flow graph")
):
    """
    Comprehensive address tracing and analysis across multiple blockchains.
    """
    logger = setup_logger()
    config = load_config()

    print(f"\n[bold blue]ChainAnalyzer:[/bold blue] Tracing [green]{currency.upper()}[/green] address: [yellow]{address}[/yellow]\n")

    result = trace_crypto(currency, address, max_hops, logger, config)
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
        visualize_flow(result)

    if output_format == "json":
        print(json.dumps(output, indent=2))
    else:
        print("\n[bold green]\u2705 Trace Complete[/bold green]")
        print(f"[bold]Risk Score:[/bold] {risk_report.get('score')}")
        if alerts:
            print(f"[red]\u26a0\ufe0f Alerts:[/red] {alerts}")

if __name__ == "__main__":
    app()

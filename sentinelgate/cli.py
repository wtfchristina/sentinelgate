import argparse
import asyncio
from pathlib import Path
import sys
import httpx
from rich.console import Console
from rich.table import Table

from sentinelgate.scanner import extract_ast_imports, extract_from_requirements
from sentinelgate.provenance import fetch_pypi_metadata
from sentinelgate.policy import PolicyEngine
from sentinelgate.interceptor import audit_and_forward

console = Console()

async def run_scan(packages: set[str], threshold: float) -> int:
    policy = PolicyEngine(max_risk_threshold=threshold)
    
    table = Table(title="SentinelGate Pre-Execution Dependency Audit")
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Age (Days)", justify="right")
    table.add_column("Risk Score", justify="right")
    table.add_column("Flags / Reasons", style="yellow")

    exit_code = 0

    async with httpx.AsyncClient() as client:
        tasks = [fetch_pypi_metadata(client, pkg) for pkg in sorted(packages)]
        provenance_results = await asyncio.gather(*tasks)

    for prov in provenance_results:
        res = policy.evaluate(prov)
        if not res.allowed:
            exit_code = 1
            status_style = "[red]BLOCKED[/red]"
        else:
            status_style = "[green]ALLOWED[/green]"

        table.add_row(
            prov.name,
            status_style,
            str(prov.age_days) if prov.exists else "N/A",
            f"{prov.risk_score:.2f}",
            ", ".join(prov.flags) if prov.flags else "None",
        )

    console.print(table)
    return exit_code

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        # Interceptor mode
        exit_code = asyncio.run(audit_and_forward(sys.argv[2:]))
        sys.exit(exit_code)

    parser = argparse.ArgumentParser(
        prog="sentinelgate",
        description="Pre-execution firewall intercepting hallucinated and slopsquatted packages."
    )
    parser.add_argument("--file", "-f", type=Path, help="Path to requirements.txt, pyproject.toml, or .py source.")
    parser.add_argument("--package", "-p", action="append", default=[], help="Package name(s) to scan directly.")
    parser.add_argument("--threshold", "-t", type=float, default=0.45, help="Risk threshold (0.0 to 1.0). Default: 0.45")

    args = parser.parse_args()
    targets: set[str] = set(args.package)

    if args.file and args.file.is_file():
        if args.file.suffix == ".py":
            targets.update(extract_ast_imports(args.file))
        elif "requirements" in args.file.name:
            targets.update(extract_from_requirements(args.file))

    if not targets:
        console.print("[yellow]No packages discovered or specified. Exiting cleanly.[/yellow]")
        sys.exit(0)

    code = asyncio.run(run_scan(targets, args.threshold))
    sys.exit(code)

if __name__ == "__main__":
    main()

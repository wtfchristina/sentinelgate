import subprocess
import sys
from pathlib import Path
import asyncio
import httpx

from sentinelgate.scanner import extract_from_requirements
from sentinelgate.provenance import fetch_pypi_metadata
from sentinelgate.policy import PolicyEngine
from rich.console import Console

console = Console()

def parse_pip_args(args: list[str]) -> tuple[set[str], list[str]]:
    """Extract raw package names or requirement files from pip arguments."""
    packages = set()
    forward_args = []
    skip_next = False

    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue

        if arg in ("-r", "--requirement"):
            if i + 1 < len(args):
                req_path = Path(args[i + 1])
                packages.update(extract_from_requirements(req_path))
                skip_next = True
            forward_args.append(arg)
        elif arg.startswith("-"):
            forward_args.append(arg)
        else:
            # Clean version specifiers like httpx>=0.27
            import re
            clean_pkg = re.split(r"[><=~!;]", arg)[0].strip()
            if clean_pkg:
                packages.add(clean_pkg.lower())
            forward_args.append(arg)

    return packages, forward_args

async def audit_and_forward(pip_args: list[str], threshold: float = 0.45) -> int:
    packages, forward_args = parse_pip_args(pip_args)
    if not packages:
        return subprocess.run([sys.executable, "-m", "pip", "install"] + forward_args).returncode

    console.print(f"[bold cyan]SentinelGate: Auditing {len(packages)} incoming target(s)...[/bold cyan]")
    policy = PolicyEngine(max_risk_threshold=threshold)
    
    async with httpx.AsyncClient() as client:
        tasks = [fetch_pypi_metadata(client, pkg) for pkg in sorted(packages)]
        results = await asyncio.gather(*tasks)

    blocked = []
    for prov in results:
        res = policy.evaluate(prov)
        if not res.allowed:
            blocked.append(prov)

    if blocked:
        console.print(f"\n[bold red]✖ FIREWALL INTERCEPTED {len(blocked)} SUSPICIOUS/HALLUCINATED PACKAGE(S):[/bold red]")
        for b in blocked:
            console.print(f"  • [red]{b.name}[/red] (Risk: {b.risk_score:.2f}) -> {', '.join(b.flags)}")
        console.print("\n[yellow]pip execution aborted. No packages were installed.[/yellow]\n")
        return 1

    console.print("[green]✔ Provenance checks passed. Executing pip install...[/green]\n")
    return subprocess.run([sys.executable, "-m", "pip", "install"] + forward_args).returncode

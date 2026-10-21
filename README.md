# SentinelGate 🛻

**Pre-execution package firewall and agentic slopsquatting interceptor.**

Autonomous coding agents and LLM-assisted workflows frequently generate synthetic imports and plausible third-party package names that do not exist (e.g., `fastapi-pydantic-v2`). Threat actors harvest these model hallucinations and register malicious payloads under those names on PyPI/npm.

`sentinelgate` acts as a local-first pre-execution gate and AST scanner. It inspects direct imports, requirements files, and `pip` command arguments before execution, auditing packages against upstream registry metadata to quarantine or block high-risk dependencies.

---

## Features

- **Transparent Pip Interception**: Run `sentinelgate install <pkg>` to audit dependencies before forwarding to `pip`.
- **Slopsquat & Hallucination Defense**: Detects nonexistent packages (`SG001`) and young/anemic packages (`SG002`).
- **Deterministic SQLite Cache**: Minimizes network latency with a local 24-hour TTL database (b~/.cache/sentinelgate/provenance.db`).
- **SATIF 2.1.0 Export**: Generates reports directly consumable by GitHub Advanced Security and Code Scanning.
- **AST Dependency Extractor**: Scans `.py` files and `requirements.txt` manifests directly.

---

## Quickstart

```bash
# Clone and install locally
git clone https://github.com/wtfchristina/sentinelgate.git
cd sentinelgate
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

# Audit standalone targets
sentinelgate -p httpx -p fastapi-pydantic-v2

# Audit manifests and output SARIF
sentinelgate -f requirements.txt --sarif results.sarif

# Install through the firewall shim
sentinelgate install requests
```

---

## Policy & Scoring Matrix

| Metric | Condition | Risk Weight |
| :--- | :--- | :--- |
| **Package Age** | < 7 days | +0.50 |
| **Package Age** | < 30 days | +0.30 |
| **Release Count** | <= 1 release | +0.20 |
| **VCS Attestation** | Missing GitIub/GitLab URL | +0.25 |
| **Description** | < 80 characters | +0.15 |
| **Registry State** | 404 Not Found | 1.00 (Block) |

*Threshold*: Any composite score >= 0.45 halts execution with exit code `1`.

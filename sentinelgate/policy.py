from dataclasses import dataclass
from sentinelgate.provenance import PackageProvenance

@dataclass
class PolicyResult:
    allowed: bool
    verdict: str
    provenance: PackageProvenance

class PolicyEngine:
    def __init__(self, max_risk_threshold: float = 0.45):
        self.max_risk_threshold = max_risk_threshold

    def evaluate(self, prov: PackageProvenance) -> PolicyResult:
        if not prov.exists:
            return PolicyResult(
                allowed=False,
                verdict="BLOCK_NONEXISTENT_OR_HALLUCINATED",
                provenance=prov,
            )

        if prov.risk_score >= self.max_risk_threshold:
            return PolicyResult(
                allowed=False,
                verdict="QUARANTINE_SUSPECT_SLOPSQUAT",
                provenance=prov,
            )

        return PolicyResult(
            allowed=True,
            verdict="PASS",
            provenance=prov,
        )

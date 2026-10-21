from pathlib import Path
from sentinelgate.scanner import extract_ast_imports, extract_from_requirements
from sentinelgate.provenance import PackageProvenance
from sentinelgate.policy import PolicyEngine

def test_ast_import_extraction(tmp_path: Path):
    sample_file = tmp_path / "app.py"
    sample_file.write_text(
        "import os\n"
        "import httpx\n"
        "from fastapi_pydantic_v2 import fake_helper\n"
    )
    imports = extract_ast_imports(sample_file)
    assert "os" not in imports
    assert "httpx" in imports
    assert "fastapi_pydantic_v2" in imports

def test_requirements_extraction(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests>=2.28.0\n# comment\nfake-package==0.0.1\n")
    pkgs = extract_from_requirements(req_file)
    assert "requests" in pkgs
    assert "fake-package" in pkgs

def test_policy_thresholds():
    policy = PolicyEngine(max_risk_threshold=0.45)
    safe = PackageProvenance(name="httpx", exists=True, risk_score=0.10)
    assert policy.evaluate(safe).allowed is True

    unsafe = PackageProvenance(name="sketchy-pkg", exists=True, risk_score=0.70)
    assert policy.evaluate(unsafe).allowed is False

    missing = PackageProvenance(name="hallucinated-lib", exists=False)
    assert policy.evaluate(missing).allowed is False

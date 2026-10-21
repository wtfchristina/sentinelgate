from dataclasses import dataclass, field
from datetime import datetime, timezone
import httpx

PYPI_URL = "https://pypi.org/pypi/{pkg}/json"

@dataclass
class PackageProvenance:
    name: str
    exists: bool
    age_days: float = 0.0
    version_count: int = 0
    has_project_urls: bool = False
    has_source_repo: bool = False
    latest_release_age_days: float = 0.0
    risk_score: float = 0.0
    flags: list[str] = field(default_factory=list)

async def fetch_pypi_metadata(client: httpx.AsyncClient, package_name: str) -> PackageProvenance:
    url = PYPI_URL.format(pkg=package_name)
    now = datetime.now(timezone.utc)

    try:
        resp = await client.get(url, timeout=6.0)
    except httpx.RequestError:
        return PackageProvenance(
            name=package_name,
            exists=False,
            risk_score=1.0,
            flags=["REGISTRY_CONNECTION_TIMEOUT"]
        )

    if resp.status_code == 404:
        return PackageProvenance(
            name=package_name,
            exists=False,
            risk_score=1.0,
            flags=["UNREGISTERED_POTENTIAL_HALLUCINATION"]
        )

    if resp.status_code != 200:
        return PackageProvenance(
            name=package_name,
            exists=False,
            risk_score=0.9,
            flags=[f"REGISTRY_HTTP_{resp.status_code}"]
        )

    data = resp.json()
    info = data.get("info", {})
    releases = data.get("releases", {})

    upload_times: list[datetime] = []
    for rel_files in releases.values():
        for f in rel_files:
            upload_str = f.get("upload_time_iso_8601")
            if upload_str:
                try:
                    dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                    upload_times.append(dt)
                except ValueError:
                    pass

    if upload_times:
        upload_times.sort()
        package_age_days = (now - upload_times[0]).total_seconds() / 86400.0
        latest_release_age_days = (now - upload_times[-1]).total_seconds() / 86400.0
    else:
        package_age_days = 0.0
        latest_release_age_days = 0.0

    project_urls = info.get("project_urls") or {}
    has_urls = len(project_urls) > 0
    has_repo = any(
        "github.com" in str(v).lower() or "gitlab.com" in str(v).lower()
        for v in project_urls.values()
    )

    flags = []
    risk = 0.0

    if package_age_days < 7.0:
        risk += 0.50
        flags.append(f"PACKAGE_AGE_CRITICAL ({package_age_days:.1f} days old)")
    elif package_age_days < 30.0:
        risk += 0.30
        flags.append(f"PACKAGE_AGE_ELEVATED ({package_age_days:.1f} days old)")

    version_count = len(releases)
    if version_count <= 1:
        risk += 0.20
        flags.append("SINGLE_VERSION_RELEASE")

    if not has_repo:
        risk += 0.25
        flags.append("NO_PUBLIC_VCS_ATTESTATION")

    desc = info.get("description", "") or ""
    if len(desc.strip()) < 80:
        risk += 0.15
        flags.append("ANEMIC_METADATA_DESCRIPTION")

    normalized_risk = min(1.0, round(risk, 2))

    return PackageProvenance(
        name=package_name,
        exists=True,
        age_days=round(package_age_days, 1),
        version_count=version_count,
        has_project_urls=has_urls,
        has_source_repo=has_repo,
        latest_release_age_days=round(latest_release_age_days, 1),
        risk_score=normalized_risk,
        flags=flags,
    )

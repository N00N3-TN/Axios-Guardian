"""Core scanning engine for Axios Guardian."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class VulnerableAxios:
    file: str
    version: str
    severity: str = "CRITICAL"

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "version": self.version, "severity": self.severity}


@dataclass
class MaliciousPackage:
    package: str
    version: str
    file: str
    severity: str = "CRITICAL"
    type: str = "malicious_dependency"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "file": self.file,
            "severity": self.severity,
            "type": self.type,
        }


@dataclass
class SuspiciousFile:
    path: str
    pattern: str
    severity: str = "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "pattern": self.pattern, "severity": self.severity}


@dataclass
class ScanResult:
    scan_path: str
    vulnerable_axios: list[VulnerableAxios] = field(default_factory=list)
    malicious_packages: list[MaliciousPackage] = field(default_factory=list)
    suspicious_files: list[SuspiciousFile] = field(default_factory=list)
    projects_scanned: int = 0

    @property
    def threats_found(self) -> bool:
        return bool(self.vulnerable_axios or self.malicious_packages or self.suspicious_files)

    @property
    def threat_level(self) -> str:
        if self.vulnerable_axios or self.malicious_packages:
            return "CRITICAL"
        if self.suspicious_files:
            return "HIGH"
        return "CLEAN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_path": self.scan_path,
            "threats_found": self.threats_found,
            "vulnerable_axios": [v.to_dict() for v in self.vulnerable_axios],
            "malicious_packages": [m.to_dict() for m in self.malicious_packages],
            "suspicious_files": [s.to_dict() for s in self.suspicious_files],
            "summary": {
                "projects_scanned": self.projects_scanned,
                "threat_level": self.threat_level,
            },
        }


def _load_blocklist() -> dict[str, Any]:
    """Load blocklist.json bundled with the package."""
    blocklist_path = Path(__file__).parent / "blocklist.json"
    with blocklist_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _parse_version(version_str: str) -> str:
    """Strip semver range prefixes (^, ~, >=, etc.) and return bare version."""
    return re.sub(r"^[\^~>=<*]+", "", version_str).strip()


def _scan_package_json(
    pkg_path: Path,
    vulnerable_versions: list[str],
    malicious_pkgs: list[str],
    verbose: bool = False,
) -> tuple[list[VulnerableAxios], list[MaliciousPackage]]:
    """Scan a single package.json for threats."""
    vuln_axios: list[VulnerableAxios] = []
    mal_pkgs: list[MaliciousPackage] = []

    try:
        with pkg_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        if verbose:
            print(f"  [warn] Could not parse {pkg_path}: {exc}")
        return vuln_axios, mal_pkgs

    all_deps: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        all_deps.update(data.get(section, {}))

    for pkg_name, version_range in all_deps.items():
        bare = _parse_version(str(version_range))

        if pkg_name == "axios" and bare in vulnerable_versions:
            vuln_axios.append(VulnerableAxios(file=str(pkg_path), version=bare))

        if pkg_name in malicious_pkgs:
            mal_pkgs.append(
                MaliciousPackage(package=pkg_name, version=bare, file=str(pkg_path))
            )

    return vuln_axios, mal_pkgs


def _scan_lockfile(
    lock_path: Path,
    vulnerable_versions: list[str],
    verbose: bool = False,
) -> list[VulnerableAxios]:
    """Scan package-lock.json or yarn.lock for vulnerable axios versions."""
    vuln_axios: list[VulnerableAxios] = []

    try:
        content = lock_path.read_text(encoding="utf-8")
    except OSError as exc:
        if verbose:
            print(f"  [warn] Could not read {lock_path}: {exc}")
        return vuln_axios

    # package-lock.json (JSON)
    if lock_path.name == "package-lock.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return vuln_axios

        # v2/v3 lockfile: packages key
        packages = data.get("packages", {})
        for pkg_key, pkg_data in packages.items():
            if "axios" in pkg_key and isinstance(pkg_data, dict):
                ver = _parse_version(pkg_data.get("version", ""))
                if ver in vulnerable_versions:
                    vuln_axios.append(VulnerableAxios(file=str(lock_path), version=ver))

        # v1 lockfile: dependencies key
        dependencies = data.get("dependencies", {})
        for pkg_name, pkg_data in dependencies.items():
            if pkg_name == "axios" and isinstance(pkg_data, dict):
                ver = _parse_version(pkg_data.get("version", ""))
                if ver in vulnerable_versions:
                    vuln_axios.append(VulnerableAxios(file=str(lock_path), version=ver))

    # yarn.lock (custom format)
    elif lock_path.name in ("yarn.lock", "yarn-lock.yaml"):
        # Look for axios@<version> patterns
        for match in re.finditer(r'"?axios@[^"]*"?\s*:\s*\n\s+version\s+"?([^"\n]+)"?', content):
            ver = _parse_version(match.group(1))
            if ver in vulnerable_versions:
                vuln_axios.append(VulnerableAxios(file=str(lock_path), version=ver))

    return vuln_axios


def _scan_node_modules(
    node_modules_path: Path,
    suspicious_patterns: list[str],
    verbose: bool = False,
) -> list[SuspiciousFile]:
    """Walk node_modules and find suspicious files."""
    suspicious: list[SuspiciousFile] = []
    compiled = [(p, re.compile(p, re.IGNORECASE)) for p in suspicious_patterns]

    try:
        for root, _dirs, files in os.walk(node_modules_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                for pattern_str, pattern_re in compiled:
                    if pattern_re.search(filename) or pattern_re.search(file_path):
                        suspicious.append(SuspiciousFile(path=file_path, pattern=pattern_str))
                        if verbose:
                            print(f"  [suspicious] {file_path} matches pattern '{pattern_str}'")
                        break
    except OSError as exc:
        if verbose:
            print(f"  [warn] Could not walk {node_modules_path}: {exc}")

    return suspicious


def scan(path: str | Path, verbose: bool = False) -> ScanResult:
    """
    Recursively scan *path* for vulnerable Axios versions and malicious packages.

    Args:
        path: Root directory to scan.
        verbose: Print extra debug information.

    Returns:
        A :class:`ScanResult` instance.
    """
    root = Path(path).resolve()
    blocklist = _load_blocklist()
    vulnerable_versions: list[str] = blocklist.get("vulnerable_axios_versions", [])
    malicious_pkgs: list[str] = blocklist.get("malicious_packages", [])
    suspicious_patterns: list[str] = blocklist.get("suspicious_patterns", [])

    result = ScanResult(scan_path=str(root))

    if not root.exists():
        if verbose:
            print(f"[error] Path does not exist: {root}")
        return result

    # Walk directory tree looking for package.json files
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip hidden dirs and deeply nested node_modules (only scan top-level)
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d != "node_modules"
        ]

        current_dir = Path(dirpath)

        if "package.json" in filenames:
            pkg_json = current_dir / "package.json"
            if verbose:
                print(f"  [scan] {pkg_json}")

            vuln, mal = _scan_package_json(
                pkg_json, vulnerable_versions, malicious_pkgs, verbose
            )
            result.vulnerable_axios.extend(vuln)
            result.malicious_packages.extend(mal)
            result.projects_scanned += 1

        # Scan lockfiles
        for lockfile in ("package-lock.json", "yarn.lock"):
            if lockfile in filenames:
                lock_path = current_dir / lockfile
                if verbose:
                    print(f"  [scan] {lock_path}")
                result.vulnerable_axios.extend(
                    _scan_lockfile(lock_path, vulnerable_versions, verbose)
                )

        # Scan node_modules in this directory (one level only)
        node_modules = current_dir / "node_modules"
        if node_modules.is_dir():
            result.suspicious_files.extend(
                _scan_node_modules(node_modules, suspicious_patterns, verbose)
            )

    # De-duplicate findings by (file, version) for axios
    seen_axios: set[tuple[str, str]] = set()
    unique_axios: list[VulnerableAxios] = []
    for v in result.vulnerable_axios:
        key = (v.file, v.version)
        if key not in seen_axios:
            seen_axios.add(key)
            unique_axios.append(v)
    result.vulnerable_axios = unique_axios

    # De-duplicate malicious packages by (file, package)
    seen_mal: set[tuple[str, str]] = set()
    unique_mal: list[MaliciousPackage] = []
    for m in result.malicious_packages:
        key = (m.file, m.package)
        if key not in seen_mal:
            seen_mal.add(key)
            unique_mal.append(m)
    result.malicious_packages = unique_mal

    return result

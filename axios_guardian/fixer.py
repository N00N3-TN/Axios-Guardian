"""Auto-remediation: pin safe Axios, remove malicious packages, clean suspicious files."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from axios_guardian.scanner import ScanResult

SAFE_AXIOS_VERSION = "^1.7.9"


def _update_package_json(pkg_path: Path, malicious_packages: list[str], verbose: bool) -> bool:
    """
    Pin axios to SAFE_AXIOS_VERSION and remove malicious packages from package.json.
    Returns True if the file was modified.
    """
    try:
        with pkg_path.open("r", encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [error] Cannot read {pkg_path}: {exc}")
        return False

    modified = False
    dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]

    for section in dep_sections:
        if section not in data:
            continue
        deps: dict[str, str] = data[section]

        # Pin axios
        if "axios" in deps:
            old = deps["axios"]
            deps["axios"] = SAFE_AXIOS_VERSION
            if old != SAFE_AXIOS_VERSION:
                modified = True
                if verbose:
                    print(f"  [fix] {pkg_path}: axios {old!r} → {SAFE_AXIOS_VERSION!r}")

        # Remove malicious packages
        for pkg in malicious_packages:
            if pkg in deps:
                del deps[pkg]
                modified = True
                if verbose:
                    print(f"  [fix] {pkg_path}: removed malicious package '{pkg}'")

    if modified:
        try:
            with pkg_path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        except OSError as exc:
            print(f"  [error] Cannot write {pkg_path}: {exc}")
            return False

    return modified


def _remove_from_node_modules(node_modules: Path, package_name: str, verbose: bool) -> None:
    """Delete a package directory from node_modules."""
    pkg_dir = node_modules / package_name
    if pkg_dir.is_dir():
        shutil.rmtree(pkg_dir, ignore_errors=True)
        if verbose:
            print(f"  [fix] Removed node_modules/{package_name}/")


def _remove_suspicious_file(file_path: str, verbose: bool) -> None:
    """Delete a suspicious file."""
    try:
        os.remove(file_path)
        if verbose:
            print(f"  [fix] Deleted suspicious file: {file_path}")
    except OSError as exc:
        print(f"  [warn] Could not delete {file_path}: {exc}")


def _run_npm_install(directory: Path, verbose: bool) -> bool:
    """Run `npm install` in directory if npm is available."""
    npm_bin = shutil.which("npm")
    if not npm_bin:
        if verbose:
            print("  [info] npm not found — skipping npm install")
        return False

    try:
        result = subprocess.run(  # noqa: S603
            [npm_bin, "install"],
            cwd=directory,
            capture_output=not verbose,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print(f"  [fix] npm install completed in {directory}")
            return True
        else:
            print(f"  [warn] npm install failed (exit {result.returncode})")
            if verbose and result.stderr:
                print(result.stderr)
            return False
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"  [warn] npm install error: {exc}")
        return False


def fix(result: ScanResult, verbose: bool = False) -> None:
    """
    Apply auto-remediation based on the scan result.

    Actions:
    - Pin axios to a safe version in every affected package.json
    - Remove malicious package entries from package.json
    - Delete malicious packages from node_modules/
    - Delete suspicious files from node_modules/
    - Re-run `npm install` in each affected project directory
    """
    if not result.threats_found:
        print("  Nothing to fix — no threats detected.")
        return

    # Collect unique package.json files that need updating
    affected_files: set[str] = set()
    malicious_pkg_names: list[str] = [m.package for m in result.malicious_packages]

    for v in result.vulnerable_axios:
        if v.file.endswith("package.json"):
            affected_files.add(v.file)

    for m in result.malicious_packages:
        if m.file.endswith("package.json"):
            affected_files.add(m.file)

    # Update each package.json
    npm_install_dirs: set[Path] = set()
    for pkg_file_str in affected_files:
        pkg_path = Path(pkg_file_str)
        modified = _update_package_json(pkg_path, malicious_pkg_names, verbose)
        if modified:
            npm_install_dirs.add(pkg_path.parent)

        # Remove malicious packages from sibling node_modules/
        node_modules = pkg_path.parent / "node_modules"
        if node_modules.is_dir():
            for pkg_name in malicious_pkg_names:
                _remove_from_node_modules(node_modules, pkg_name, verbose)

    # Remove suspicious files
    for sf in result.suspicious_files:
        _remove_suspicious_file(sf.path, verbose)

    # Re-run npm install
    for directory in npm_install_dirs:
        _run_npm_install(directory, verbose)

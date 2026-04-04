"""Tests for axios_guardian.scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from axios_guardian.scanner import scan, _parse_version


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------

class TestParseVersion:
    def test_caret(self):
        assert _parse_version("^1.14.1") == "1.14.1"

    def test_tilde(self):
        assert _parse_version("~1.7.3") == "1.7.3"

    def test_bare(self):
        assert _parse_version("1.0.0") == "1.0.0"

    def test_gte(self):
        assert _parse_version(">=0.29.0") == "0.29.0"

    def test_star(self):
        assert _parse_version("*") == ""


# ---------------------------------------------------------------------------
# Vulnerable axios detection
# ---------------------------------------------------------------------------

class TestVulnerableAxios:
    def test_detects_vulnerable_version(self, project_with_vulnerable_axios: Path):
        result = scan(project_with_vulnerable_axios)
        assert result.threats_found
        assert len(result.vulnerable_axios) == 1
        assert result.vulnerable_axios[0].version == "1.14.1"
        assert result.vulnerable_axios[0].severity == "CRITICAL"

    def test_clean_project_no_threats(self, clean_project: Path):
        result = scan(clean_project)
        assert not result.threats_found
        assert result.vulnerable_axios == []

    def test_all_vulnerable_versions_detected(self, tmp_path: Path):
        """Each known-bad version should be flagged."""
        vulnerable = ["1.14.1", "0.30.4", "1.7.3", "0.29.0"]
        for ver in vulnerable:
            proj = tmp_path / ver
            proj.mkdir()
            pkg = {"dependencies": {"axios": ver}}
            (proj / "package.json").write_text(json.dumps(pkg))

        result = scan(tmp_path)
        found_versions = {v.version for v in result.vulnerable_axios}
        assert found_versions == set(vulnerable)

    def test_caret_version_in_package_json(self, tmp_path: Path):
        pkg = {"dependencies": {"axios": "^1.14.1"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = scan(tmp_path)
        assert any(v.version == "1.14.1" for v in result.vulnerable_axios)

    def test_safe_axios_version_not_flagged(self, clean_project: Path):
        result = scan(clean_project)
        assert result.vulnerable_axios == []

    def test_no_package_json(self, tmp_path: Path):
        result = scan(tmp_path)
        assert not result.threats_found
        assert result.projects_scanned == 0

    def test_empty_dependencies(self, tmp_path: Path):
        pkg = {"name": "empty", "dependencies": {}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = scan(tmp_path)
        assert not result.threats_found

    def test_malformed_package_json(self, tmp_path: Path):
        """Malformed JSON should not crash the scanner; file is found but yields no threats."""
        (tmp_path / "package.json").write_text("{ invalid json }")
        result = scan(tmp_path)  # should not raise
        assert not result.threats_found
        assert result.vulnerable_axios == []
        assert result.malicious_packages == []

    def test_projects_counted(self, tmp_path: Path):
        for name in ("app1", "app2", "app3"):
            d = tmp_path / name
            d.mkdir()
            (d / "package.json").write_text('{"dependencies":{}}')
        result = scan(tmp_path)
        assert result.projects_scanned == 3

    def test_nonexistent_path(self, tmp_path: Path):
        result = scan(tmp_path / "does_not_exist")
        assert not result.threats_found


# ---------------------------------------------------------------------------
# Lockfile scanning
# ---------------------------------------------------------------------------

class TestLockfileScanning:
    def test_detects_in_package_lock(self, project_with_lockfile: Path):
        result = scan(project_with_lockfile)
        assert any(v.version == "1.14.1" for v in result.vulnerable_axios)

    def test_clean_lockfile_no_flag(self, tmp_path: Path):
        pkg = {"dependencies": {"axios": "1.7.9"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        lockfile = {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/axios": {"version": "1.7.9"}
            },
        }
        (tmp_path / "package-lock.json").write_text(json.dumps(lockfile))
        result = scan(tmp_path)
        assert result.vulnerable_axios == []

    def test_malformed_lockfile_no_crash(self, tmp_path: Path):
        (tmp_path / "package.json").write_text('{"dependencies":{}}')
        (tmp_path / "package-lock.json").write_text("{ bad json }")
        result = scan(tmp_path)  # should not raise

    def test_deduplication_across_pkg_and_lockfile(self, project_with_lockfile: Path):
        """Same version found in package.json and lockfile should not duplicate infinitely."""
        result = scan(project_with_lockfile)
        # We should find the version but not have absurd counts
        assert len(result.vulnerable_axios) <= 2


# ---------------------------------------------------------------------------
# Malicious package detection
# ---------------------------------------------------------------------------

class TestMaliciousPackages:
    def test_detects_malicious_package(self, project_with_malicious_pkg: Path):
        result = scan(project_with_malicious_pkg)
        assert result.threats_found
        assert len(result.malicious_packages) == 1
        assert result.malicious_packages[0].package == "plain-crypto-js"

    def test_threat_level_critical_for_malicious(self, project_with_malicious_pkg: Path):
        result = scan(project_with_malicious_pkg)
        assert result.threat_level == "CRITICAL"

    def test_multiple_malicious_packages(self, tmp_path: Path):
        pkg = {
            "dependencies": {
                "plain-crypto-js": "1.0.0",
                "axios-proxy-helper": "2.0.0",
                "axios-retry-malicious": "3.0.0",
            }
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = scan(tmp_path)
        names = {m.package for m in result.malicious_packages}
        assert "plain-crypto-js" in names
        assert "axios-proxy-helper" in names
        assert "axios-retry-malicious" in names

    def test_malicious_in_dev_deps(self, tmp_path: Path):
        pkg = {"devDependencies": {"plain-crypto-js": "1.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = scan(tmp_path)
        assert any(m.package == "plain-crypto-js" for m in result.malicious_packages)


# ---------------------------------------------------------------------------
# Suspicious files
# ---------------------------------------------------------------------------

class TestSuspiciousFiles:
    def test_detects_suspicious_files(self, project_with_suspicious_files: Path):
        result = scan(project_with_suspicious_files)
        assert result.suspicious_files
        names = [Path(s.path).name for s in result.suspicious_files]
        assert any("keylogger" in n for n in names)
        assert any(".exe" in n for n in names)

    def test_normal_js_not_flagged(self, clean_project: Path):
        nm = clean_project / "node_modules" / "axios"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("// axios")
        result = scan(clean_project)
        assert result.suspicious_files == []


# ---------------------------------------------------------------------------
# ScanResult helpers
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_to_dict_structure(self, project_with_vulnerable_axios: Path):
        result = scan(project_with_vulnerable_axios)
        d = result.to_dict()
        assert "scan_path" in d
        assert "threats_found" in d
        assert "vulnerable_axios" in d
        assert "malicious_packages" in d
        assert "suspicious_files" in d
        assert "summary" in d
        assert "projects_scanned" in d["summary"]
        assert "threat_level" in d["summary"]

    def test_threat_level_clean(self, clean_project: Path):
        result = scan(clean_project)
        assert result.threat_level == "CLEAN"

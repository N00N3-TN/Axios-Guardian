"""Tests for axios_guardian.fixer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from axios_guardian.fixer import fix, SAFE_AXIOS_VERSION, _update_package_json
from axios_guardian.scanner import scan, ScanResult


class TestUpdatePackageJson:
    def test_pins_axios_version(self, tmp_path: Path):
        pkg = {"dependencies": {"axios": "1.14.1", "lodash": "4.17.21"}}
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps(pkg))

        _update_package_json(pkg_path, malicious_packages=[], verbose=False)

        updated = json.loads(pkg_path.read_text())
        assert updated["dependencies"]["axios"] == SAFE_AXIOS_VERSION
        assert updated["dependencies"]["lodash"] == "4.17.21"

    def test_removes_malicious_package(self, tmp_path: Path):
        pkg = {"dependencies": {"axios": "1.7.9", "plain-crypto-js": "4.2.1"}}
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps(pkg))

        _update_package_json(pkg_path, malicious_packages=["plain-crypto-js"], verbose=False)

        updated = json.loads(pkg_path.read_text())
        assert "plain-crypto-js" not in updated["dependencies"]

    def test_handles_dev_dependencies(self, tmp_path: Path):
        pkg = {
            "dependencies": {"axios": "1.7.9"},
            "devDependencies": {"plain-crypto-js": "1.0.0"},
        }
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps(pkg))

        _update_package_json(pkg_path, malicious_packages=["plain-crypto-js"], verbose=False)

        updated = json.loads(pkg_path.read_text())
        assert "plain-crypto-js" not in updated.get("devDependencies", {})

    def test_malformed_json_returns_false(self, tmp_path: Path):
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text("{ invalid }")
        result = _update_package_json(pkg_path, malicious_packages=[], verbose=False)
        assert result is False

    def test_no_axios_key_no_error(self, tmp_path: Path):
        pkg = {"dependencies": {"lodash": "4.17.21"}}
        pkg_path = tmp_path / "package.json"
        pkg_path.write_text(json.dumps(pkg))
        # Should not raise
        _update_package_json(pkg_path, malicious_packages=[], verbose=False)


class TestFix:
    def test_fix_no_threats_does_nothing(self, clean_project: Path, capsys):
        result = scan(clean_project)
        fix(result, verbose=False)
        captured = capsys.readouterr()
        assert "Nothing to fix" in captured.out

    def test_fix_pins_axios(self, project_with_vulnerable_axios: Path):
        result = scan(project_with_vulnerable_axios)
        fix(result, verbose=False)

        updated = json.loads((project_with_vulnerable_axios / "package.json").read_text())
        assert updated["dependencies"]["axios"] == SAFE_AXIOS_VERSION

    def test_fix_removes_malicious_from_package_json(self, project_with_malicious_pkg: Path):
        result = scan(project_with_malicious_pkg)
        fix(result, verbose=False)

        updated = json.loads((project_with_malicious_pkg / "package.json").read_text())
        assert "plain-crypto-js" not in updated.get("dependencies", {})

    def test_fix_removes_malicious_from_node_modules(self, project_with_malicious_pkg: Path):
        # Create a fake node_modules directory for the malicious package
        nm = project_with_malicious_pkg / "node_modules" / "plain-crypto-js"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("evil()")

        result = scan(project_with_malicious_pkg)
        fix(result, verbose=False)

        assert not nm.exists()

    def test_fix_removes_suspicious_files(self, project_with_suspicious_files: Path):
        result = scan(project_with_suspicious_files)
        suspicious_paths = [Path(s.path) for s in result.suspicious_files]
        assert suspicious_paths  # precondition

        fix(result, verbose=False)

        for p in suspicious_paths:
            assert not p.exists(), f"Suspicious file was not removed: {p}"

    def test_fix_empty_scan_result(self, tmp_path: Path):
        """fix() on an empty ScanResult should not raise."""
        result = ScanResult(scan_path=str(tmp_path))
        fix(result, verbose=False)  # should not raise

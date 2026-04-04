"""Tests for axios_guardian.reporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from axios_guardian.reporter import print_report, print_json, save_report
from axios_guardian.scanner import scan, ScanResult


FIXED_TIMESTAMP = "2025-07-05T14:23:01+00:00"


class TestPrintReport:
    def test_clean_project_shows_clean(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_report(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        assert "CLEAN" in out

    def test_vulnerable_project_shows_critical(self, project_with_vulnerable_axios: Path, capsys):
        result = scan(project_with_vulnerable_axios)
        print_report(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        assert "CRITICAL" in out
        assert "1.14.1" in out

    def test_malicious_pkg_shows_in_output(self, project_with_malicious_pkg: Path, capsys):
        result = scan(project_with_malicious_pkg)
        print_report(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        assert "plain-crypto-js" in out

    def test_no_banner_suppresses_header(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_report(result, timestamp=FIXED_TIMESTAMP, show_banner=False)
        out = capsys.readouterr().out
        assert "AXIOS GUARDIAN" not in out

    def test_banner_shown_by_default(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_report(result, timestamp=FIXED_TIMESTAMP, show_banner=True)
        out = capsys.readouterr().out
        assert "AXIOS GUARDIAN" in out

    def test_timestamp_in_output(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_report(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        assert FIXED_TIMESTAMP in out

    def test_scan_path_in_output(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_report(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        assert str(clean_project) in out

    def test_suspicious_files_shown(self, project_with_suspicious_files: Path, capsys):
        result = scan(project_with_suspicious_files)
        print_report(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        assert "Suspicious" in out


class TestPrintJson:
    def test_outputs_valid_json(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_json(result, timestamp=FIXED_TIMESTAMP)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "scan_timestamp" in data
        assert "threats_found" in data

    def test_timestamp_in_json(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_json(result, timestamp=FIXED_TIMESTAMP)
        data = json.loads(capsys.readouterr().out)
        assert data["scan_timestamp"] == FIXED_TIMESTAMP

    def test_vulnerable_axios_in_json(self, project_with_vulnerable_axios: Path, capsys):
        result = scan(project_with_vulnerable_axios)
        print_json(result, timestamp=FIXED_TIMESTAMP)
        data = json.loads(capsys.readouterr().out)
        assert data["threats_found"] is True
        assert any(v["version"] == "1.14.1" for v in data["vulnerable_axios"])

    def test_malicious_pkg_in_json(self, project_with_malicious_pkg: Path, capsys):
        result = scan(project_with_malicious_pkg)
        print_json(result, timestamp=FIXED_TIMESTAMP)
        data = json.loads(capsys.readouterr().out)
        assert any(m["package"] == "plain-crypto-js" for m in data["malicious_packages"])

    def test_summary_in_json(self, clean_project: Path, capsys):
        result = scan(clean_project)
        print_json(result, timestamp=FIXED_TIMESTAMP)
        data = json.loads(capsys.readouterr().out)
        assert "summary" in data
        assert "threat_level" in data["summary"]
        assert "projects_scanned" in data["summary"]


class TestSaveReport:
    def test_saves_json_file(self, clean_project: Path, tmp_path: Path):
        result = scan(clean_project)
        report_path = tmp_path / "report.json"
        save_report(result, report_path, timestamp=FIXED_TIMESTAMP)
        assert report_path.exists()

    def test_saved_file_is_valid_json(self, clean_project: Path, tmp_path: Path):
        result = scan(clean_project)
        report_path = tmp_path / "report.json"
        save_report(result, report_path, timestamp=FIXED_TIMESTAMP)
        data = json.loads(report_path.read_text())
        assert "scan_timestamp" in data

    def test_saved_report_contains_threats(self, project_with_vulnerable_axios: Path, tmp_path: Path):
        result = scan(project_with_vulnerable_axios)
        report_path = tmp_path / "report.json"
        save_report(result, report_path, timestamp=FIXED_TIMESTAMP)
        data = json.loads(report_path.read_text())
        assert data["threats_found"] is True

    def test_invalid_path_does_not_raise(self, clean_project: Path):
        result = scan(clean_project)
        # Should not raise even on bad path — just warn
        save_report(result, "/nonexistent_dir/report.json", timestamp=FIXED_TIMESTAMP)

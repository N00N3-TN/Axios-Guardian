"""Integration tests for the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from axios_guardian.cli import main


class TestCLI:
    def test_clean_project_exits_zero(self, clean_project: Path):
        code = main(["--path", str(clean_project), "--no-banner"])
        assert code == 0

    def test_vulnerable_project_exits_one(self, project_with_vulnerable_axios: Path):
        code = main(["--path", str(project_with_vulnerable_axios), "--no-banner"])
        assert code == 1

    def test_malicious_project_exits_one(self, project_with_malicious_pkg: Path):
        code = main(["--path", str(project_with_malicious_pkg), "--no-banner"])
        assert code == 1

    def test_json_output_is_valid(self, clean_project: Path, capsys):
        main(["--path", str(clean_project), "--json", "--no-banner"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "threats_found" in data

    def test_report_file_created(self, clean_project: Path, tmp_path: Path):
        report_path = tmp_path / "out.json"
        main(["--path", str(clean_project), "--report", str(report_path), "--no-banner"])
        assert report_path.exists()

    def test_fix_flag_pins_axios(self, project_with_vulnerable_axios: Path):
        main(["--path", str(project_with_vulnerable_axios), "--fix", "--no-banner"])
        updated = json.loads((project_with_vulnerable_axios / "package.json").read_text())
        from axios_guardian.fixer import SAFE_AXIOS_VERSION
        assert updated["dependencies"]["axios"] == SAFE_AXIOS_VERSION

    def test_verbose_flag_no_crash(self, clean_project: Path):
        code = main(["--path", str(clean_project), "--verbose", "--no-banner"])
        assert code == 0

    def test_nonexistent_path_exits_zero(self, tmp_path: Path):
        code = main(["--path", str(tmp_path / "does_not_exist"), "--no-banner"])
        assert code == 0  # no threats = clean exit

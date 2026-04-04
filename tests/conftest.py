"""Shared pytest fixtures for Axios Guardian tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """Return an empty temporary project directory."""
    return tmp_path


@pytest.fixture()
def project_with_vulnerable_axios(tmp_path: Path) -> Path:
    """A project that references a vulnerable axios version."""
    pkg = {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "axios": "1.14.1",
            "lodash": "4.17.21",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))
    return tmp_path


@pytest.fixture()
def project_with_malicious_pkg(tmp_path: Path) -> Path:
    """A project that contains a malicious package."""
    pkg = {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "axios": "1.7.9",
            "plain-crypto-js": "4.2.1",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))
    return tmp_path


@pytest.fixture()
def clean_project(tmp_path: Path) -> Path:
    """A project with no known threats."""
    pkg = {
        "name": "clean-app",
        "version": "1.0.0",
        "dependencies": {
            "axios": "1.7.9",
            "express": "4.18.2",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))
    return tmp_path


@pytest.fixture()
def project_with_lockfile(tmp_path: Path) -> Path:
    """A project with a package-lock.json containing a vulnerable axios."""
    pkg = {"name": "lockfile-app", "version": "1.0.0", "dependencies": {"axios": "^1.14.1"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))

    lockfile = {
        "name": "lockfile-app",
        "lockfileVersion": 2,
        "packages": {
            "node_modules/axios": {
                "version": "1.14.1",
                "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz",
            }
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lockfile, indent=2))
    return tmp_path


@pytest.fixture()
def project_with_suspicious_files(tmp_path: Path) -> Path:
    """A project with suspicious files in node_modules."""
    pkg = {"name": "sus-app", "version": "1.0.0", "dependencies": {"axios": "1.7.9"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))

    nm = tmp_path / "node_modules" / "some-pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("// normal")
    (nm / "keylogger.js").write_text("// evil")
    (nm / "backdoor.exe").write_text("binary")
    return tmp_path

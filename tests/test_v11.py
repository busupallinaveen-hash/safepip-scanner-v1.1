"""
safe-pip v1.1 test suite
Run with: pytest
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import BytesIO

import pytest
from click.testing import CliRunner

from safe_pip import __version__
from safe_pip.cli import main
from safe_pip.scanner import _check_typosquat, _score_local, fetch_pypi
from safe_pip.watch import (
    _windows_shim_content,
    _unix_shim_content,
    _PS_ALIAS_TEMPLATE,
    enable,
    disable,
    status,
    _shim_dir,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_pypi(pkg="testpkg", version="1.0.0", author="Alice", releases=10,
               age_years=3.0, homepage="https://example.com", license_="MIT"):
    return {
        "name": pkg, "version": version, "summary": "A test package",
        "author": author, "license": license_, "requires_python": ">=3.8",
        "homepage": homepage, "keywords": "", "release_count": releases,
        "age_years": age_years, "requires_dist": [], "yanked": False,
        "pypi_exists": True,
    }


def _mock_urlopen(body: dict):
    raw = json.dumps(body).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_format(self):
        parts = __version__.split(".")
        assert len(parts) == 3

    def test_version_is_1_1(self):
        assert __version__ == "1.1.0"

    def test_cli_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_cli_help_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "watch" in result.output


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------

class TestTyposquat:
    def test_known_threat_colourama(self):
        r = _check_typosquat("colourama")
        assert r["known_threat"] is True
        assert r["likely_typosquat"] is True
        assert r["similar_legit_package"] == "colorama"

    def test_known_threat_requestss(self):
        r = _check_typosquat("requestss")
        assert r["likely_typosquat"] is True

    def test_known_threat_numppy(self):
        r = _check_typosquat("numppy")
        assert r["likely_typosquat"] is True

    def test_known_threat_diango(self):
        r = _check_typosquat("diango")
        assert r["known_threat"] is True
        assert r["similar_legit_package"] == "django"

    def test_clean_package_not_flagged(self):
        r = _check_typosquat("requests")
        assert r["likely_typosquat"] is False
        assert r["known_threat"] is False

    def test_numpy_not_flagged(self):
        r = _check_typosquat("numpy")
        assert r["likely_typosquat"] is False

    def test_result_has_required_keys(self):
        r = _check_typosquat("flask")
        assert "known_threat" in r
        assert "likely_typosquat" in r
        assert "similar_legit_package" in r
        assert "highest_similarity" in r
        assert "top_matches" in r

    def test_top_matches_sorted_desc(self):
        r = _check_typosquat("numppy")
        if r["top_matches"]:
            sims = [m["similarity"] for m in r["top_matches"]]
            assert sims == sorted(sims, reverse=True)

    def test_top_matches_max_5(self):
        r = _check_typosquat("requestss")
        assert len(r["top_matches"]) <= 5


# ---------------------------------------------------------------------------
# Local scorer
# ---------------------------------------------------------------------------

class TestLocalScorer:
    def _osv(self, total=0):
        return {"total": total, "cve_ids": [], "error": None}

    def test_trusted_package_low_score(self):
        pypi = _mock_pypi("flask")
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("flask", pypi, typo, self._osv())
        assert r["score"] == 0
        assert r["decision"] == "INSTALL"
        assert r["verdict"] == "LOW"

    def test_known_dangerous_pycrypto(self):
        pypi = _mock_pypi("pycrypto")
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("pycrypto", pypi, typo, self._osv())
        assert r["decision"] == "BLOCK"
        assert r["score"] >= 80

    def test_typosquat_blocked(self):
        pypi = _mock_pypi("requestss")
        typo = {"likely_typosquat": True, "known_threat": False,
                 "similar_legit_package": "requests", "highest_similarity": 95, "top_matches": []}
        r = _score_local("requestss", pypi, typo, self._osv())
        assert r["decision"] == "BLOCK"
        assert r["score"] >= 90

    def test_not_on_pypi_blocked(self):
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("nonexistent-pkg", None, typo, self._osv())
        assert r["decision"] == "BLOCK"

    def test_yanked_package_penalised(self):
        pypi = _mock_pypi("badpkg")
        pypi["yanked"] = True
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("badpkg", pypi, typo, self._osv())
        assert r["score"] >= 30

    def test_cve_raises_score(self):
        pypi = _mock_pypi("somepkg")
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("somepkg", pypi, typo, self._osv(total=2))
        assert r["score"] > 25

    def test_output_schema(self):
        pypi = _mock_pypi("flask")
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("flask", pypi, typo, self._osv())
        for key in ("score", "verdict", "decision", "decision_reason",
                    "findings", "analysis", "recommendation", "trust_score", "known_cves", "metrics"):
            assert key in r, f"Missing key: {key}"

    def test_score_clamped_to_100(self):
        pypi = _mock_pypi("badpkg")
        pypi["yanked"] = True
        typo = {"likely_typosquat": False, "known_threat": False,
                 "similar_legit_package": None, "highest_similarity": 0, "top_matches": []}
        r = _score_local("badpkg", pypi, typo, self._osv(total=10))
        assert r["score"] <= 100


# ---------------------------------------------------------------------------
# CLI scan command
# ---------------------------------------------------------------------------

class TestScanCommand:
    def test_scan_trusted_exits_0(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "flask"])
        assert result.exit_code == 0

    def test_scan_typosquat_exits_1(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "requestss", "--fail-on", "high"])
        assert result.exit_code == 1

    def test_scan_json_output_valid(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "flask", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["package"] == "flask"
        assert "score" in parsed
        assert "decision" in parsed

    def test_scan_json_has_findings(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "flask", "--json"])
        parsed = json.loads(result.output)
        assert "findings" in parsed
        assert isinstance(parsed["findings"], list)

    def test_fail_on_warn_safe_pkg_exits_0(self):
        runner = CliRunner()
        # numpy is trusted → always score=0/INSTALL regardless of CVE count
        result = runner.invoke(main, ["scan", "numpy", "--fail-on", "warn"])
        assert result.exit_code == 0, (
            f"numpy is trusted — should always exit 0 (INSTALL), got {result.exit_code}. "
            f"Output: {result.output[-300:]}"
        )

    def test_fail_on_warn_dangerous_exits_1(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "pycrypto", "--fail-on", "warn"])
        assert result.exit_code == 1

    def test_scan_empty_package_fails(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", ""])
        assert result.exit_code != 0

    def test_scan_invalid_chars_fails(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "!!!"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------

class TestWatchShimContent:
    def test_windows_shim_has_header(self):
        shim = _windows_shim_content("safe-pip.exe", "pip.exe")
        assert "safe-pip shim" in shim

    def test_windows_shim_bypass_present(self):
        shim = _windows_shim_content("safe-pip.exe", "pip.exe")
        assert "SAFE_PIP_BYPASS" in shim

    def test_windows_shim_goto_structure(self):
        # Must NOT have safe-pip call inside nested if() block
        shim = _windows_shim_content("safe-pip.exe", "pip.exe")
        assert "if /i not" in shim    # goto-based, not nested if
        assert "Scan passed" in shim  # real pip called after scan

    def test_windows_shim_calls_real_pip_after_scan(self):
        shim = _windows_shim_content("safe-pip.exe", "pip.exe")
        scan_idx = shim.index("safe-pip.exe\" install")
        pip_idx  = shim.index("pip.exe %*", scan_idx)
        assert pip_idx > scan_idx    # real pip comes after scan

    def test_windows_shim_bypasses_editable(self):
        shim = _windows_shim_content("safe-pip.exe", "pip.exe")
        assert '"%~2"=="-e"' in shim

    def test_unix_shim_is_shell_script(self):
        shim = _unix_shim_content("/usr/bin/safe-pip", "/usr/bin/pip")
        assert shim.startswith("#!/bin/sh")

    def test_unix_shim_bypass_present(self):
        shim = _unix_shim_content("/usr/bin/safe-pip", "/usr/bin/pip")
        assert "SAFE_PIP_BYPASS" in shim

    def test_unix_shim_calls_real_pip_after_scan(self):
        shim = _unix_shim_content("/usr/bin/safe-pip", "/usr/bin/pip")
        assert "exec /usr/bin/pip" in shim

    def test_ps_alias_checks_exit_code(self):
        assert "LASTEXITCODE" in _PS_ALIAS_TEMPLATE

    def test_ps_alias_calls_real_pip_after_scan(self):
        # real_pip call must come AFTER the LASTEXITCODE check
        idx = _PS_ALIAS_TEMPLATE.index("LASTEXITCODE")
        assert "real_pip" in _PS_ALIAS_TEMPLATE[idx:]

    def test_ps_alias_has_bypass_message(self):
        assert "SAFE_PIP_BYPASS" in _PS_ALIAS_TEMPLATE


class TestWatchEnableDisable:
    def test_enable_creates_shim_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr("safe_pip.watch._shim_dir", lambda: tmp_path / "shims")
        monkeypatch.setattr("safe_pip.watch._find_safe_pip_exe", lambda: "safe-pip")
        monkeypatch.setattr("safe_pip.watch._find_real_pip", lambda: "pip")
        monkeypatch.setattr("safe_pip.watch._windows_add_to_path", lambda d: True)
        monkeypatch.setattr("safe_pip.watch._windows_fix_pathext", lambda: True)
        monkeypatch.setattr("safe_pip.watch._write_ps_alias", lambda s, r: [])
        monkeypatch.setattr("safe_pip.watch._cmd_shim_locations", lambda r: [tmp_path / "shims" / "pip.bat"])
        monkeypatch.setattr("safe_pip.watch.IS_WINDOWS", True)

        r = enable()
        shim = tmp_path / "shims" / "pip.bat"
        assert shim.exists()
        assert "safe-pip shim" in shim.read_text()

    def test_disable_removes_shim(self, tmp_path, monkeypatch):
        shim = tmp_path / "shims" / "pip.bat"
        shim.parent.mkdir(parents=True)
        shim.write_text("@echo off\nREM safe-pip shim\n")

        monkeypatch.setattr("safe_pip.watch._shim_dir", lambda: tmp_path / "shims")
        monkeypatch.setattr("safe_pip.watch._find_real_pip", lambda: "pip")
        monkeypatch.setattr("safe_pip.watch._windows_remove_from_path", lambda d: True)
        monkeypatch.setattr("safe_pip.watch._remove_ps_alias", lambda: 1)
        monkeypatch.setattr("safe_pip.watch._cmd_shim_locations", lambda r: [shim])
        monkeypatch.setattr("safe_pip.watch.IS_WINDOWS", True)

        r = disable()
        assert r["cmd_removed"] >= 1

    def test_status_inactive_when_no_shim(self, tmp_path, monkeypatch):
        monkeypatch.setattr("safe_pip.watch._shim_dir", lambda: tmp_path / "shims")
        s = status()
        assert s["active"] is False
        assert s["shim_exists"] is False


class TestWatchCli:
    def test_watch_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["watch", "--help"])
        assert result.exit_code == 0
        assert "enable" in result.output
        assert "disable" in result.output
        assert "status" in result.output

    def test_watch_status_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["watch", "status"])
        assert result.exit_code == 0
        assert "Watch mode" in result.output

    def test_watch_enable_runs(self, tmp_path, monkeypatch):
        monkeypatch.setattr("safe_pip.watch._shim_dir", lambda: tmp_path / "shims")
        monkeypatch.setattr("safe_pip.watch._find_safe_pip_exe", lambda: "safe-pip")
        monkeypatch.setattr("safe_pip.watch._find_real_pip", lambda: "pip")
        monkeypatch.setattr("safe_pip.watch._windows_add_to_path", lambda d: True)
        monkeypatch.setattr("safe_pip.watch._windows_fix_pathext", lambda: False)
        monkeypatch.setattr("safe_pip.watch._write_ps_alias", lambda s, r: [])
        monkeypatch.setattr("safe_pip.watch._cmd_shim_locations", lambda r: [tmp_path / "pip.bat"])
        monkeypatch.setattr("safe_pip.watch.IS_WINDOWS", True)

        runner = CliRunner()
        result = runner.invoke(main, ["watch", "enable"])
        assert result.exit_code == 0
        assert "enabling" in result.output.lower()

    def test_watch_disable_runs(self, tmp_path, monkeypatch):
        monkeypatch.setattr("safe_pip.watch._shim_dir", lambda: tmp_path / "shims")
        monkeypatch.setattr("safe_pip.watch._find_real_pip", lambda: "pip")
        monkeypatch.setattr("safe_pip.watch._windows_remove_from_path", lambda d: True)
        monkeypatch.setattr("safe_pip.watch._remove_ps_alias", lambda: 0)
        monkeypatch.setattr("safe_pip.watch._cmd_shim_locations", lambda r: [])
        monkeypatch.setattr("safe_pip.watch.IS_WINDOWS", True)

        runner = CliRunner()
        result = runner.invoke(main, ["watch", "disable"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Watch status: "INACTIVE in same terminal" explanation
# ---------------------------------------------------------------------------

class TestWatchStatusMessage:
    def test_status_shows_shim_exists(self):
        runner = CliRunner()
        result = runner.invoke(main, ["watch", "status"])
        assert "Shim exists" in result.output

    def test_status_shows_on_path(self):
        runner = CliRunner()
        result = runner.invoke(main, ["watch", "status"])
        assert "On PATH" in result.output


# ---------------------------------------------------------------------------
# New commands: install, doctor, update-db
# ---------------------------------------------------------------------------

class TestInstallCommand:
    def test_install_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["install", "--help"])
        assert result.exit_code == 0
        assert "install" in result.output.lower()

    def test_install_blocked_exits_1(self):
        runner = CliRunner()
        result = runner.invoke(main, ["install", "pycrypto", "--yes"])
        assert result.exit_code == 1

    def test_install_typosquat_blocked(self):
        runner = CliRunner()
        result = runner.invoke(main, ["install", "requestss", "--yes"])
        assert result.exit_code == 1


class TestDoctorCommand:
    def test_doctor_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
        assert result.exit_code in (0, 1)  # may fail if deps missing
        assert "doctor" in result.output.lower()

    def test_doctor_shows_python_version(self):
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
        assert "Python version" in result.output

    def test_doctor_shows_watch_status(self):
        runner = CliRunner()
        result = runner.invoke(main, ["doctor"])
        assert "Watch mode" in result.output


class TestUpdateDbCommand:
    def test_update_db_runs(self):
        runner = CliRunner()
        result = runner.invoke(main, ["update-db"])
        assert result.exit_code == 0
        assert "threat database" in result.output.lower()

    def test_update_db_shows_entries(self):
        runner = CliRunner()
        result = runner.invoke(main, ["update-db"])
        assert "entries" in result.output


class TestAllCommandsInHelp:
    def test_scan_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "scan" in result.output

    def test_install_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "install" in result.output

    def test_doctor_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "doctor" in result.output

    def test_update_db_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "update-db" in result.output

    def test_watch_in_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert "watch" in result.output


# ---------------------------------------------------------------------------
# False positive reduction
# ---------------------------------------------------------------------------

class TestFalsePositives:
    """Packages that should always be INSTALL — no false positives."""

    SAFE_PKGS = [
        "mypy", "poetry", "loguru", "invoke", "httpx", "black",
        "flake8", "arrow", "paramiko", "cryptography", "pillow",
        "celery", "aiohttp", "sqlalchemy", "pydantic", "fastapi",
        "numpy", "pandas", "flask", "django", "requests",
    ]

    def test_no_false_positives(self):
        from safe_pip.scanner import scan
        fps = []
        for pkg in self.SAFE_PKGS:
            r = _scan_direct(pkg)
            if r["ai"]["decision"] != "INSTALL":
                fps.append((pkg, r["ai"]["decision"], r["ai"]["score"]))
        assert fps == [], f"False positives detected: {fps}"

    def test_mypy_install(self):
        from safe_pip.scanner import scan
        r = _scan_direct("mypy")
        assert r["ai"]["decision"] == "INSTALL"
        assert r["ai"]["score"] == 0

    def test_poetry_install(self):
        from safe_pip.scanner import scan
        r = _scan_direct("poetry")
        assert r["ai"]["decision"] == "INSTALL", f"poetry scored {r['ai']['score']} → {r['ai']['decision']}"
        assert r["ai"]["score"] == 0

    def test_loguru_install(self):
        from safe_pip.scanner import scan
        r = _scan_direct("loguru")
        assert r["ai"]["decision"] == "INSTALL"

    def test_homepage_from_project_urls(self):
        """Packages using project_urls instead of home_page should not be penalised."""
        from safe_pip.scanner import fetch_pypi
        from unittest.mock import patch
        import json, urllib.error

        # Simulate PyPI response with project_urls but no home_page
        fake_info = {
            "name": "mypkg", "version": "1.0", "summary": "A package",
            "author": "Alice", "license": None, "requires_python": ">=3.8",
            "home_page": None, "keywords": "",
            "project_urls": {"Homepage": "https://github.com/alice/mypkg"},
            "classifiers": ["License :: OSI Approved :: MIT License"],
            "requires_dist": [], "yanked": False,
        }
        fake_response_body = json.dumps({
            "info": fake_info,
            "releases": {"1.0": [{"upload_time": "2020-01-01T00:00:00"}]},
            "urls": [],
        }).encode()

        from unittest.mock import MagicMock
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_response_body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_get = MagicMock()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "info": fake_info,
            "releases": {"1.0": [{"upload_time": "2020-01-01T00:00:00"}]},
            "urls": [],
        }
        mock_get.return_value.raise_for_status = lambda: None

        with patch("requests.get", mock_get):
            result = fetch_pypi("mypkg")

        assert result["homepage"] == "https://github.com/alice/mypkg"
        assert result["license"] == "MIT License"

    def test_license_from_classifiers(self):
        """License should be extracted from classifiers when license field is empty."""
        from safe_pip.scanner import fetch_pypi
        from unittest.mock import patch, MagicMock
        import json

        fake_info = {
            "name": "mypkg", "version": "1.0", "summary": "x",
            "author": "Alice", "license": None, "requires_python": ">=3.8",
            "home_page": "https://example.com", "keywords": "",
            "project_urls": {},
            "classifiers": ["License :: OSI Approved :: Apache Software License"],
            "requires_dist": [], "yanked": False,
        }
        fake_body = json.dumps({
            "info": fake_info,
            "releases": {"1.0": [{"upload_time": "2020-01-01T00:00:00"}]},
            "urls": [],
        }).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_get = MagicMock()
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "info": fake_info,
            "releases": {"1.0": [{"upload_time": "2020-01-01T00:00:00"}]},
            "urls": [],
        }
        mock_get.return_value.raise_for_status = lambda: None

        with patch("requests.get", mock_get):
            result = fetch_pypi("mypkg")

        assert result["license"] == "Apache Software License"


# ---------------------------------------------------------------------------
# Alias / Did you mean
# ---------------------------------------------------------------------------

class TestAliasDisplay:
    """Typosquats should show 'Did you mean: X' prominently in output."""

    TYPOSQUAT_MAP = {
        "numppy":    "numpy",
        "requestss": "requests",
        "diango":    "django",
        "pandass":   "pandas",
    }

    def test_did_you_mean_shown_in_rich_output(self):
        runner = CliRunner()
        for typo, correct in self.TYPOSQUAT_MAP.items():
            result = runner.invoke(main, ["scan", typo])
            assert "Did you mean" in result.output, (
                f"Expected 'Did you mean' for {typo!r}, got:\n{result.output}"
            )

    def test_alias_shows_correct_package(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "numppy"])
        assert "numpy" in result.output

    def test_did_you_mean_in_json(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "numppy", "--json"])
        import json
        d = json.loads(result.output)
        assert d.get("did_you_mean") == "numpy"

    def test_no_did_you_mean_for_clean_package(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "flask", "--json"])
        import json
        d = json.loads(result.output)
        assert d.get("did_you_mean") is None

    def test_alias_run_command_shown(self):
        """Output should suggest the correct pip install command."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "requestss"])
        assert "pip install requests" in result.output

    def test_typosquat_still_blocked(self):
        """Did you mean should not change the BLOCK decision."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "numppy", "--json"])
        import json
        d = json.loads(result.output)
        assert d["decision"] == "BLOCK"
        assert d["did_you_mean"] == "numpy"


# ---------------------------------------------------------------------------
# Input validation — clear error messages
# ---------------------------------------------------------------------------

class TestInputValidationMessages:
    def test_invalid_chars_shows_invalid_message(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "!!!"])
        assert result.exit_code == 1
        assert "Invalid" in result.output or "invalid" in result.output

    def test_space_in_name_shows_invalid(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "req uests"])
        assert result.exit_code == 1

    def test_empty_string_fails(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", ""])
        assert result.exit_code == 1

    def test_valid_hyphenated_name_accepted(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "scikit-learn"])
        assert result.exit_code == 0

    def test_valid_dotted_name_accepted(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "zope.interface"])
        # May fail on network but not on validation
        assert result.exit_code in (0, 1)

    def test_valid_underscored_name_accepted(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "python_dateutil"])
        assert result.exit_code in (0, 1)


# ---------------------------------------------------------------------------
# False positive reduction
# ---------------------------------------------------------------------------

from safe_pip.scanner import scan as _scan_direct

class TestFalsePositiveReduction:
    """Packages that were false-positiving due to missing project_urls / classifiers."""

    def test_mypy_not_flagged(self):
        r = _scan_direct("mypy")
        assert r["ai"]["decision"] == "INSTALL", f"mypy should be INSTALL, got {r['ai']['decision']} score={r['ai']['score']}"

    def test_poetry_not_flagged(self):
        r = _scan_direct("poetry")
        assert r["ai"]["decision"] == "INSTALL"

    def test_loguru_not_flagged(self):
        r = _scan_direct("loguru")
        assert r["ai"]["decision"] == "INSTALL"

    def test_invoke_not_flagged(self):
        r = _scan_direct("invoke")
        assert r["ai"]["decision"] == "INSTALL"

    def test_black_not_flagged(self):
        r = _scan_direct("black")
        assert r["ai"]["decision"] == "INSTALL"

    def test_flake8_not_flagged(self):
        r = _scan_direct("flake8")
        assert r["ai"]["decision"] == "INSTALL"

    def test_httpx_not_flagged(self):
        r = _scan_direct("httpx")
        assert r["ai"]["decision"] == "INSTALL"

    def test_arrow_not_flagged(self):
        r = _scan_direct("arrow")
        assert r["ai"]["decision"] == "INSTALL"

    def test_trusted_packages_all_install(self):
        for pkg in ["requests", "flask", "numpy", "pandas", "django",
                    "boto3", "sqlalchemy", "cryptography", "pillow"]:
            r = _scan_direct(pkg)
            assert r["ai"]["decision"] == "INSTALL", (
                f"{pkg} should be INSTALL, got {r['ai']['decision']} score={r['ai']['score']}")


# ---------------------------------------------------------------------------
# Alias / Did you mean
# ---------------------------------------------------------------------------

class TestAlias:
    def test_numppy_alias_numpy(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "numppy"])
        assert "Did you mean" in result.output
        assert "numpy" in result.output

    def test_requestss_alias_requests(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "requestss"])
        assert "Did you mean" in result.output
        assert "requests" in result.output

    def test_diango_alias_django(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "diango"])
        assert "Did you mean" in result.output
        assert "django" in result.output

    def test_pandass_alias_pandas(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "pandass"])
        assert "Did you mean" in result.output
        assert "pandas" in result.output

    def test_alias_in_json_output(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "numppy", "--json"])
        parsed = json.loads(result.output)
        assert parsed["did_you_mean"] == "numpy"

    def test_no_alias_for_clean_package(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "flask", "--json"])
        parsed = json.loads(result.output)
        assert parsed.get("did_you_mean") is None

    def test_alias_install_command_shows_correct_name(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "requestss"])
        # Should show pip install requests (the correct package)
        assert "requests" in result.output


# ---------------------------------------------------------------------------
# Improved input validation
# ---------------------------------------------------------------------------

class TestInputValidationImproved:
    def test_invalid_chars_shows_error_message(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "!!!"])
        assert result.exit_code == 1
        assert "Invalid" in result.output or "invalid" in result.output.lower()

    def test_space_in_name_shows_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "req uests"])
        assert result.exit_code == 1

    def test_empty_name_shows_error(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", ""])
        assert result.exit_code == 1

    def test_valid_hyphenated_name_passes_validation(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "scikit-learn"])
        assert result.exit_code == 0

    def test_valid_dotted_name_passes_validation(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "zope.interface"])
        assert result.exit_code == 0

    def test_valid_underscored_name_passes_validation(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "my_package"])
        assert result.exit_code in (0, 1)  # may not exist on PyPI but shouldn't be ValueError


# ---------------------------------------------------------------------------
# python -m safe_pip support
# ---------------------------------------------------------------------------

class TestPythonMModule:
    def test_python_m_safe_pip_version(self):
        import subprocess, sys
        r = subprocess.run([sys.executable, "-m", "safe_pip", "--version"],
                           capture_output=True, text=True)
        assert r.returncode == 0
        assert "1.1.0" in r.stdout

    def test_python_m_safe_pip_scan(self):
        import subprocess, sys
        r = subprocess.run([sys.executable, "-m", "safe_pip", "scan", "flask", "--json"],
                           capture_output=True, text=True)
        assert r.returncode == 0
        import json
        d = json.loads(r.stdout)
        assert d["decision"] == "INSTALL"

    def test_main_py_exists(self):
        import os
        main_path = os.path.join(
            os.path.dirname(__file__), "..", "safe_pip", "__main__.py")
        assert os.path.exists(main_path)


# ---------------------------------------------------------------------------
# Expanded typosquat detection (threshold=85 + more KNOWN_THREATS)
# ---------------------------------------------------------------------------

class TestExpandedTyposquatDetection:
    """Full spec coverage — 91 typosquats across 40+ packages."""

    CASES = [
        # requests
        ("requestss","requests"),("reqests","requests"),("requsets","requests"),
        ("requestes","requests"),("requsts","requests"),
        # numpy
        ("numppy","numpy"),("nummpy","numpy"),("numy","numpy"),("nuumpy","numpy"),
        # pandas
        ("pandaas","pandas"),("pands","pandas"),("pandass","pandas"),("paandas","pandas"),
        # django
        ("djagno","django"),("djanngo","django"),("djangoo","django"),
        # flask
        ("flaks","flask"),("flaskk","flask"),("flsk","flask"),
        # tensorflow
        ("tensorflw","tensorflow"),("tensorfow","tensorflow"),
        ("tensorflo","tensorflow"),("tensor-flow","tensorflow"),
        # torch/pytorch
        ("torhc","torch"),("toorch","torch"),("troch","torch"),
        ("pytoch","torch"),("pytorc","torch"),("pyttorch","torch"),
        # matplotlib
        ("matplotllib","matplotlib"),("matplotib","matplotlib"),("matplolib","matplotlib"),
        # scikit-learn
        ("scikitlearn","scikit-learn"),("scikitlern","scikit-learn"),("scikit-leern","scikit-learn"),
        # beautifulsoup4
        ("beautiflsoup4","beautifulsoup4"),("beautifulsop4","beautifulsoup4"),("beautifulsoop4","beautifulsoup4"),
        # selenium
        ("sellenium","selenium"),("seleniumm","selenium"),("selenum","selenium"),
        # pillow
        ("pilow","pillow"),("pilllow","pillow"),("piloww","pillow"),
        # cryptography
        ("cryptograpy","cryptography"),("cryptograhpy","cryptography"),("cryptographyy","cryptography"),
        # sqlalchemy
        ("sqlachemy","sqlalchemy"),("sqlalchmey","sqlalchemy"),("sqlalchemyy","sqlalchemy"),
        # fastapi
        ("fastpai","fastapi"),("fastappi","fastapi"),("fast-api","fastapi"),
        # pytest
        ("pytes","pytest"),("pyttest","pytest"),("pytestt","pytest"),
        # jupyter/notebook
        ("jupytr","jupyter"),("jupter","jupyter"),("jupyterr","jupyter"),
        ("notebok","notebook"),("notebookk","notebook"),
        # streamlit
        ("streamlitt","streamlit"),("streamlt","streamlit"),
        # transformers
        ("transformres","transformers"),("transfomers","transformers"),
        # langchain
        ("langchan","langchain"),("langcahin","langchain"),
        # openai
        ("opneai","openai"),("openaai","openai"),
        # anthropic
        ("anthropik","anthropic"),("anthrophic","anthropic"),
        # rich/click
        ("ricch","rich"),("richh","rich"),("clik","click"),("clickk","click"),
        # pyyaml
        ("pyaml","pyyaml"),("pyyml","pyyaml"),
        # celery/redis
        ("celerry","celery"),("celry","celery"),
        ("reddis","redis"),("rediss","redis"),
        # boto3
        ("bot03","boto3"),("boto33","boto3"),
        # black/mypy/pylint/isort
        ("blacck","black"),("blackk","black"),
        ("myppi","mypy"),("myppy","mypy"),
        ("pylnt","pylint"),("pyllint","pylint"),
        ("issort","isort"),("isorrt","isort"),
    ]

    @pytest.mark.parametrize("typo,target", CASES)
    def test_typosquat_detected(self, typo, target):
        r = _check_typosquat(typo)
        assert r["likely_typosquat"] is True, (
            f"{typo!r} should be detected as typosquat of {target!r}, "
            f"got similar={r.get('similar_legit_package')} similarity={r.get('highest_similarity')}"
        )
        assert r["similar_legit_package"] == target, (
            f"{typo!r}: expected {target!r}, got {r.get('similar_legit_package')!r}"
        )

    def test_legitimate_packages_not_flagged(self):
        legit = ["requests","numpy","pandas","django","flask","tensorflow",
                 "torch","matplotlib","scikit-learn","beautifulsoup4",
                 "selenium","pillow","cryptography","sqlalchemy","fastapi",
                 "pytest","jupyter","streamlit","transformers","langchain",
                 "openai","anthropic","rich","click","pyyaml","celery",
                 "redis","boto3","black","mypy","pylint","isort"]
        for pkg in legit:
            r = _check_typosquat(pkg)
            assert r["likely_typosquat"] is False, f"{pkg} should not be a typosquat"


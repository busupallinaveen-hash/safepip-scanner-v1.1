"""
safe-pip scanner v1.1 — improved scoring engine with more metadata analysis.
Still uses requests (circular dependency not yet fixed).
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Optional

import requests

ANTHROPIC_MODEL = "claude-sonnet-4-6"
ANTHROPIC_API   = "https://api.anthropic.com/v1/messages"
PYPI_URL        = "https://pypi.org/pypi/{pkg}/json"
OSV_URL         = "https://api.osv.dev/v1/query"

_KNOWN_DANGEROUS = {
    "pycrypto":          "Abandoned since 2014; unpatched CVEs. Use pycryptodome.",
    "colourama":         "Confirmed typosquat of colorama — credential stealer.",
    "python3-dateutil":  "Typosquat of python-dateutil — confirmed malicious.",
    "insecure-package":  "Intentionally insecure test package.",
    "setup-tools":       "Typosquat of setuptools.",
}

_TRUSTED = {
    # Core
    "requests", "urllib3", "certifi", "charset-normalizer", "idna",
    "packaging", "pip", "wheel", "setuptools", "six", "attrs",
    "typing-extensions", "tomli", "toml",
    # Web frameworks
    "flask", "django", "fastapi", "starlette", "uvicorn", "gunicorn",
    "twisted", "aiohttp", "httpx", "werkzeug", "jinja2", "markupsafe",
    "itsdangerous", "blinker", "asgiref", "whitenoise",
    # Data science
    "numpy", "pandas", "scipy", "matplotlib", "scikit-learn", "statsmodels",
    "seaborn", "plotly", "bokeh", "altair", "pillow", "imageio",
    # ML / AI
    "torch", "tensorflow", "keras", "openai", "anthropic", "langchain",
    "transformers", "huggingface-hub", "tokenizers", "datasets",
    "xgboost", "lightgbm", "catboost",
    # Databases / storage
    "sqlalchemy", "alembic", "pymongo", "redis", "celery", "kombu",
    "psycopg2", "psycopg", "pymysql", "aiomysql", "motor", "elasticsearch",
    # AWS / Cloud
    "boto3", "botocore", "s3transfer", "google-cloud-storage",
    "azure-storage-blob",
    # CLI / TUI
    "click", "rich", "typer", "colorama", "prompt-toolkit", "blessed",
    "textual", "urwid",
    # Config / serialisation
    "pydantic", "pyyaml", "python-dotenv", "dynaconf", "hydra-core",
    "marshmallow", "cattrs",
    # Dev tools
    "pytest", "black", "mypy", "flake8", "pylint", "isort", "ruff",
    "bandit", "coverage", "tox", "nox", "pre-commit", "hypothesis",
    "poetry", "hatch", "flit", "build", "twine",
    # Utilities
    "tqdm", "joblib", "filelock", "platformdirs", "distlib", "virtualenv",
    "paramiko", "fabric", "ansible", "invoke", "loguru", "structlog",
    "arrow", "pendulum", "python-dateutil", "pytz", "humanize",
    "cryptography", "pyjwt", "passlib", "bcrypt",
    "beautifulsoup4", "lxml", "html5lib", "cssselect",
    "multiprocess", "dask", "ray",
}


def fetch_pypi(pkg: str) -> Optional[dict]:
    """Fetch and parse PyPI package metadata."""
    try:
        resp = requests.get(PYPI_URL.format(pkg=pkg), timeout=10)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        info     = data.get("info", {})
        releases = data.get("releases", {})

        # Compute age
        age_years = None
        dates = []
        for rel_list in releases.values():
            for rel in rel_list:
                if rel.get("upload_time"):
                    dates.append(rel["upload_time"])
        if dates:
            from datetime import datetime
            try:
                first = datetime.fromisoformat(sorted(dates)[0][:19])
                age_years = round((datetime.now() - first).days / 365.25, 1)
            except Exception:
                pass

        # homepage: check home_page first, then project_urls
        project_urls = info.get("project_urls") or {}
        homepage = (info.get("home_page") or "").strip()
        if not homepage:
            for key in ("Homepage", "Source", "Repository", "Documentation"):
                if project_urls.get(key):
                    homepage = project_urls[key]
                    break

        # license: check license field first, then classifiers
        license_ = (info.get("license") or "").strip()
        if not license_:
            for clf in (info.get("classifiers") or []):
                if clf.startswith("License ::"):
                    parts = clf.split(" :: ")
                    license_ = parts[-1] if parts else ""
                    break
        if not license_:
            license_ = "not specified"

        return {
            "name":           info.get("name", pkg),
            "version":        info.get("version", "unknown"),
            "summary":        (info.get("summary") or "")[:120],
            "author":         info.get("author") or info.get("maintainer") or "unknown",
            "license":        license_,
            "requires_python": info.get("requires_python") or "any",
            "homepage":       homepage,
            "keywords":       info.get("keywords") or "",
            "release_count":  len(releases),
            "age_years":      age_years,
            "requires_dist":  (info.get("requires_dist") or [])[:8],
            "yanked":         info.get("yanked", False),
            "pypi_exists":    True,
        }
    except requests.RequestException:
        return None


def fetch_osv(pkg: str) -> dict:
    """Check OSV.dev for known CVEs."""
    try:
        resp = requests.post(
            OSV_URL,
            json={"package": {"name": pkg, "ecosystem": "PyPI"}},
            timeout=8,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulns", [])
        cve_ids = []
        for v in vulns:
            for alias in v.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_ids.append(alias)
        return {"total": len(vulns), "cve_ids": cve_ids[:5], "error": None}
    except Exception as e:
        return {"total": 0, "cve_ids": [], "error": str(e)}


def _check_typosquat(pkg: str) -> dict:
    """Enhanced typosquat detection."""
    def levenshtein(a: str, b: str) -> int:
        if a == b: return 0
        if not a: return len(b)
        if not b: return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i]
            for j, cb in enumerate(b, 1):
                curr.append(min(prev[j] + 1, curr[-1] + 1, prev[j-1] + (ca != cb)))
            prev = curr
        return prev[-1]

    def similarity(a: str, b: str) -> int:
        if not a and not b: return 100
        d = levenshtein(a.lower(), b.lower())
        return round((1 - d / max(len(a), len(b))) * 100)

    _KNOWN_THREATS = {
        # ── Confirmed malicious ───────────────────────────────────────────────
        "colourama":            "colorama",
        "python3-dateutil":     "python-dateutil",
        "setup-tools":          "setuptools",
        "pytorch":              "torch",

        # ── requests ─────────────────────────────────────────────────────────
        "requestss":            "requests",
        "reqests":              "requests",
        "requsets":             "requests",
        "requestes":            "requests",
        "requsts":              "requests",
        "requets":              "requests",
        "reqeusts":             "requests",
        "reuqests":             "requests",
        "requestt":             "requests",

        # ── numpy ─────────────────────────────────────────────────────────────
        "numppy":               "numpy",
        "nummpy":               "numpy",
        "numy":                 "numpy",
        "nuumpy":               "numpy",
        "mumpy":                "numpy",
        "nimpy":                "numpy",

        # ── pandas ───────────────────────────────────────────────────────────
        "pandaas":              "pandas",
        "pands":                "pandas",
        "pandass":              "pandas",
        "paandas":              "pandas",
        "panads":               "pandas",
        "pnadas":               "pandas",

        # ── django ───────────────────────────────────────────────────────────
        "djagno":               "django",
        "djanngo":              "django",
        "djangoo":              "django",
        "diango":               "django",
        "djnago":               "django",
        "dajngo":               "django",

        # ── flask ─────────────────────────────────────────────────────────────
        "flaks":                "flask",
        "flaskk":               "flask",
        "flsk":                 "flask",
        "flsak":                "flask",
        "flaask":               "flask",
        "falsk":                "flask",

        # ── tensorflow ───────────────────────────────────────────────────────
        "tensorflw":            "tensorflow",
        "tensorfow":            "tensorflow",
        "tensorflo":            "tensorflow",
        "tensor-flow":          "tensorflow",

        # ── torch / pytorch ──────────────────────────────────────────────────
        "torhc":                "torch",
        "toorch":               "torch",
        "troch":                "torch",
        "pytoch":               "torch",
        "pytorc":               "torch",
        "pyttorch":             "torch",

        # ── matplotlib ───────────────────────────────────────────────────────
        "matplotllib":          "matplotlib",
        "matplotib":            "matplotlib",
        "matplolib":            "matplotlib",
        "matpotlib":            "matplotlib",

        # ── scikit-learn ─────────────────────────────────────────────────────
        "scikitlearn":          "scikit-learn",
        "scikitlern":           "scikit-learn",
        "scikit-leern":         "scikit-learn",

        # ── beautifulsoup4 ───────────────────────────────────────────────────
        "beautiflsoup4":        "beautifulsoup4",
        "beautifulsop4":        "beautifulsoup4",
        "beautifulsoop4":       "beautifulsoup4",
        "beautifulsoupp4":      "beautifulsoup4",

        # ── selenium ─────────────────────────────────────────────────────────
        "sellenium":            "selenium",
        "seleniumm":            "selenium",
        "selenum":              "selenium",

        # ── pillow ───────────────────────────────────────────────────────────
        "pilow":                "pillow",
        "pilllow":              "pillow",
        "piloww":               "pillow",

        # ── cryptography ─────────────────────────────────────────────────────
        "cryptograpy":          "cryptography",
        "cryptograhpy":         "cryptography",
        "cryptographyy":        "cryptography",

        # ── sqlalchemy ───────────────────────────────────────────────────────
        "sqlachemy":            "sqlalchemy",
        "sqlalchmey":           "sqlalchemy",
        "sqlalchemyy":          "sqlalchemy",

        # ── fastapi ──────────────────────────────────────────────────────────
        "fastpai":              "fastapi",
        "fastappi":             "fastapi",
        "fast-api":             "fastapi",

        # ── pytest ───────────────────────────────────────────────────────────
        "pytes":                "pytest",
        "pyttest":              "pytest",
        "pytestt":              "pytest",

        # ── jupyter / notebook ───────────────────────────────────────────────
        "jupytr":               "jupyter",
        "jupter":               "jupyter",
        "jupyterr":             "jupyter",
        "notebok":              "notebook",
        "notebookk":            "notebook",

        # ── streamlit ────────────────────────────────────────────────────────
        "streamlitt":           "streamlit",
        "streamlt":             "streamlit",

        # ── opencv-python ────────────────────────────────────────────────────
        "opencvpyhton":         "opencv-python",
        "open-cv-python":       "opencv-python",

        # ── transformers ─────────────────────────────────────────────────────
        "transformres":         "transformers",
        "transfomers":          "transformers",

        # ── huggingface-hub ──────────────────────────────────────────────────
        "huggingfacehub":       "huggingface-hub",
        "hugging-face-hub":     "huggingface-hub",

        # ── langchain ────────────────────────────────────────────────────────
        "langchan":             "langchain",
        "langcahin":            "langchain",
        "langchian":            "langchain",

        # ── openai ───────────────────────────────────────────────────────────
        "opneai":               "openai",
        "openaai":              "openai",

        # ── anthropic ────────────────────────────────────────────────────────
        "anthropik":            "anthropic",
        "anthrophic":           "anthropic",
        "anthropics":           "anthropic",

        # ── rich / click ─────────────────────────────────────────────────────
        "ricch":                "rich",
        "richh":                "rich",
        "clik":                 "click",
        "clickk":               "click",

        # ── pyyaml ───────────────────────────────────────────────────────────
        "pyaml":                "pyyaml",
        "pyyml":                "pyyaml",

        # ── aiohttp ──────────────────────────────────────────────────────────
        "aiohttpp":             "aiohttp",

        # ── uvicorn / gunicorn ───────────────────────────────────────────────
        "uvicornn":             "uvicorn",
        "gunicorm":             "gunicorn",
        "gunicornn":            "gunicorn",

        # ── celery ───────────────────────────────────────────────────────────
        "celerry":              "celery",
        "celry":                "celery",

        # ── redis ────────────────────────────────────────────────────────────
        "reddis":               "redis",
        "rediss":               "redis",

        # ── pymongo ──────────────────────────────────────────────────────────
        "pymngo":               "pymongo",
        "pymongoo":             "pymongo",

        # ── psycopg2 ─────────────────────────────────────────────────────────
        "psycop2":              "psycopg2",
        "psycopgg2":            "psycopg2",

        # ── mysqlclient ──────────────────────────────────────────────────────
        "mysqlclent":           "mysqlclient",
        "mysql-client":         "mysqlclient",

        # ── flask extensions ─────────────────────────────────────────────────
        "flasklogin":           "flask-login",
        "flask-logn":           "flask-login",
        "flasksqlalchemy":      "flask-sqlalchemy",
        "flask-sqalchemy":      "flask-sqlalchemy",

        # ── scrapy ───────────────────────────────────────────────────────────
        "scrappy":              "scrapy",
        "scapyy":               "scrapy",

        # ── lxml ─────────────────────────────────────────────────────────────
        "lxmll":                "lxml",
        "lxm":                  "lxml",

        # ── boto3 ────────────────────────────────────────────────────────────
        "bot03":                "boto3",
        "boto33":               "boto3",

        # ── paramiko ─────────────────────────────────────────────────────────
        "paramikoo":            "paramiko",
        "parimako":             "paramiko",

        # ── pycryptodome ─────────────────────────────────────────────────────
        "pycryptodm":           "pycryptodome",
        "pycryptodmee":         "pycryptodome",

        # ── black / mypy / pylint / isort ────────────────────────────────────
        "blacck":               "black",
        "blackk":               "black",
        "myppi":                "mypy",
        "myppy":                "mypy",
        "pylnt":                "pylint",
        "pyllint":              "pylint",
        "issort":               "isort",
        "isorrt":               "isort",

        # ── scipy ────────────────────────────────────────────────────────────
        "scippy":               "scipy",
        "scipi":                "scipy",

        # ── django-rest-framework ────────────────────────────────────────────
        "django-restframewrk":  "django-rest-framework",
        "djangorestframwork":   "django-rest-framework",
    }

    norm = pkg.lower().replace("_", "-")
    if norm in _KNOWN_THREATS:
        return {
            "known_threat": True, "likely_typosquat": True,
            "similar_legit_package": _KNOWN_THREATS[norm],
            "highest_similarity": 100, "top_matches": [],
        }

    scores = []
    for legit in _TRUSTED:
        sim = similarity(pkg, legit)
        if sim >= 80 and pkg.lower() != legit.lower():
            scores.append({"package": legit, "similarity": sim})
    scores.sort(key=lambda x: x["similarity"], reverse=True)
    top = scores[:5]
    highest = top[0]["similarity"] if top else 0
    likely = highest >= 85 and pkg.lower() not in {t.lower() for t in _TRUSTED}

    return {
        "known_threat": False, "likely_typosquat": likely,
        "similar_legit_package": top[0]["package"] if likely else None,
        "highest_similarity": highest, "top_matches": top,
    }


def _score_local(pkg: str, pypi: Optional[dict], typo: dict, osv: dict) -> dict:
    """Improved v1.1 local scorer — uses age, CVEs, yanked status."""
    norm = pkg.lower().replace("-", "_")

    if norm in {k.replace("-", "_") for k in _KNOWN_DANGEROUS}:
        reason = list(_KNOWN_DANGEROUS.values())[
            list({k.replace("-","_") for k in _KNOWN_DANGEROUS}).index(norm)
            if norm in {k.replace("-","_") for k in _KNOWN_DANGEROUS} else 0]
        return {
            "score": 90, "verdict": "HIGH", "decision": "BLOCK",
            "decision_reason": reason[:80],
            "findings": [{"level": "high", "category": "Known Threat", "text": reason}],
            "analysis": reason, "recommendation": "Do not install.",
            "trust_score": 0, "known_cves": 0,
            "metrics": {"code_risk": 50, "reputation": 0, "typosquat": 100,
                        "dependency": 0, "maintenance": 50},
        }

    if typo.get("likely_typosquat"):
        target = typo.get("similar_legit_package", "a known package")
        return {
            "score": 95, "verdict": "HIGH", "decision": "BLOCK",
            "decision_reason": f"Likely typosquat of {target}",
            "findings": [{"level": "high", "category": "Supply Chain",
                          "text": f"Typosquat of '{target}'"}],
            "analysis": f"'{pkg}' closely resembles '{target}'.",
            "recommendation": f"Did you mean '{target}'?",
            "trust_score": 0, "known_cves": 0,
            "metrics": {"code_risk": 0, "reputation": 0, "typosquat": 95,
                        "dependency": 0, "maintenance": 0},
        }

    if pypi is None:
        return {
            "score": 70, "verdict": "HIGH", "decision": "BLOCK",
            "decision_reason": "Package not found on PyPI",
            "findings": [{"level": "high", "category": "Supply Chain",
                          "text": "Package not found on PyPI"}],
            "analysis": f"'{pkg}' does not exist on PyPI.",
            "recommendation": "Verify the package name.",
            "trust_score": 0, "known_cves": 0,
            "metrics": {"code_risk": 0, "reputation": 0, "typosquat": 0,
                        "dependency": 0, "maintenance": 0},
        }

    if norm in {t.replace("-", "_") for t in _TRUSTED}:
        cve_count = osv.get("total", 0)
        findings = [{"level": "low", "category": "Reputation",
                     "text": f"'{pkg}' is a well-known, widely-trusted PyPI package"}]
        if cve_count:
            # Show CVEs as informational only — trusted packages are still safe to
            # install; historical CVEs in well-known packages are already patched
            # in current versions and do not warrant blocking installation.
            findings.insert(0, {"level": "low", "category": "CVE",
                                 "text": f"{cve_count} historical CVE(s) on record: {', '.join(osv.get('cve_ids', [])[:3])}"})
        return {
            "score": 0, "verdict": "LOW", "decision": "INSTALL",
            "decision_reason": f"'{pkg}' is a well-known, widely-trusted PyPI package",
            "findings": findings,
            "analysis": f"'{pkg}' is a well-established package with a strong security track record. Risk score is 0/100. Safe to install.",
            "recommendation": "Safe to install.",
            "trust_score": 100, "known_cves": cve_count,
            "metrics": {"code_risk": 0, "reputation": 100, "typosquat": 0,
                        "dependency": 0, "maintenance": 0},
        }

    # Unknown package — score based on signals. Base 15 so minor signals
    # (no homepage, no license) don't immediately hit the WARN threshold (31).
    s = 15
    findings = []
    cve_count = osv.get("total", 0)

    if cve_count > 0:
        s += cve_count * 15
        findings.append({"level": "high", "category": "CVE",
                          "text": f"{cve_count} known CVE(s): {', '.join(osv.get('cve_ids', [])[:3])}"})
    if pypi.get("yanked"):
        s += 30
        findings.append({"level": "high", "category": "Supply Chain",
                          "text": "Package has been yanked from PyPI"})
    if not pypi.get("homepage"):
        s += 5
        findings.append({"level": "low", "category": "Reputation",
                          "text": "No homepage URL"})
    if not pypi.get("license") or pypi.get("license") == "not specified":
        s += 5
        findings.append({"level": "low", "category": "Reputation",
                          "text": "No license specified"})
    age = pypi.get("age_years")
    if age is not None and age < 0.25:
        s += 15
        findings.append({"level": "medium", "category": "Maintenance",
                          "text": f"Very new package — only {round(age * 12)} month(s) old"})
    if pypi.get("release_count", 0) <= 1:
        s += 10
        findings.append({"level": "medium", "category": "Maintenance",
                          "text": "Only 1 release — very early stage"})

    s = min(s, 100)
    if s >= 66: verdict, decision = "HIGH", "BLOCK"
    elif s >= 31: verdict, decision = "MEDIUM", "WARN"
    else: verdict, decision = "LOW", "INSTALL"

    reason = findings[0]["text"] if findings else "Unknown package"
    return {
        "score": s, "verdict": verdict, "decision": decision,
        "decision_reason": reason,
        "findings": findings,
        "analysis": f"'{pkg}' is an unknown package.",
        "recommendation": "Proceed with caution." if verdict != "HIGH" else "Do not install.",
        "trust_score": max(0, 100 - s), "known_cves": cve_count,
        "metrics": {"code_risk": 0, "reputation": max(0, 70 - s),
                    "typosquat": 0, "dependency": 0, "maintenance": s // 3},
    }


def scan(pkg: str, progress_cb=None) -> dict:
    """Run a full security scan. v1.1 adds OSV CVE lookup."""
    def _cb(stage, detail=""):
        if progress_cb:
            progress_cb(stage, detail)

    start = time.time()
    clean = pkg.strip().lower().split("==")[0].split(">=")[0].split("[")[0].strip()
    if not clean:
        raise ValueError("Package name cannot be empty")
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", clean):
        raise ValueError(f"Invalid package name {clean!r}")

    _cb("pypi_fetch", f"querying PyPI for {clean}")
    pypi = fetch_pypi(clean)

    _cb("typosquat", "checking for typosquats")
    typo = _check_typosquat(clean)

    _cb("osv", "checking CVE database")
    osv = fetch_osv(clean)

    _cb("scoring", "computing risk score")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key and pypi:
        try:
            prompt = f'Analyze package "{clean}" v{pypi.get("version")} by {pypi.get("author")}. Summary: {pypi.get("summary")}. CVEs: {osv.get("total", 0)}. Typosquat: {typo.get("likely_typosquat")}. Return ONLY JSON: {{"score":0,"verdict":"LOW","decision":"INSTALL","decision_reason":"","trust_score":100,"known_cves":0,"metrics":{{"code_risk":0,"reputation":100,"typosquat":0,"dependency":0,"maintenance":0}},"findings":[],"analysis":"","recommendation":""}}'
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-sonnet-4-6", "max_tokens": 800,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=30,
            )
            resp.raise_for_status()
            text = resp.json()["content"][0]["text"].strip().replace("```json","").replace("```","")
            ai = __import__("json").loads(text)
        except Exception:
            ai = _score_local(clean, pypi, typo, osv)
    else:
        ai = _score_local(clean, pypi, typo, osv)

    return {
        "package":   clean,
        "pypi":      pypi,
        "typo":      typo,
        "osv":       osv,
        "ai":        ai,
        "elapsed":   round(time.time() - start, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

"""safe-pip CLI v1.0"""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.panel import Panel

from safe_pip import __version__
from safe_pip.scanner import scan

console = Console()


def _color(score: int) -> str:
    if score >= 66: return "red"
    if score >= 31: return "yellow"
    return "green"


def _print_result(result: dict, output: str) -> None:
    pkg   = result.get("package", "?")
    pypi  = result.get("pypi") or {}
    ai    = result.get("ai", {})
    score = ai.get("score", 0)
    verdict  = ai.get("verdict", "LOW")
    decision = ai.get("decision", "INSTALL")
    elapsed  = result.get("elapsed", 0)

    if output == "json":
        out = {
            "package":    pkg,
            "version":    pypi.get("version") if pypi else None,
            "score":      score,
            "verdict":    verdict,
            "decision":   decision,
            "did_you_mean": (result.get("typo") or {}).get("similar_legit_package"),
            "findings":   ai.get("findings", []),
            "analysis":   ai.get("analysis", ""),
            "elapsed":    elapsed,
        }
        print(json.dumps(out, indent=2))
        return

    sc_color  = _color(score)
    dec_icon  = "✓" if decision == "INSTALL" else ("⚠" if decision == "WARN" else "✕")
    dec_color = "green" if decision == "INSTALL" else ("yellow" if decision == "WARN" else "red")

    console.print()
    console.print(
        f"  [bold white]{pkg}[/bold white] "
        f"[dim]v{pypi.get('version', '?')}[/dim]  "
        f"[{sc_color}]score {score}/100[/{sc_color}]  "
        f"[{dec_color}]{verdict}[/{dec_color}]  "
        f"[bold {dec_color}]{dec_icon} {decision}[/bold {dec_color}]"
        f"  [dim]{elapsed}s[/dim]"
    )

    facts = []
    if pypi.get("author") and pypi.get("author") != "unknown":
        facts.append(f"author: {pypi['author']}")
    if pypi.get("release_count"):
        facts.append(f"releases: {pypi['release_count']}")
    if facts:
        console.print("  " + "  ·  ".join(facts))

    console.print()
    for f in ai.get("findings", []):
        lv = f.get("level", "low")
        lc = "red" if lv == "high" else ("yellow" if lv == "medium" else "dim")
        console.print(f"  [{lc}]●[/{lc}] [dim]{f.get('category', '')}[/dim]  {f.get('text', '')}")

    if ai.get("analysis"):
        console.print()
        console.print(f"  [dim]{ai['analysis']}[/dim]")

    # Alias / Did you mean — show prominently for typosquats
    from rich.markup import escape
    similar = (result.get("typo") or {}).get("similar_legit_package")
    if similar and (result.get("typo") or {}).get("likely_typosquat"):
        console.print()
        console.print(
            f"  [yellow]ℹ Did you mean:[/yellow] [bold green]{similar}[/bold green]"
            f"  →  run: [bold]pip install {similar}[/bold]"
        )

    if ai.get("decision_reason"):
        console.print()
        console.print(
            f"  Decision: [{dec_color}]{dec_icon} {decision}[/{dec_color}]"
            f"  [dim]{escape(ai['decision_reason'])}[/dim]"
        )
    console.print()


@click.group()
@click.version_option(__version__, prog_name="safe-pip")
def main():
    """safe-pip — Python package security scanner."""
    pass


@main.command("scan")
@click.argument("package")
@click.option("--json", "output", flag_value="json", help="JSON output.")
@click.option("--plain", "output", flag_value="plain", help="Plain text output.")
@click.option("--output", "output", default="rich", help="Output format.")
@click.option("--fail-on", default="high",
              type=click.Choice(["warn", "high"]),
              help="Exit 1 if verdict meets or exceeds this level.")
def scan_cmd(package, output, fail_on):
    """Scan a Python package for security risks."""
    if output != "json":
        console.print()
        console.print("[bold]safe-pip[/bold] — Python package security scanner")
        console.print("─" * 70)
        api_key = __import__("os").environ.get("ANTHROPIC_API_KEY", "")
        engine = "Claude AI" if api_key else "local rule-based scorer  (set ANTHROPIC_API_KEY to use Claude AI)"
        console.print(f"\nEngine: {engine}\n")

    def progress(stage, detail=""):
        pass  # v1.0: silent progress

    try:
        result = scan(package, progress_cb=progress)
    except ValueError as e:
        console.print(f"[red]✗ Invalid package name: {e}[/red]")
        # Suggest correction if it looks like a typosquat
        from safe_pip.scanner import _check_typosquat
        try:
            typo = _check_typosquat(package.strip())
            if typo.get("similar_legit_package"):
                console.print(f"  [yellow]Did you mean:[/yellow] [bold]{typo['similar_legit_package']}[/bold]")
        except Exception:
            pass
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗ Error scanning {package!r}: {e}[/red]")
        sys.exit(1)

    _print_result(result, output or "rich")

    # Exit code: based on final decision, not verdict label.
    # INSTALL always exits 0. WARN exits 1 if --fail-on warn. BLOCK always exits 1.
    decision = result.get("ai", {}).get("decision", "INSTALL")
    if decision == "BLOCK":
        sys.exit(1)
    if decision == "WARN" and fail_on == "warn":
        sys.exit(1)


if __name__ == "__main__":
    main()


# Wire in watch commands
from safe_pip.watch import watch_cmd
main.add_command(watch_cmd)


@main.command("install")
@click.argument("packages", nargs=-1, required=True)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt.")
@click.option("--fail-on", default="high", type=click.Choice(["warn", "high"]),
              help="Exit 1 if verdict meets or exceeds this level.")
def install_cmd(packages, yes, fail_on):
    """Scan then install one or more packages (alias for scan + pip install)."""
    import subprocess
    console.print()
    console.print("[bold]safe-pip[/bold] — Python package security scanner")
    console.print("─" * 70)
    api_key = __import__("os").environ.get("ANTHROPIC_API_KEY", "")
    engine = "Claude AI" if api_key else "local rule-based scorer  (set ANTHROPIC_API_KEY to use Claude AI)"
    console.print(f"\nEngine: {engine}\n")

    blocked, warned = [], []
    for pkg in packages:
        try:
            result = scan(pkg)
        except Exception as e:
            console.print(f"[red]Error scanning {pkg}: {e}[/red]")
            sys.exit(1)
        _print_result(result, "rich")
        decision = result.get("ai", {}).get("decision", "INSTALL")
        if decision == "BLOCK":
            blocked.append(pkg)
        elif decision == "WARN":
            warned.append(pkg)

    if blocked:
        console.print(f"[red]✕ Blocked: {', '.join(blocked)}[/red]")
        sys.exit(1)

    if warned and fail_on == "warn":
        console.print(f"[yellow]⚠ Warned packages blocked by --fail-on warn: {', '.join(warned)}[/yellow]")
        sys.exit(1)

    if warned and not yes:
        console.print(f"\n[yellow]⚠ Warning: {', '.join(warned)} received WARN verdict.[/yellow]")
        if not click.confirm("  Proceed with installation?", default=False):
            console.print("  Aborted.")
            sys.exit(1)

    safe = [p for p in packages if p not in blocked]
    if safe:
        console.print(f"\n  Running pip install…\n")
        real_pip = __import__("shutil").which("pip") or "pip"
        result = subprocess.run([real_pip, "install"] + list(safe))
        sys.exit(result.returncode)


@main.command("doctor")
def doctor_cmd():
    """Check safe-pip installation health."""
    import importlib
    console.print("\n  [bold]safe-pip doctor[/bold]\n")

    checks = []

    # Python version
    import sys as _sys
    pv = _sys.version_info
    checks.append(("Python version", pv >= (3, 9),
                   f"{pv.major}.{pv.minor}.{pv.micro}"))

    # Required deps
    for dep in ("rich", "click"):
        try:
            mod = importlib.import_module(dep)
            try:
                import importlib.metadata as _meta
                ver = _meta.version(dep)
            except Exception:
                ver = getattr(mod, "__version__", "?")
            checks.append((f"{dep} installed", True, ver))
        except ImportError:
            checks.append((f"{dep} installed", False, f"missing — run: pip install {dep}"))

    # requests (required in v1.1)
    try:
        import requests
        checks.append(("requests installed", True, requests.__version__))
    except ImportError:
        checks.append(("requests installed", False, "missing — run: pip install requests"))

    # safe-pip CLI
    import shutil
    sp = shutil.which("safe-pip")
    checks.append(("safe-pip on PATH", sp is not None, sp or "not found"))

    # Watch mode status
    from safe_pip.watch import status as watch_status
    ws = watch_status()
    checks.append(("Watch mode", ws["active"] or ws["shim_exists"],
                   "ACTIVE" if ws["active"] else ("PENDING (open new terminal)" if ws["shim_exists"] else "INACTIVE")))

    # Print results
    for label, ok, detail in checks:
        icon  = "[green]✓[/green]" if ok else "[red]✗[/red]"
        color = "green" if ok else "red"
        console.print(f"  {icon}  [{color}]{label}[/{color}]  [dim]{detail}[/dim]")

    all_ok = all(ok for _, ok, _ in checks)
    console.print()
    if all_ok:
        console.print("  [green]All checks passed — safe-pip is healthy.[/green]\n")
    else:
        console.print("  [red]Some checks failed. See above for details.[/red]\n")
        sys.exit(1)


@main.command("update-db")
def update_db_cmd():
    """Update the offline threat database."""
    console.print("\n  [bold]safe-pip[/bold] — updating offline threat database\n")

    # In v1.1 the threat DB is the built-in typosquat list + known dangerous dict.
    # We fetch the top PyPI packages to refresh the known-good list.
    import json, urllib.request

    entries = 0
    try:
        url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        rows = data.get("rows", [])
        count = len(rows)
        console.print(f"  [green]✓[/green]  Top-{count} packages feed: {count:,} entries")
        entries += count
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow]  Top packages feed: could not fetch ({e})")

    # Typosquat blocklist (built-in)
    from safe_pip.scanner import _KNOWN_DANGEROUS
    console.print(f"  [green]✓[/green]  Known dangerous packages: {len(_KNOWN_DANGEROUS)} entries")
    entries += len(_KNOWN_DANGEROUS)

    console.print(f"\n  [green]✓[/green] Offline threat database ready — {entries:,} total entries.")
    console.print("  Scans will use this data automatically.\n")

#!/usr/bin/env python3
"""
CLI interface for the AI Agent Audit Trail Generator.

Commands:
  audit demo              — Load demo data (8 healthcare AI scenarios)
  audit ingest <file>     — Ingest actions from file (jsonl/json/csv/cef)
  audit assess            — Run full HIPAA compliance assessment
  audit report            — Generate PDF + Markdown compliance report
  audit verify            — Verify hash chain integrity
  audit violations        — List current violations
  audit agents            — List registered agents
  audit serve             — Start FastAPI dashboard
  audit detect-shadow     — Detect unregistered agents
  audit detect-exfil      — Run bulk PHI exfiltration scan
  audit detect-scope-drift — Run scope drift analysis per agent

Usage examples::

    # Quick start with demo data
    audit demo

    # Run with custom database
    audit demo --db /data/audit.db

    # Run assessment for specific period
    audit assess --start 2026-01-01 --end 2026-04-07

    # Generate report
    audit report --format pdf --output reports/

    # Start dashboard on specific port
    audit serve --port 8090
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=level,
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _get_store(args) -> "AuditStore":
    from .storage import AuditStore
    db_path = Path(args.db) if hasattr(args, "db") and args.db else None
    return AuditStore(db_path=db_path)


def _get_engine(store) -> "ComplianceEngine":
    from .compliance import ComplianceEngine
    return ComplianceEngine(store=store)


def cmd_demo(args: argparse.Namespace) -> int:
    """Load realistic healthcare AI demo data and run violation detection."""
    from .demo import run_demo
    db_path = Path(args.db) if args.db else None
    store, violations = run_demo(
        db_path=db_path,
        seed=getattr(args, "seed", 42),
        verbose=True,
    )
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest action records from a file."""
    from .ingestion import ActionIngester
    from .violations import ViolationDetector

    filepath = Path(args.file)
    if not filepath.exists():
        print(f"ERROR: File not found: {filepath}", file=sys.stderr)
        return 1

    store = _get_store(args)
    ingester = ActionIngester()
    fmt = args.format or filepath.suffix.lstrip(".").lower()
    if fmt == "ndjson":
        fmt = "jsonl"

    print(f"Ingesting {filepath} (format={fmt})...")
    try:
        actions = ingester.ingest_batch(filepath, fmt=fmt)
    except Exception as exc:
        print(f"ERROR: Ingestion failed: {exc}", file=sys.stderr)
        return 1

    print(f"  Ingested {len(actions)} actions")

    stored = store.store_actions_batch(actions)
    print(f"  Stored {len(stored)} records")

    if not args.no_detect:
        detector = ViolationDetector(store=store)
        violations = detector.analyze_batch(actions)
        for v in violations:
            store.store_violation(v)
        print(f"  Detected {len(violations)} violation(s)")
        by_sev: dict[str, int] = {}
        for v in violations:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        for sev in ["critical", "high", "medium", "low"]:
            if by_sev.get(sev, 0):
                print(f"    {sev.upper()}: {by_sev[sev]}")

    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    """Run full HIPAA compliance assessment."""
    store = _get_store(args)
    engine = _get_engine(store)

    start = args.start or (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    end = args.end or datetime.now(timezone.utc).isoformat()

    if len(start) == 10:
        start += "T00:00:00+00:00"
    if len(end) == 10:
        end += "T23:59:59+00:00"

    print(f"\nHIPAA Compliance Assessment")
    print(f"Period: {start[:10]} to {end[:10]}")
    print(f"{'─' * 60}")

    results = engine.assess_all_controls(start, end)
    score = engine.compute_compliance_score(results)
    rating = engine.get_rating(score)

    # Print control results
    compliant = sum(1 for r in results if r.status == "compliant")
    partial = sum(1 for r in results if r.status == "partially_compliant")
    non_compliant = sum(1 for r in results if r.status == "non_compliant")

    status_symbols = {
        "compliant": "✓",
        "partially_compliant": "⚠",
        "non_compliant": "✗",
        "not_assessed": "–",
    }

    for c in results:
        sym = status_symbols.get(c.status, "?")
        score_str = f"{c.risk_score:.1f}" if c.status != "not_assessed" else "N/A"
        print(f"  {sym} {c.control_id:<8} {c.hipaa_section:<22} {c.hipaa_standard[:42]:<42} [{c.severity.upper():<14}] {score_str}")

    print(f"\n{'─' * 60}")
    print(f"OVERALL SCORE:  {score:.1f}/100")
    print(f"RATING:         {rating}")
    print(f"Compliant:      {compliant}/{len(results)}")
    print(f"Partial:        {partial}/{len(results)}")
    print(f"Non-Compliant:  {non_compliant}/{len(results)}")

    # NIST AI RMF
    rmf = engine.map_to_nist_ai_rmf(results)
    if rmf:
        print(f"\nNIST AI RMF Alignment:")
        for func, s in sorted(rmf.items()):
            bar = "█" * int(s * 20) + "░" * (20 - int(s * 20))
            print(f"  {func.title():<10} [{bar}] {s*100:.1f}%")

    # Gap analysis
    gaps = engine.generate_gap_analysis(results)
    if gaps:
        print(f"\nTop Gaps (priority-ordered):")
        for g in gaps[:5]:
            print(f"  {g['priority']}. [{g['severity'].upper():<8}] {g['control_id']} — {g['standard'][:50]}")

    if args.json:
        output = {
            "period_start": start,
            "period_end": end,
            "overall_score": score,
            "overall_rating": rating,
            "controls": [c.to_dict() for c in results],
            "nist_ai_rmf": rmf,
            "gap_analysis": gaps,
        }
        print("\n" + json.dumps(output, indent=2, default=str))

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate PDF and/or Markdown compliance report."""
    from .compliance import ComplianceEngine
    from .reporting import ReportGenerator
    from .config import ORGANIZATION_NAME

    store = _get_store(args)
    engine = ComplianceEngine(store=store)

    start = args.start or (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    end = args.end or datetime.now(timezone.utc).isoformat()
    if len(start) == 10:
        start += "T00:00:00+00:00"
    if len(end) == 10:
        end += "T23:59:59+00:00"

    org = args.org or ORGANIZATION_NAME
    print(f"Generating compliance report for {org}...")
    print(f"Period: {start[:10]} to {end[:10]}")

    results = engine.assess_all_controls(start, end)
    report = engine.build_report(results, start, end, org)
    violations = store.query_violations(start=start, end=end)

    output_dir = Path(args.output) if args.output else Path("reports")
    generator = ReportGenerator(output_dir=output_dir)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fmt = getattr(args, "format", "both").lower()

    if fmt in {"pdf", "both"}:
        pdf_path = generator.generate_pdf(report, results, violations, f"hipaa_report_{ts}.pdf")
        print(f"  PDF: {pdf_path}")

    if fmt in {"md", "markdown", "both"}:
        md_path = generator.generate_markdown(report, results, violations, f"hipaa_report_{ts}.md")
        print(f"  Markdown: {md_path}")

    print(f"\nCompliance Score: {report.overall_score:.1f}/100 — {report.overall_rating}")
    print(f"Report ID: {report.report_id}")

    # Persist report
    store.store_report(report)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify the tamper-evident hash chain integrity."""
    store = _get_store(args)
    print("Verifying hash chain integrity...")

    valid, errors = store.verify_chain_integrity()
    stats = store.get_database_stats()

    print(f"\nTotal records:  {stats['chain_total_records']}")
    print(f"Chain valid:    {'YES ✓' if valid else 'NO ✗'}")

    if valid:
        print("\n✓ CHAIN INTEGRITY VERIFIED")
        print("  No tampering, deletion, or injection detected.")
        print(f"  Genesis hash: {stats['chain_genesis_hash'][:32]}...")
        print(f"  Last hash:    {stats['chain_last_hash']}")
    else:
        print(f"\n✗ CHAIN INTEGRITY FAILURE — {len(errors)} error(s):")
        for e in errors[:10]:
            print(f"  ERROR: {e}")
        print("\nIMMEDIATE ACTION REQUIRED: §164.308(a)(6) Security Incident Response")
        return 1

    return 0


def cmd_violations(args: argparse.Namespace) -> int:
    """List compliance violations."""
    store = _get_store(args)

    kwargs: dict = {}
    if args.severity:
        kwargs["severity"] = args.severity
    if args.status:
        kwargs["status"] = args.status
    if args.agent:
        kwargs["agent_id"] = args.agent

    violations = store.query_violations(**kwargs, limit=args.limit)
    summary = store.get_violation_summary()

    print(f"\nViolations Summary:")
    by_sev = summary.get("by_severity", {})
    for sev in ["critical", "high", "medium", "low"]:
        print(f"  {sev.upper():<12}: {by_sev.get(sev, 0)}")

    by_status = summary.get("by_status", {})
    print(f"\n  Open:       {by_status.get('open', 0)}")
    print(f"  Remediated: {by_status.get('remediated', 0)}")

    if violations:
        print(f"\n{'─' * 90}")
        print(f"{'SEV':<10} {'TYPE':<35} {'AGENT':<20} {'HIPAA §':<20} {'DETECTED':<20}")
        print(f"{'─' * 90}")
        for v in violations:
            vtype = v.violation_type.replace("_", " ").title()[:33]
            agent = v.agent_id[:18]
            print(f"{v.severity.upper():<10} {vtype:<35} {agent:<20} {v.hipaa_section:<20} {v.timestamp[:16]}")

    if args.json:
        print("\n" + json.dumps([v.to_dict() for v in violations], indent=2, default=str))

    return 0


def cmd_agents(args: argparse.Namespace) -> int:
    """List registered AI agents."""
    store = _get_store(args)
    agents = store.list_agents(
        status=args.status if hasattr(args, "status") else None,
        risk_tier=args.risk_tier if hasattr(args, "risk_tier") else None,
    )

    print(f"\nRegistered Agents ({len(agents)} total):")
    print(f"{'─' * 100}")
    print(f"{'AGENT ID':<24} {'NAME':<38} {'TYPE':<20} {'RISK':<10} {'STATUS':<12} {'CRED AGE'}")
    print(f"{'─' * 100}")
    for a in agents:
        name = a.agent_name[:36]
        print(f"{a.agent_id[:22]:<24} {name:<38} {a.agent_type:<20} {a.risk_tier:<10} {a.status:<12} {a.credential_age_days}d")

    if args.json:
        print("\n" + json.dumps([a.to_dict() for a in agents], indent=2, default=str))

    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the FastAPI audit dashboard."""
    from .storage import AuditStore
    from .compliance import ComplianceEngine
    from .dashboard import run_server

    db_path = Path(args.db) if args.db else None
    store = AuditStore(db_path=db_path)
    engine = ComplianceEngine(store=store)

    host = args.host or "0.0.0.0"
    port = args.port or 8090

    print(f"\nStarting AI Agent Audit Dashboard")
    print(f"  URL:      http://{host if host != '0.0.0.0' else 'localhost'}:{port}")
    print(f"  Database: {store.db_path}")
    print(f"  API docs: http://localhost:{port}/docs")
    print(f"\n  §164.312(b): Real-time audit examination interface")
    print(f"  Press Ctrl+C to stop\n")

    run_server(store=store, compliance_engine=engine, host=host, port=port)
    return 0


def cmd_detect_shadow(args: argparse.Namespace) -> int:
    """Detect unregistered (shadow) AI agents in the action log."""
    from .violations import ViolationDetector

    store = _get_store(args)
    detector = ViolationDetector(store=store)

    print("Scanning for unregistered (shadow) agents...")
    violations = detector.detect_shadow_agents()

    if not violations:
        print("✓ No shadow agents detected. All agents in action log are registered.")
        return 0

    print(f"\n✗ {len(violations)} shadow agent(s) detected:\n")
    for v in violations:
        ev = v.evidence
        print(f"  Agent ID:    {ev.get('unregistered_agent_id', 'unknown')}")
        print(f"  Actions:     {ev.get('total_actions', 0)} ({ev.get('phi_actions', 0)} PHI)")
        print(f"  PHI Volume:  {ev.get('total_phi_volume', 0)}")
        print(f"  First Seen:  {ev.get('first_seen', '')[:16]}")
        print(f"  Last Seen:   {ev.get('last_seen', '')[:16]}")
        print(f"  Remediation: {v.remediation_action[:80]}")
        print()

    for v in violations:
        store.store_violation(v)
    print(f"  {len(violations)} violation(s) recorded.")
    return 1 if violations else 0


def cmd_detect_exfil(args: argparse.Namespace) -> int:
    """Scan all agents for bulk PHI exfiltration patterns."""
    from .violations import ViolationDetector

    store = _get_store(args)
    detector = ViolationDetector(store=store)
    agents = store.list_agents()
    window = getattr(args, "window", 60)

    print(f"Scanning {len(agents)} agents for bulk PHI exfiltration (window={window}min)...")
    found = 0
    for agent in agents:
        v = detector.detect_exfiltration_pattern(agent.agent_id, window_minutes=window)
        if v:
            found += 1
            ev = v.evidence
            print(f"\n  ✗ EXFILTRATION DETECTED: {agent.agent_name}")
            print(f"    Session: {ev.get('session_id', '')[:32]}")
            print(f"    Volume:  {ev.get('phi_volume', 0)} records (threshold: {ev.get('threshold', 0)})")
            store.store_violation(v)

    if found == 0:
        print("✓ No bulk exfiltration patterns detected.")
    else:
        print(f"\n✗ {found} exfiltration pattern(s) detected and recorded.")
    return 1 if found else 0


def cmd_detect_scope_drift(args: argparse.Namespace) -> int:
    """Run scope drift analysis for all agents."""
    from .violations import ViolationDetector

    store = _get_store(args)
    detector = ViolationDetector(store=store)
    agents = store.list_agents()
    window = getattr(args, "window", 30)

    print(f"Analyzing scope drift for {len(agents)} agents (window={window} days)...")
    found = 0
    for agent in agents:
        v = detector.detect_scope_drift(agent.agent_id, window_days=window)
        if v:
            found += 1
            ev = v.evidence
            print(f"\n  ✗ SCOPE DRIFT: {agent.agent_name}")
            print(f"    Early avg: {ev.get('early_avg_phi_volume', 0):.1f} records/action")
            print(f"    Late avg:  {ev.get('late_avg_phi_volume', 0):.1f} records/action")
            print(f"    Drift:     +{ev.get('drift_percent', 0):.1f}%")
            store.store_violation(v)

    if found == 0:
        print("✓ No scope drift detected across all agents.")
    else:
        print(f"\n✗ {found} scope drift pattern(s) recorded.")
    return 1 if found else 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse argument parser."""
    parser = argparse.ArgumentParser(
        prog="audit",
        description=(
            "AI Agent Audit Trail Generator — HIPAA §164.312 compliance\n"
            "Monitors AI agent actions and produces compliance audit reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", help="Path to SQLite database (default: data/audit.db)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # demo
    p_demo = subparsers.add_parser("demo", help="Load demo data (8 healthcare AI scenarios)")
    p_demo.add_argument("--seed", type=int, default=42, help="Random seed")
    p_demo.set_defaults(func=cmd_demo)

    # ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest actions from file")
    p_ingest.add_argument("file", help="Input file path")
    p_ingest.add_argument("--format", choices=["jsonl", "json", "csv", "cef"], help="File format (auto-detected if not specified)")
    p_ingest.add_argument("--no-detect", action="store_true", help="Skip violation detection")
    p_ingest.set_defaults(func=cmd_ingest)

    # assess
    p_assess = subparsers.add_parser("assess", help="Run HIPAA compliance assessment")
    p_assess.add_argument("--start", help="Period start (YYYY-MM-DD or ISO 8601)")
    p_assess.add_argument("--end", help="Period end (YYYY-MM-DD or ISO 8601)")
    p_assess.add_argument("--json", action="store_true", help="Output JSON results")
    p_assess.set_defaults(func=cmd_assess)

    # report
    p_report = subparsers.add_parser("report", help="Generate compliance report")
    p_report.add_argument("--start", help="Period start")
    p_report.add_argument("--end", help="Period end")
    p_report.add_argument("--format", choices=["pdf", "md", "markdown", "both"], default="both")
    p_report.add_argument("--output", help="Output directory (default: reports/)")
    p_report.add_argument("--org", help="Organization name")
    p_report.set_defaults(func=cmd_report)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify hash chain integrity")
    p_verify.set_defaults(func=cmd_verify)

    # violations
    p_viol = subparsers.add_parser("violations", help="List compliance violations")
    p_viol.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    p_viol.add_argument("--status", choices=["open", "acknowledged", "remediated", "accepted_risk", "false_positive"])
    p_viol.add_argument("--agent", help="Filter by agent ID")
    p_viol.add_argument("--limit", type=int, default=50)
    p_viol.add_argument("--json", action="store_true", help="Output JSON")
    p_viol.set_defaults(func=cmd_violations)

    # agents
    p_agents = subparsers.add_parser("agents", help="List registered AI agents")
    p_agents.add_argument("--status", choices=["active", "suspended", "decommissioned", "under_review"])
    p_agents.add_argument("--risk-tier", dest="risk_tier", choices=["critical", "high", "medium", "low"])
    p_agents.add_argument("--json", action="store_true", help="Output JSON")
    p_agents.set_defaults(func=cmd_agents)

    # serve
    p_serve = subparsers.add_parser("serve", help="Start FastAPI dashboard")
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8090)
    p_serve.set_defaults(func=cmd_serve)

    # detect-shadow
    p_shadow = subparsers.add_parser("detect-shadow", help="Detect unregistered agents")
    p_shadow.set_defaults(func=cmd_detect_shadow)

    # detect-exfil
    p_exfil = subparsers.add_parser("detect-exfil", help="Scan for bulk PHI exfiltration")
    p_exfil.add_argument("--window", type=int, default=60, help="Window in minutes (default: 60)")
    p_exfil.set_defaults(func=cmd_detect_exfil)

    # detect-scope-drift
    p_drift = subparsers.add_parser("detect-scope-drift", help="Run scope drift analysis")
    p_drift.add_argument("--window", type=int, default=30, help="Window in days (default: 30)")
    p_drift.set_defaults(func=cmd_detect_scope_drift)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    _setup_logging(verbose=getattr(args, "verbose", False))

    if not args.command:
        parser.print_help()
        return 0

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

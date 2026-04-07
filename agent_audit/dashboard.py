#!/usr/bin/env python3
"""
FastAPI dashboard with dark-mode terminal UI.

Provides:
  - REST API endpoints for all audit data
  - Server-Sent Events (SSE) for real-time violation streaming
  - Dark-mode HTML dashboard rendered server-side via Jinja2
  - /health endpoint for operational monitoring

HIPAA grounding:
  §164.312(b) — Audit Controls: real-time examination of audit logs
  §164.308(a)(1) — Risk Analysis: continuous monitoring dashboard
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, AsyncGenerator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from .config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    ORGANIZATION_NAME,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dark-mode terminal HTML template (inline, no external files needed)
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>AI Agent Audit Trail | {{ org_name }}</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
      --green: #3fb950; --yellow: #d29922; --orange: #db6d28;
      --red: #f85149; --purple: #bc8cff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Consolas','Courier New',monospace; font-size: 13px; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 20px; display: flex; align-items: center; gap: 16px; }
    header h1 { font-size: 16px; color: var(--accent); letter-spacing: 0.05em; }
    header .badge { font-size: 10px; background: var(--border); padding: 2px 8px; border-radius: 12px; color: var(--muted); }
    .main { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 12px; padding: 16px; }
    .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px; }
    .card h2 { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 8px; }
    .metric { font-size: 28px; font-weight: bold; color: var(--text); }
    .metric.red { color: var(--red); }
    .metric.green { color: var(--green); }
    .metric.yellow { color: var(--yellow); }
    .metric.orange { color: var(--orange); }
    .sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
    .score-bar { height: 8px; background: var(--border); border-radius: 4px; margin-top: 8px; overflow: hidden; }
    .score-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .wide { grid-column: span 2; }
    .full { grid-column: span 4; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; padding: 6px 8px; border-bottom: 1px solid var(--border); text-align: left; }
    td { padding: 6px 8px; border-bottom: 1px solid #21262d; vertical-align: top; }
    tr:hover td { background: #1c2128; }
    .sev-critical { color: var(--red); font-weight: bold; }
    .sev-high { color: var(--orange); font-weight: bold; }
    .sev-medium { color: var(--yellow); }
    .sev-low { color: var(--green); }
    .status-compliant { color: var(--green); }
    .status-partial { color: var(--yellow); }
    .status-noncompliant { color: var(--red); }
    .status-open { color: var(--red); }
    .status-remediated { color: var(--green); }
    .tag { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 10px; background: var(--border); color: var(--muted); margin: 1px; }
    .tag.phi { background: #3d1f1f; color: var(--red); }
    .tag.op { background: #1f2d3d; color: var(--accent); }
    .live-feed { height: 220px; overflow-y: auto; font-size: 11px; }
    .live-feed .entry { padding: 4px 6px; border-bottom: 1px solid #21262d; display: flex; gap: 8px; }
    .live-feed .ts { color: var(--muted); white-space: nowrap; }
    .live-feed .msg { color: var(--text); }
    .chain-ok { color: var(--green); }
    .chain-fail { color: var(--red); }
    .section-label { grid-column: span 4; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; padding: 4px 0 0 0; border-top: 1px solid var(--border); margin-top: 4px; }
    .rmf-bar { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
    .rmf-label { width: 70px; font-size: 11px; color: var(--muted); }
    .rmf-track { flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .rmf-fill { height: 100%; border-radius: 3px; }
    code { background: #1c2128; padding: 1px 5px; border-radius: 3px; font-size: 11px; color: var(--purple); }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .nav { display: flex; gap: 4px; margin-left: auto; }
    .nav a { font-size: 11px; padding: 4px 10px; background: var(--border); border-radius: 4px; color: var(--muted); }
    .nav a:hover { background: var(--accent); color: var(--bg); text-decoration: none; }
    .refresh-note { font-size: 10px; color: var(--muted); margin-top: 4px; }
    #chain-status { font-size: 13px; font-weight: bold; }
  </style>
</head>
<body>
  <header>
    <h1>⬡ AI AGENT AUDIT TRAIL</h1>
    <span class="badge">HIPAA §164.312(b)</span>
    <span class="badge">{{ org_name }}</span>
    <span class="badge" id="clock">—</span>
    <nav class="nav">
      <a href="/api/agents">Agents API</a>
      <a href="/api/actions?limit=50">Actions API</a>
      <a href="/api/violations">Violations API</a>
      <a href="/api/chain/verify">Chain Integrity</a>
      <a href="/docs">OpenAPI</a>
    </nav>
  </header>

  <div class="main" id="dashboard">
    <!-- Row 1: Key Metrics -->
    <div class="section-label">KEY METRICS</div>

    <div class="card">
      <h2>Compliance Score</h2>
      <div class="metric {{ score_class }}" id="score">{{ score }}%</div>
      <div class="score-bar"><div class="score-fill" id="score-bar" style="width:{{ score }}%;background:{{ score_color }};"></div></div>
      <div class="sub">{{ rating }}</div>
    </div>

    <div class="card">
      <h2>Open Violations</h2>
      <div class="metric {{ open_class }}" id="open-viol">{{ open_violations }}</div>
      <div class="sub">Critical: <span class="sev-critical">{{ critical_violations }}</span> &nbsp; High: <span class="sev-high">{{ high_violations }}</span></div>
    </div>

    <div class="card">
      <h2>Actions Logged</h2>
      <div class="metric" id="total-actions">{{ total_actions }}</div>
      <div class="sub">{{ total_agents }} agents active</div>
    </div>

    <div class="card">
      <h2>Chain Integrity</h2>
      <div id="chain-status" class="{{ chain_class }}">{{ chain_status }}</div>
      <div class="sub">{{ chain_records }} records &nbsp;|&nbsp; <a href="/api/chain/verify">verify</a></div>
    </div>

    <!-- Row 2: Agent Risk + Violations by severity -->
    <div class="section-label">AGENT INVENTORY & VIOLATIONS</div>

    <div class="card">
      <h2>Agents by Risk Tier</h2>
      <table>
        <tr><th>Tier</th><th>Count</th></tr>
        {% for tier, count in agents_by_risk %}
        <tr><td class="sev-{{ tier }}">{{ tier.upper() }}</td><td>{{ count }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="card">
      <h2>Violations by Severity</h2>
      <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {% for sev, cnt in violations_by_severity %}
        <tr><td class="sev-{{ sev }}">{{ sev.upper() }}</td><td>{{ cnt }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="card">
      <h2>Operations Distribution</h2>
      <table>
        <tr><th>Operation</th><th>Count</th></tr>
        {% for op, cnt in top_operations %}
        <tr><td><span class="tag op">{{ op }}</span></td><td>{{ cnt }}</td></tr>
        {% endfor %}
      </table>
    </div>

    <div class="card">
      <h2>NIST AI RMF Alignment</h2>
      {% for func, score in rmf_scores %}
      <div class="rmf-bar">
        <div class="rmf-label">{{ func.title() }}</div>
        <div class="rmf-track"><div class="rmf-fill" style="width:{{ score }}%;background:{{ '#3fb950' if score > 75 else '#d29922' if score > 50 else '#f85149' }};"></div></div>
        <span style="font-size:11px;color:var(--muted)">{{ score }}%</span>
      </div>
      {% endfor %}
    </div>

    <!-- Row 3: Recent actions + violations feed -->
    <div class="section-label">RECENT ACTIVITY</div>

    <div class="card wide">
      <h2>Recent Agent Actions</h2>
      <div class="live-feed" id="actions-feed">
        <table>
          <tr><th>Timestamp</th><th>Agent</th><th>Operation</th><th>Resource</th><th>PHI</th><th>Enc</th><th>Status</th></tr>
          {% for a in recent_actions %}
          <tr>
            <td class="ts">{{ a.timestamp[:19] }}</td>
            <td><code>{{ a.agent_id[:16] }}</code></td>
            <td><span class="tag op">{{ a.operation }}</span></td>
            <td>{{ a.resource_type }}</td>
            <td>{% if a.phi_categories %}<span class="tag phi">PHI</span>{% endif %}</td>
            <td>{% if a.encryption_in_transit %}<span style="color:var(--green)">✓</span>{% else %}<span style="color:var(--red)">✗</span>{% endif %}</td>
            <td class="{{ 'status-compliant' if a.status == 'completed' else 'status-noncompliant' }}">{{ a.status }}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>

    <div class="card wide">
      <h2>Open Violations Feed</h2>
      <div class="live-feed">
        <table>
          <tr><th>Severity</th><th>Type</th><th>Agent</th><th>HIPAA §</th><th>Detected</th></tr>
          {% for v in open_violations_list %}
          <tr>
            <td class="sev-{{ v.severity }}">{{ v.severity.upper() }}</td>
            <td>{{ v.violation_type.replace('_', ' ').title() }}</td>
            <td><code>{{ v.agent_id[:16] }}</code></td>
            <td>{{ v.hipaa_section }}</td>
            <td class="ts">{{ v.timestamp[:16] }}</td>
          </tr>
          {% endfor %}
          {% if not open_violations_list %}
          <tr><td colspan="5" style="color:var(--green);text-align:center;padding:12px;">✓ No open violations</td></tr>
          {% endif %}
        </table>
      </div>
    </div>

    <!-- Row 4: Control summary -->
    <div class="section-label">COMPLIANCE CONTROL STATUS</div>

    <div class="card full">
      <h2>Control Assessment Summary — HIPAA §164.312</h2>
      <table>
        <tr><th>Control ID</th><th>HIPAA §</th><th>Standard</th><th>Type</th><th>Status</th><th>Score</th><th>Finding</th></tr>
        {% for c in controls %}
        <tr>
          <td><code>{{ c.control_id }}</code></td>
          <td>{{ c.hipaa_section }}</td>
          <td>{{ c.hipaa_standard[:50] }}{% if c.hipaa_standard|length > 50 %}…{% endif %}</td>
          <td>{{ c.requirement_type }}</td>
          <td class="{{ 'status-compliant' if c.status == 'compliant' else 'status-partial' if c.status == 'partially_compliant' else 'status-noncompliant' if c.status == 'non_compliant' else '' }}">
            {{ '✓' if c.status == 'compliant' else '⚠' if c.status == 'partially_compliant' else '✗' if c.status == 'non_compliant' else '—' }}
            {{ c.status.replace('_', ' ').title() }}
          </td>
          <td class="{{ 'sev-critical' if c.risk_score >= 9 else 'sev-high' if c.risk_score >= 7 else 'sev-medium' if c.risk_score >= 4 else 'sev-low' }}">{{ c.risk_score }}</td>
          <td style="font-size:11px;color:var(--muted);">{{ c.finding[:90] }}{% if c.finding and c.finding|length > 90 %}…{% endif %}</td>
        </tr>
        {% endfor %}
      </table>
    </div>

  </div>

  <script>
    // Live clock
    function updateClock() {
      document.getElementById('clock').textContent = new Date().toISOString().slice(0,19) + ' UTC';
    }
    updateClock();
    setInterval(updateClock, 1000);

    // Auto-refresh every 30s
    setTimeout(() => location.reload(), 30000);

    // SSE for real-time violation alerts
    if (typeof EventSource !== 'undefined') {
      const es = new EventSource('/events/violations');
      es.onmessage = (e) => {
        const data = JSON.parse(e.data);
        if (data.type === 'violation') {
          const feed = document.querySelector('.live-feed:last-of-type tbody');
          // Flash the open violations count
          const el = document.getElementById('open-viol');
          if (el) { el.style.animation = 'none'; el.style.color = '#f85149'; }
        }
      };
    }
  </script>
</body>
</html>"""


def create_app(store=None, compliance_engine=None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        store:            AuditStore instance (lazy-loaded if None).
        compliance_engine: ComplianceEngine instance (lazy-loaded if None).

    Returns:
        Configured FastAPI application.
    """
    app = FastAPI(
        title="AI Agent Audit Trail",
        description=(
            "HIPAA-compliant audit trail and compliance reporting for AI agents "
            "in healthcare networks. Implements §164.312 Technical Safeguards."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Store references on app state
    app.state.store = store
    app.state.compliance_engine = compliance_engine
    app.state.last_assessment_results = []

    # ------------------------------------------------------------------
    # Health / Status
    # ------------------------------------------------------------------

    @app.get("/health", tags=["System"])
    async def health():
        """Health check endpoint for operational monitoring."""
        _store = app.state.store
        if _store is None:
            return {"status": "degraded", "reason": "store not initialized"}
        try:
            stats = _store.get_database_stats()
            return {
                "status": "healthy",
                "timestamp": _utc_now(),
                "database": str(_store.db_path),
                "total_actions": stats["total_actions"],
                "total_agents": stats["total_agents"],
                "open_violations": stats["open_violations"],
            }
        except Exception as exc:
            return {"status": "unhealthy", "error": str(exc)}

    # ------------------------------------------------------------------
    # Main Dashboard
    # ------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard(request: Request):
        """
        Dark-mode terminal dashboard.

        §164.312(b): Real-time examination of activity in systems containing ePHI.
        """
        try:
            from jinja2 import Environment
        except ImportError:
            return HTMLResponse("<pre>Install jinja2 to enable dashboard: pip install jinja2</pre>")

        _store = app.state.store
        if _store is None:
            return HTMLResponse("<pre>AuditStore not initialized. Start the server via CLI: audit serve</pre>")

        stats = _store.get_database_stats()
        recent_actions = _store.get_recent_actions(limit=15)
        open_viol = _store.get_critical_violations(limit=15)
        all_open = _store.query_violations(status="open", limit=20)
        viol_summary = _store.get_violation_summary()
        agents = _store.list_agents()

        # Run quick compliance assessment if not cached
        controls = app.state.last_assessment_results
        if not controls:
            try:
                from datetime import timedelta
                now = datetime.now(timezone.utc)
                start = (now - timedelta(days=30)).isoformat()
                end = now.isoformat()
                _engine = app.state.compliance_engine
                if _engine:
                    controls = _engine.assess_all_controls(start, end)
                    app.state.last_assessment_results = controls
            except Exception as exc:
                logger.warning("Dashboard compliance assessment failed: %s", exc)
                controls = []

        # Compute score
        overall_score = 0.0
        rating = "Not Assessed"
        if controls and app.state.compliance_engine:
            try:
                overall_score = app.state.compliance_engine.compute_compliance_score(controls)
                rating = app.state.compliance_engine.get_rating(overall_score)
            except Exception:
                pass

        score_int = int(overall_score)
        score_class = "green" if score_int >= 90 else "yellow" if score_int >= 75 else "orange" if score_int >= 50 else "red"
        score_color = "#3fb950" if score_int >= 90 else "#d29922" if score_int >= 75 else "#db6d28" if score_int >= 50 else "#f85149"

        by_sev = viol_summary.get("by_severity", {})
        open_count = stats.get("open_violations", 0)
        critical_count = by_sev.get("critical", 0)
        high_count = by_sev.get("high", 0)

        # Agent risk tier counts
        by_risk: dict[str, int] = {}
        by_op: dict[str, int] = {}
        for a in agents:
            by_risk[a.risk_tier] = by_risk.get(a.risk_tier, 0) + 1
        for a in recent_actions:
            by_op[a.operation] = by_op.get(a.operation, 0) + 1

        chain_valid, chain_errors = _store.verify_chain_integrity()
        chain_status = "✓ VERIFIED" if chain_valid else f"✗ COMPROMISED ({len(chain_errors)} errors)"
        chain_class = "chain-ok" if chain_valid else "chain-fail"
        chain_records = stats.get("chain_total_records", 0)

        # NIST AI RMF scores
        rmf_scores = []
        if controls and app.state.compliance_engine:
            try:
                rmf = app.state.compliance_engine.map_to_nist_ai_rmf(controls)
                rmf_scores = [(f, int(s * 100)) for f, s in sorted(rmf.items())]
            except Exception:
                pass

        # Operations sorted by count
        action_counts_for_ops: dict[str, int] = {}
        for a in _store.query_actions(limit=500):
            action_counts_for_ops[a.operation] = action_counts_for_ops.get(a.operation, 0) + 1
        top_operations = sorted(action_counts_for_ops.items(), key=lambda x: -x[1])[:8]

        env = Environment(autoescape=True)
        tmpl = env.from_string(_DASHBOARD_HTML)
        html = tmpl.render(
            org_name=ORGANIZATION_NAME,
            score=score_int,
            score_class=score_class,
            score_color=score_color,
            rating=rating,
            open_violations=open_count,
            open_class="red" if open_count > 0 else "green",
            critical_violations=critical_count,
            high_violations=high_count,
            total_actions=stats.get("total_actions", 0),
            total_agents=stats.get("total_agents", 0),
            chain_status=chain_status,
            chain_class=chain_class,
            chain_records=chain_records,
            agents_by_risk=sorted(by_risk.items()),
            violations_by_severity=sorted(by_sev.items(), key=lambda x: ["critical","high","medium","low"].index(x[0]) if x[0] in ["critical","high","medium","low"] else 9),
            top_operations=top_operations,
            rmf_scores=rmf_scores,
            recent_actions=recent_actions,
            open_violations_list=all_open,
            controls=controls,
        )
        return HTMLResponse(content=html)

    # ------------------------------------------------------------------
    # Agent Endpoints
    # ------------------------------------------------------------------

    @app.get("/api/agents", tags=["Agents"])
    async def list_agents(
        status: Optional[str] = None,
        risk_tier: Optional[str] = None,
        department: Optional[str] = None,
    ):
        """
        List registered AI agents with optional filters.

        §164.312(a)(2)(i): The complete agent registry.
        """
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        agents = _store.list_agents(status=status, risk_tier=risk_tier, department=department)
        return {"agents": [a.to_dict() for a in agents], "total": len(agents)}

    @app.get("/api/agents/{agent_id}", tags=["Agents"])
    async def get_agent(agent_id: str):
        """Get a specific agent by ID."""
        _store = app.state.store
        agent = _store.get_agent(agent_id) if _store else None
        if not agent:
            raise HTTPException(404, f"Agent '{agent_id}' not found")
        return agent.to_dict()

    @app.get("/api/agents/{agent_id}/stats", tags=["Agents"])
    async def get_agent_stats(agent_id: str):
        """Get compliance statistics for a specific agent."""
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        return _store.get_agent_stats(agent_id)

    # ------------------------------------------------------------------
    # Action Endpoints
    # ------------------------------------------------------------------

    @app.get("/api/actions", tags=["Actions"])
    async def list_actions(
        agent_id: Optional[str] = None,
        operation: Optional[str] = None,
        start: Optional[str] = None,
        end: Optional[str] = None,
        limit: int = Query(default=50, le=500),
        offset: int = 0,
    ):
        """
        Query audit action records.

        §164.312(b): Examination of activity in information systems containing ePHI.
        """
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        actions = _store.query_actions(
            agent_id=agent_id, operation=operation,
            start=start, end=end,
            limit=limit, offset=offset,
        )
        return {
            "actions": [a.to_dict() for a in actions],
            "total": len(actions),
            "offset": offset,
            "limit": limit,
        }

    @app.get("/api/actions/{action_id}", tags=["Actions"])
    async def get_action(action_id: str):
        """Get a specific audit action record by ID."""
        _store = app.state.store
        action = _store.get_action(action_id) if _store else None
        if not action:
            raise HTTPException(404, f"Action '{action_id}' not found")
        return action.to_dict()

    # ------------------------------------------------------------------
    # Violation Endpoints
    # ------------------------------------------------------------------

    @app.get("/api/violations", tags=["Violations"])
    async def list_violations(
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = Query(default=50, le=500),
    ):
        """
        Query compliance violations.

        §164.308(a)(6): Incident response — violations feed into the
        HIPAA security incident identification process.
        """
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        violations = _store.query_violations(
            agent_id=agent_id, severity=severity, status=status, limit=limit
        )
        return {"violations": [v.to_dict() for v in violations], "total": len(violations)}

    @app.get("/api/violations/summary", tags=["Violations"])
    async def violation_summary(
        start: Optional[str] = None,
        end: Optional[str] = None,
    ):
        """Violation counts by severity, type, and status."""
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        return _store.get_violation_summary(start=start, end=end)

    # ------------------------------------------------------------------
    # Chain Integrity
    # ------------------------------------------------------------------

    @app.get("/api/chain/verify", tags=["Integrity"])
    async def verify_chain():
        """
        Verify the tamper-evident SHA-256 hash chain integrity.

        §164.312(b): Detects any modification, deletion, or injection
        in the append-only audit log.
        """
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        valid, errors = _store.verify_chain_integrity()
        return {
            "chain_valid": valid,
            "errors": errors,
            "error_count": len(errors),
            "verified_at": _utc_now(),
            "message": "Chain integrity verified — no tampering detected" if valid else f"CHAIN INTEGRITY FAILURE: {len(errors)} error(s)",
        }

    # ------------------------------------------------------------------
    # Compliance Assessment
    # ------------------------------------------------------------------

    @app.get("/api/compliance/assess", tags=["Compliance"])
    async def run_assessment(
        start: Optional[str] = None,
        end: Optional[str] = None,
    ):
        """
        Run full HIPAA compliance assessment and return results.

        §164.308(a)(1): Risk analysis must specifically assess AI systems.
        """
        _store = app.state.store
        _engine = app.state.compliance_engine
        if not _store or not _engine:
            raise HTTPException(503, "Store or compliance engine not initialized")

        if not start:
            from datetime import timedelta
            start = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        if not end:
            end = datetime.now(timezone.utc).isoformat()

        results = _engine.assess_all_controls(start, end)
        app.state.last_assessment_results = results
        score = _engine.compute_compliance_score(results)
        rating = _engine.get_rating(score)

        return {
            "period_start": start,
            "period_end": end,
            "overall_score": score,
            "overall_rating": rating,
            "controls": [c.to_dict() for c in results],
            "assessed_at": _utc_now(),
        }

    @app.get("/api/compliance/gap-analysis", tags=["Compliance"])
    async def gap_analysis():
        """Return prioritized gap analysis from last assessment."""
        _engine = app.state.compliance_engine
        controls = app.state.last_assessment_results
        if not _engine or not controls:
            raise HTTPException(
                428,
                "No assessment results available. Run /api/compliance/assess first."
            )
        return {"gaps": _engine.generate_gap_analysis(controls)}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @app.get("/api/stats", tags=["System"])
    async def database_stats():
        """High-level database statistics."""
        _store = app.state.store
        if not _store:
            raise HTTPException(503, "Store not initialized")
        return _store.get_database_stats()

    # ------------------------------------------------------------------
    # SSE: Real-time violation stream
    # ------------------------------------------------------------------

    @app.get("/events/violations", tags=["Streaming"])
    async def violation_events():
        """
        Server-Sent Events stream for real-time violation notifications.

        Clients can subscribe to this endpoint to receive push notifications
        when new violations are detected, enabling real-time SIEM integration.

        §164.312(b): Supports real-time examination of system activity.
        """
        async def event_generator() -> AsyncGenerator[str, None]:
            # Send initial connection event
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': _utc_now()})}\n\n"

            _store = app.state.store
            if not _store:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Store not initialized'})}\n\n"
                return

            # Send current open violations
            violations = _store.query_violations(status="open", limit=10)
            for v in violations:
                yield f"data: {json.dumps({'type': 'violation', 'data': v.to_dict()})}\n\n"

            # Keep-alive
            import asyncio
            while True:
                await asyncio.sleep(30)
                yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': _utc_now()})}\n\n"

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return app


def run_server(store=None, compliance_engine=None, host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT) -> None:
    """
    Start the Uvicorn server for the audit dashboard.

    Args:
        store:            AuditStore instance.
        compliance_engine: ComplianceEngine instance.
        host:             Bind host.
        port:             Bind port.
    """
    try:
        import uvicorn
    except ImportError:
        raise RuntimeError("uvicorn not installed. Run: pip install uvicorn")

    app = create_app(store=store, compliance_engine=compliance_engine)
    logger.info("Starting AI Agent Audit Dashboard on http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

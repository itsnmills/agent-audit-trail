#!/usr/bin/env python3
"""
Violation detection engine.

Analyzes agent actions for compliance violations using a rules-based engine
with 20 detection rules covering critical through low severity.

Also implements pattern-based detection for:
  - Bulk PHI exfiltration (V-005)
  - Scope drift over time (MN-003)
  - Shadow agent identification (RM-002)

HIPAA grounding:
  §164.312(a)  — Access Control violations
  §164.312(b)  — Audit Control violations
  §164.312(d)  — Authentication violations
  §164.312(e)  — Transmission Security violations
  §164.502(b)  — Minimum Necessary violations
  §164.308(b)  — Business Associate violations
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, TYPE_CHECKING

from .config import (
    AFTER_HOURS_END,
    AFTER_HOURS_START,
    BULK_ACCESS_THRESHOLD,
    CREDENTIAL_ROTATION_MAX_DAYS,
    EXFIL_WINDOW_MINUTES,
    MAX_SESSION_HOURS,
    REDUNDANT_ACCESS_MINUTES,
    SCOPE_DRIFT_WINDOW_DAYS,
    SEVERITY_SCORES,
    PHI_IMPACT_MULTIPLIERS,
)
from .models import AgentAction, AgentIdentity, ViolationRecord

if TYPE_CHECKING:
    from .storage import AuditStore

logger = logging.getLogger(__name__)


# ===========================================================================
# Detection Rules
# Format: (rule_id, name, severity, description, hipaa_section)
# ===========================================================================

DETECTION_RULES: list[tuple[str, str, str, str, str]] = [
    # CRITICAL — Direct PHI exposure or missing authentication
    ("V-001", "Unencrypted PHI Access",
     "critical",
     "Agent accessed PHI without encryption at rest or in transit.",
     "§164.312(a)(2)(iv) + §164.312(e)(2)(ii) [2025 Mandatory]"),

    ("V-002", "Missing Human Authorizer",
     "critical",
     "Agent action has no linked human authorizer. Every AI agent action must be traceable "
     "to an authenticated human per §164.312(d).",
     "§164.312(d)"),

    ("V-003", "PHI Transmitted to External System Unencrypted",
     "critical",
     "PHI transmitted to an external or non-HIPAA cloud zone without encryption. "
     "This likely constitutes a reportable breach under §164.402.",
     "§164.312(e)"),

    ("V-004", "Agent Accessing PHI Without Authentication Record",
     "critical",
     "No last_authenticated timestamp exists for the agent, indicating it may have "
     "accessed PHI without prior authentication per §164.312(d).",
     "§164.312(d)"),

    ("V-005", "Bulk PHI Exfiltration Pattern",
     "critical",
     f"Agent accessed >{BULK_ACCESS_THRESHOLD} distinct patient records in a single session, "
     "far exceeding any individual clinical workflow's minimum necessary scope.",
     "§164.502(b)"),

    # HIGH — Significant risk, elevated PHI exposure
    ("V-006", "Minimum Necessary Violation",
     "high",
     "Agent accessed more PHI than required for the stated task. Access scope is "
     "disproportionate to the documented clinical justification.",
     "§164.502(b)"),

    ("V-007", "Stale Agent Credentials",
     "high",
     f"Agent credentials have not been rotated in >{CREDENTIAL_ROTATION_MAX_DAYS} days. "
     "Stale credentials are a common attack vector and violate 2025 HIPAA amendment requirements.",
     "§164.312(d)"),

    ("V-008", "Missing Business Associate Agreement",
     "high",
     "Third-party AI agent operating without a Business Associate Agreement (BAA). "
     "Per 2025 HIPAA amendments, BAs now bear direct Security Rule liability.",
     "§164.308(b)"),

    ("V-009", "Cross-Department PHI Access",
     "high",
     "Agent accessed PHI for patients or records outside its designated department scope. "
     "This may indicate misconfiguration or privilege escalation.",
     "§164.312(a)"),

    ("V-010", "Audit Log Chain Gap",
     "high",
     "A gap was detected in the tamper-evident hash chain, indicating records may have "
     "been deleted, modified, or injected. Immediate investigation required.",
     "§164.312(b)"),

    # MEDIUM — Significant but not immediate exposure
    ("V-011", "Non-FIPS Encryption",
     "medium",
     "Encryption is applied but uses a non-FIPS 140-3 validated module. "
     "Per 2025 HIPAA amendments, FIPS 140-3 validation is required for ePHI operations.",
     "§164.312(e)(2)(ii)"),

    ("V-012", "Excessive Session Duration",
     "medium",
     f"Agent session active for >{MAX_SESSION_HOURS} hours without re-authentication. "
     "§164.312(a)(2)(iii) requires automatic session termination.",
     "§164.312(a)(2)(iii)"),

    ("V-013", "PHI in Non-Standard Output Format",
     "medium",
     "Agent produced output containing PHI in an unstructured format not subject to "
     "standard data classification controls, raising integrity concerns.",
     "§164.312(c)"),

    ("V-014", "Incomplete Delegation Chain",
     "medium",
     "Delegation chain has fewer than 2 entries (missing human or agent entry). "
     "§164.312(d) requires complete chain of custody from human authorizer to agent.",
     "§164.312(d)"),

    ("V-015", "Shadow Agent Detected",
     "medium",
     "Unregistered agent (not in the identity registry) is generating action records. "
     "This may indicate an unauthorized or misconfigured AI deployment.",
     "§164.312(a)"),

    # LOW — Behavioral anomalies
    ("V-016", "Agent Access Outside Business Hours",
     "low",
     f"Agent performed PHI operations outside normal business hours "
     f"({AFTER_HOURS_END:02d}:00–{AFTER_HOURS_START:02d}:00). "
     "While not prohibited, this pattern warrants monitoring.",
     "§164.312(b)"),

    ("V-017", "Deprecated Agent Still Active",
     "low",
     "Agent with status 'decommissioned' or 'under_review' is still generating action records. "
     "Decommissioned agents should have credentials revoked immediately.",
     "§164.312(a)"),

    ("V-018", "Missing Operation Detail",
     "low",
     "Audit record missing operation_detail field, reducing the granularity of the "
     "audit trail below §164.312(b) best practice requirements.",
     "§164.312(b)"),

    ("V-019", "Long Query Response Time",
     "low",
     "Agent took >30 seconds to complete a PHI operation. Unusually long operations may "
     "indicate data harvesting, API abuse, or system performance issues.",
     "§164.312(a)"),

    ("V-020", "Redundant PHI Access",
     "low",
     f"Agent re-read the same record(s) within {REDUNDANT_ACCESS_MINUTES} minutes without "
     "an intervening write. Repeated reads may indicate a data harvesting pattern.",
     "§164.502(b)"),
]

# Map rule_id → (name, severity, description, hipaa_section)
_RULE_MAP: dict[str, tuple[str, str, str, str]] = {
    rule[0]: (rule[1], rule[2], rule[3], rule[4])
    for rule in DETECTION_RULES
}


def _make_violation(
    rule_id: str,
    agent_id: str,
    action_id: str,
    evidence: dict,
    phi_impact: str = "potential_phi_exposure",
    patient_count: int = 0,
    remediation: str = "",
    remediation_owner: str = "",
    remediation_deadline: str = "",
) -> ViolationRecord:
    """Construct a ViolationRecord from a rule definition."""
    name, severity, description, hipaa_section = _RULE_MAP[rule_id]
    base_score = SEVERITY_SCORES.get(severity, 5.0)
    impact_multiplier = PHI_IMPACT_MULTIPLIERS.get(phi_impact, 0.7)
    severity_score = round(min(10.0, base_score * impact_multiplier), 2)
    # Patient count boosts score for high-volume breaches
    if patient_count > 500:
        severity_score = min(10.0, severity_score + 1.0)
    elif patient_count > 100:
        severity_score = min(10.0, severity_score + 0.5)

    return ViolationRecord(
        violation_id=str(uuid.uuid4()),
        timestamp=_utc_now(),
        agent_id=agent_id,
        action_id=action_id,
        violation_type=name.lower().replace(" ", "_").replace("-", "_").replace("/", "_"),
        hipaa_section=hipaa_section,
        severity=severity,
        severity_score=severity_score,
        description=f"{name}: {description}",
        evidence=evidence,
        phi_impact=phi_impact,
        patient_count=patient_count,
        status="open",
        remediation_action=remediation,
        remediation_owner=remediation_owner,
        remediation_deadline=remediation_deadline,
    )


# ===========================================================================
# ViolationDetector
# ===========================================================================

class ViolationDetector:
    """
    Analyzes AI agent actions for HIPAA compliance violations.

    Operates in two modes:
      1. Real-time: analyze_action() fires on each ingested record
      2. Batch:     analyze_batch() processes a set of records with
                    cross-action pattern analysis (exfiltration, scope drift)

    Detection is evidence-based: every ViolationRecord includes structured
    evidence linking it to the specific action fields that triggered it.

    Usage::

        detector = ViolationDetector(store=audit_store)
        violations = detector.analyze_action(action)
        for v in violations:
            store.store_violation(v)
    """

    def __init__(
        self,
        store: "AuditStore",
        known_agent_ids: Optional[set[str]] = None,
    ) -> None:
        """
        Initialize the detector.

        Args:
            store:           AuditStore for historical pattern lookups.
            known_agent_ids: Set of registered agent IDs. If None, will be
                             loaded from store on first use.
        """
        self.store = store
        self._known_agent_ids: Optional[set[str]] = known_agent_ids

    @property
    def known_agent_ids(self) -> set[str]:
        """Lazily load registered agent IDs from store."""
        if self._known_agent_ids is None:
            agents = self.store.list_agents()
            self._known_agent_ids = {a.agent_id for a in agents}
        return self._known_agent_ids

    def refresh_known_agents(self) -> None:
        """Refresh the cached set of known agent IDs from the store."""
        self._known_agent_ids = None  # Forces reload on next access

    # ------------------------------------------------------------------
    # Single-action analysis
    # ------------------------------------------------------------------

    def analyze_action(self, action: AgentAction) -> list[ViolationRecord]:
        """
        Analyze a single AgentAction for violations.

        Runs all applicable detection rules against the action.
        Returns a list of ViolationRecord instances (empty if no violations).

        Each rule fires independently — a single action may trigger multiple
        violations (e.g., both V-001 and V-002 if unencrypted AND missing authorizer).

        Args:
            action: The AgentAction to analyze.

        Returns:
            List of detected ViolationRecord instances.
        """
        violations: list[ViolationRecord] = []

        violations.extend(self._check_v001(action))
        violations.extend(self._check_v002(action))
        violations.extend(self._check_v003(action))
        violations.extend(self._check_v004(action))
        # V-005 is session-level — handled in analyze_batch / detect_exfiltration_pattern
        violations.extend(self._check_v006(action))
        # V-007 is agent-level — handled in analyze_agent
        # V-008 is agent-level — handled in analyze_agent
        violations.extend(self._check_v009(action))
        # V-010 is chain-level — handled separately
        violations.extend(self._check_v011(action))
        violations.extend(self._check_v013(action))
        violations.extend(self._check_v014(action))
        violations.extend(self._check_v015(action))
        violations.extend(self._check_v016(action))
        violations.extend(self._check_v018(action))
        violations.extend(self._check_v019(action))
        # V-017, V-020 require agent info or session context — handled in analyze_batch

        logger.debug(
            "Action %s: %d violation(s) detected",
            action.action_id, len(violations)
        )
        return violations

    # ------------------------------------------------------------------
    # Batch analysis (adds cross-action pattern detection)
    # ------------------------------------------------------------------

    def analyze_batch(
        self,
        actions: list[AgentAction],
        agents: Optional[list[AgentIdentity]] = None,
    ) -> list[ViolationRecord]:
        """
        Analyze a list of actions with full cross-action pattern detection.

        In addition to per-action rules, runs:
          - V-005: Bulk PHI exfiltration detection
          - V-007: Stale credential detection (per agent)
          - V-008: Missing BAA detection (per agent)
          - V-010: Chain gap detection
          - V-012: Excessive session duration
          - V-017: Deprecated agent still active
          - V-020: Redundant PHI access pattern

        Args:
            actions: List of AgentActions to analyze.
            agents:  Optional list of AgentIdentity objects for agent-level checks.
                     If not provided, will be loaded from store.

        Returns:
            All detected violations (per-action + cross-action patterns).
        """
        all_violations: list[ViolationRecord] = []

        # Per-action violations
        for action in actions:
            all_violations.extend(self.analyze_action(action))

        if not actions:
            return all_violations

        # Cross-action pattern analysis
        all_violations.extend(self._detect_bulk_exfiltration_from_actions(actions))
        all_violations.extend(self._detect_excessive_sessions(actions))
        all_violations.extend(self._detect_redundant_access(actions))

        # Agent-level checks
        if agents is None:
            agents = self.store.list_agents()
        for agent in agents:
            # Only check agents that have actions in this batch
            agent_actions = [a for a in actions if a.agent_id == agent.agent_id]
            if agent_actions:
                v = self._check_v007(agent, agent_actions[0])
                if v:
                    all_violations.append(v)
                v = self._check_v008(agent, agent_actions[0])
                if v:
                    all_violations.append(v)
                all_violations.extend(self._check_v017(agent, agent_actions))

        # Chain gap detection
        v = self._check_v010()
        if v:
            all_violations.append(v)

        logger.info(
            "Batch analysis of %d actions: %d total violation(s) detected",
            len(actions), len(all_violations),
        )
        return all_violations

    # ------------------------------------------------------------------
    # Agent-level analysis
    # ------------------------------------------------------------------

    def analyze_agent(self, agent: AgentIdentity) -> list[ViolationRecord]:
        """
        Run agent-level compliance checks (not action-specific).

        Checks: V-007 (stale credentials), V-008 (missing BAA),
                V-017 (deprecated but active).

        Args:
            agent: The AgentIdentity to analyze.

        Returns:
            List of ViolationRecord instances.
        """
        violations: list[ViolationRecord] = []
        dummy_action_id = "agent-level-check"

        v = self._check_v007(agent, None)
        if v:
            violations.append(v)
        v = self._check_v008(agent, None)
        if v:
            violations.append(v)

        return violations

    # ------------------------------------------------------------------
    # Pattern detection (public API)
    # ------------------------------------------------------------------

    def detect_exfiltration_pattern(
        self,
        agent_id: str,
        window_minutes: int = EXFIL_WINDOW_MINUTES,
    ) -> Optional[ViolationRecord]:
        """
        Detect bulk PHI access patterns for a specific agent within a rolling time window.

        §164.502(b): Accessing >BULK_ACCESS_THRESHOLD records in a single session
        almost certainly violates minimum necessary requirements.

        Args:
            agent_id:       Agent to analyze.
            window_minutes: Rolling time window in minutes.

        Returns:
            ViolationRecord if exfiltration pattern detected, else None.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ).isoformat()
        actions = self.store.query_actions(agent_id=agent_id, start=cutoff)

        session_volume: dict[str, int] = defaultdict(int)
        for a in actions:
            if a.involves_phi:
                session_volume[a.session_id] += a.phi_volume

        for session_id, volume in session_volume.items():
            if volume > BULK_ACCESS_THRESHOLD:
                return _make_violation(
                    "V-005",
                    agent_id=agent_id,
                    action_id=session_id,
                    evidence={
                        "session_id": session_id,
                        "phi_volume": volume,
                        "threshold": BULK_ACCESS_THRESHOLD,
                        "window_minutes": window_minutes,
                    },
                    phi_impact="confirmed_phi_exposure",
                    patient_count=volume,
                    remediation=(
                        f"Investigate session {session_id}: review if bulk access was "
                        f"justified. If not, suspend agent pending review. "
                        f"Document §164.502(b) justification or restrict agent scope."
                    ),
                )
        return None

    def detect_scope_drift(
        self,
        agent_id: str,
        window_days: int = SCOPE_DRIFT_WINDOW_DAYS,
    ) -> Optional[ViolationRecord]:
        """
        Detect gradual PHI access scope expansion over time for an agent.

        Compares the agent's average phi_volume per action in the first half
        of the window vs the second half. A >50% increase triggers a violation.

        §164.502(b): Minimum necessary must be maintained; scope drift indicates
        the agent is gradually exceeding its intended access boundaries.

        Args:
            agent_id:    Agent to analyze.
            window_days: Lookback window in days.

        Returns:
            ViolationRecord if scope drift detected, else None.
        """
        now = datetime.now(timezone.utc)
        mid = now - timedelta(days=window_days // 2)
        start = now - timedelta(days=window_days)

        early_actions = self.store.query_actions(
            agent_id=agent_id,
            start=start.isoformat(),
            end=mid.isoformat(),
        )
        late_actions = self.store.query_actions(
            agent_id=agent_id,
            start=mid.isoformat(),
            end=now.isoformat(),
        )

        if len(early_actions) < 5 or len(late_actions) < 5:
            return None  # Insufficient data

        early_phi = [a for a in early_actions if a.involves_phi]
        late_phi = [a for a in late_actions if a.involves_phi]

        if not early_phi or not late_phi:
            return None

        early_avg = sum(a.phi_volume for a in early_phi) / len(early_phi)
        late_avg = sum(a.phi_volume for a in late_phi) / len(late_phi)

        if early_avg > 0 and (late_avg - early_avg) / early_avg > 0.50:
            drift_pct = round((late_avg - early_avg) / early_avg * 100, 1)
            return _make_violation(
                "V-006",
                agent_id=agent_id,
                action_id="scope-drift-detection",
                evidence={
                    "early_avg_phi_volume": round(early_avg, 2),
                    "late_avg_phi_volume": round(late_avg, 2),
                    "drift_percent": drift_pct,
                    "window_days": window_days,
                },
                phi_impact="potential_phi_exposure",
                patient_count=int(late_avg),
                remediation=(
                    f"Agent phi_volume increased {drift_pct}% over {window_days} days. "
                    f"Review agent permissions and ensure current scope aligns with §164.502(b). "
                    f"Consider quarterly access reviews per ISACA AI Audit framework."
                ),
            )
        return None

    def detect_shadow_agents(self) -> list[ViolationRecord]:
        """
        Find unregistered agents appearing in action logs.

        Compares agent_ids in action records against the registered agent inventory.
        Any agent_id appearing in actions but not in the registry is a shadow agent.

        §164.312(a): All software programs accessing ePHI must be identified and
        authorized. Unregistered agents represent an unknown risk.

        Returns:
            List of ViolationRecord instances for each shadow agent found.
        """
        actions = self.store.query_actions()
        action_agent_ids = {a.agent_id for a in actions if a.agent_id}
        registry_ids = {a.agent_id for a in self.store.list_agents()}
        shadow_ids = action_agent_ids - registry_ids

        violations: list[ViolationRecord] = []
        for shadow_id in shadow_ids:
            shadow_actions = [a for a in actions if a.agent_id == shadow_id]
            phi_actions = [a for a in shadow_actions if a.involves_phi]
            total_phi = sum(a.phi_volume for a in phi_actions)

            violations.append(
                _make_violation(
                    "V-015",
                    agent_id=shadow_id,
                    action_id=shadow_actions[-1].action_id if shadow_actions else "unknown",
                    evidence={
                        "unregistered_agent_id": shadow_id,
                        "total_actions": len(shadow_actions),
                        "phi_actions": len(phi_actions),
                        "total_phi_volume": total_phi,
                        "first_seen": shadow_actions[0].timestamp if shadow_actions else "",
                        "last_seen": shadow_actions[-1].timestamp if shadow_actions else "",
                    },
                    phi_impact="confirmed_phi_exposure" if phi_actions else "no_phi_impact",
                    patient_count=total_phi,
                    remediation=(
                        f"Register agent '{shadow_id}' in the identity registry immediately "
                        f"or terminate its access. Investigate source of unregistered agent activity. "
                        f"Per §164.312(a)(2)(i), all software accessing ePHI must have unique registered IDs."
                    ),
                )
            )
        return violations

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def compute_risk_score(self, violation: ViolationRecord) -> float:
        """
        Compute a CVSS-inspired risk score for a violation (0.0–10.0).

        Score factors:
          - Base severity score (from SEVERITY_SCORES)
          - PHI impact multiplier
          - Patient count amplifier (high patient count increases score)

        Args:
            violation: The ViolationRecord to score.

        Returns:
            Risk score 0.0–10.0
        """
        base = SEVERITY_SCORES.get(violation.severity, 5.0)
        multiplier = PHI_IMPACT_MULTIPLIERS.get(violation.phi_impact, 0.7)
        score = base * multiplier
        if violation.patient_count > 500:
            score = min(10.0, score + 1.5)
        elif violation.patient_count > 100:
            score = min(10.0, score + 0.75)
        elif violation.patient_count > 10:
            score = min(10.0, score + 0.25)
        return round(score, 2)

    # ------------------------------------------------------------------
    # Private: individual rule checks
    # ------------------------------------------------------------------

    def _check_v001(self, action: AgentAction) -> list[ViolationRecord]:
        """V-001: Unencrypted PHI access."""
        if not action.involves_phi:
            return []
        if not action.encryption_in_transit or not action.encryption_at_rest:
            missing = []
            if not action.encryption_in_transit:
                missing.append("encryption_in_transit=False")
            if not action.encryption_at_rest:
                missing.append("encryption_at_rest=False")
            return [_make_violation(
                "V-001",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "encryption_in_transit": action.encryption_in_transit,
                    "encryption_at_rest": action.encryption_at_rest,
                    "encryption_algorithm": action.encryption_algorithm,
                    "phi_categories": action.phi_categories,
                    "missing_controls": missing,
                },
                phi_impact="confirmed_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    "Immediately enforce encryption for all PHI data paths. "
                    "Per 2025 HIPAA amendments, encryption is now REQUIRED. "
                    "Use AES-256-GCM with FIPS 140-3 validated modules."
                ),
            )]
        return []

    def _check_v002(self, action: AgentAction) -> list[ViolationRecord]:
        """V-002: Missing human authorizer."""
        if not action.human_authorizer_id or action.human_authorizer_id in {"", "unknown_authorizer"}:
            return [_make_violation(
                "V-002",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "human_authorizer_id": action.human_authorizer_id,
                    "operation": action.operation,
                    "resource_type": action.resource_type,
                    "phi_categories": action.phi_categories,
                },
                phi_impact="confirmed_phi_exposure" if action.involves_phi else "no_phi_impact",
                patient_count=action.phi_volume,
                remediation=(
                    "Every AI agent action must be initiated by or delegated from an "
                    "authenticated human. Update the integration to pass human_authorizer_id "
                    "and a complete delegation_chain in every action record."
                ),
            )]
        return []

    def _check_v003(self, action: AgentAction) -> list[ViolationRecord]:
        """V-003: PHI transmitted to external system unencrypted."""
        if (action.involves_phi
                and action.is_external_transmission
                and not action.encryption_in_transit):
            return [_make_violation(
                "V-003",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "network_zone": action.network_zone,
                    "target_system": action.target_system,
                    "encryption_in_transit": False,
                    "phi_categories": action.phi_categories,
                    "operation": action.operation,
                },
                phi_impact="confirmed_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    "IMMEDIATE: Terminate unencrypted external PHI transmission. "
                    "Assess whether this constitutes a reportable breach under §164.402. "
                    "Notify Privacy Officer and initiate breach analysis within 24 hours."
                ),
            )]
        return []

    def _check_v004(self, action: AgentAction) -> list[ViolationRecord]:
        """V-004: PHI access without authentication record (no last_authenticated)."""
        if not action.involves_phi:
            return []
        # Check if the agent exists and has last_authenticated
        agent = self.store.get_agent(action.agent_id)
        if agent and not agent.last_authenticated:
            return [_make_violation(
                "V-004",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "agent_id": action.agent_id,
                    "last_authenticated": "",
                    "operation": action.operation,
                },
                phi_impact="potential_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    "Configure agent authentication and ensure last_authenticated "
                    "is updated after each authentication event. "
                    "No PHI access should occur without a prior authentication record."
                ),
            )]
        return []

    def _check_v006(self, action: AgentAction) -> list[ViolationRecord]:
        """V-006: Minimum necessary violation — unrestricted scope without justification."""
        if (action.involves_phi
                and action.minimum_necessary_scope == "unrestricted"
                and not action.access_justification):
            return [_make_violation(
                "V-006",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "minimum_necessary_scope": action.minimum_necessary_scope,
                    "access_justification": action.access_justification,
                    "phi_volume": action.phi_volume,
                    "phi_categories": action.phi_categories,
                },
                phi_impact="potential_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    "Document clinical justification for unrestricted scope access, "
                    "or restrict agent to encounter_specific or patient_specific scope. "
                    "§164.502(b) requires documented justification for all PHI access scope."
                ),
            )]
        return []

    def _check_v007(
        self, agent: AgentIdentity, action: Optional[AgentAction]
    ) -> Optional[ViolationRecord]:
        """V-007: Stale agent credentials."""
        if agent.credential_age_days > CREDENTIAL_ROTATION_MAX_DAYS and agent.status == "active":
            return _make_violation(
                "V-007",
                agent_id=agent.agent_id,
                action_id=action.action_id if action else "agent-level-check",
                evidence={
                    "credential_age_days": agent.credential_age_days,
                    "max_days": CREDENTIAL_ROTATION_MAX_DAYS,
                    "last_credential_rotation": agent.last_credential_rotation,
                    "authentication_method": agent.authentication_method,
                },
                phi_impact="potential_phi_exposure",
                patient_count=0,
                remediation=(
                    f"Rotate credentials for agent {agent.agent_name} immediately. "
                    f"Credentials are {agent.credential_age_days} days old "
                    f"(max: {CREDENTIAL_ROTATION_MAX_DAYS} days per 2025 HIPAA requirements). "
                    "Document rotation in the agent registry."
                ),
            )
        return None

    def _check_v008(
        self, agent: AgentIdentity, action: Optional[AgentAction]
    ) -> Optional[ViolationRecord]:
        """V-008: Missing BAA for third-party agent."""
        if agent.is_third_party and not agent.baa_reference:
            return _make_violation(
                "V-008",
                agent_id=agent.agent_id,
                action_id=action.action_id if action else "agent-level-check",
                evidence={
                    "vendor": agent.vendor,
                    "baa_reference": "",
                    "agent_name": agent.agent_name,
                    "is_third_party": True,
                },
                phi_impact="potential_phi_exposure",
                patient_count=0,
                remediation=(
                    f"Execute a Business Associate Agreement with {agent.vendor} before "
                    f"allowing agent '{agent.agent_name}' to access PHI. "
                    "Per 2025 HIPAA amendments, BAs now bear direct Security Rule liability. "
                    "Suspend agent until BAA is in place."
                ),
            )
        return None

    def _check_v009(self, action: AgentAction) -> list[ViolationRecord]:
        """V-009: Cross-department PHI access — agent accessing outside department."""
        agent = self.store.get_agent(action.agent_id)
        if not agent or not action.involves_phi:
            return []
        # Heuristic: check if resource_id or source_system contains a different department
        # In a real deployment, this would check department tags on the resource
        # We use a simple heuristic: phi_scope=individual_encounter but phi_volume is very high
        if (agent.phi_scope == "individual_encounter"
                and action.phi_volume > 50
                and action.minimum_necessary_scope in {"department_wide", "unrestricted"}):
            return [_make_violation(
                "V-009",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "agent_phi_scope": agent.phi_scope,
                    "action_minimum_necessary_scope": action.minimum_necessary_scope,
                    "phi_volume": action.phi_volume,
                    "agent_department": agent.department,
                },
                phi_impact="potential_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    f"Agent {agent.agent_name} (phi_scope=individual_encounter) accessed "
                    f"{action.phi_volume} records at {action.minimum_necessary_scope} scope. "
                    "Review whether this agent's permissions are appropriately scoped."
                ),
            )]
        return []

    def _check_v010(self) -> Optional[ViolationRecord]:
        """V-010: Audit log chain gap."""
        valid, errors = self.store.verify_chain_integrity()
        if not valid and errors:
            return _make_violation(
                "V-010",
                agent_id="system",
                action_id="chain-integrity-check",
                evidence={"chain_errors": errors[:5], "total_errors": len(errors)},
                phi_impact="potential_phi_exposure",
                patient_count=0,
                remediation=(
                    "IMMEDIATE: Audit chain integrity failure detected. "
                    "Preserve current database state as evidence. "
                    "Initiate security incident response per §164.308(a)(6). "
                    "Determine scope of tampering and notify Privacy Officer."
                ),
            )
        return None

    def _check_v011(self, action: AgentAction) -> list[ViolationRecord]:
        """V-011: Non-FIPS encryption used for PHI."""
        if action.involves_phi and action.encryption_in_transit and not action.fips_validated:
            from .config import APPROVED_ENCRYPTION_ALGORITHMS
            if action.encryption_algorithm in APPROVED_ENCRYPTION_ALGORITHMS:
                return [_make_violation(
                    "V-011",
                    agent_id=action.agent_id,
                    action_id=action.action_id,
                    evidence={
                        "encryption_algorithm": action.encryption_algorithm,
                        "fips_validated": False,
                        "phi_categories": action.phi_categories,
                    },
                    phi_impact="potential_phi_exposure",
                    patient_count=action.phi_volume,
                    remediation=(
                        "Configure encryption modules to use FIPS 140-3 validated implementations. "
                        f"Current algorithm '{action.encryption_algorithm}' is algorithmically sound "
                        "but the module lacks FIPS validation per 2025 HIPAA amendment requirements. "
                        "Obtain FIPS certificate numbers from your crypto library vendor."
                    ),
                )]
        return []

    def _check_v013(self, action: AgentAction) -> list[ViolationRecord]:
        """V-013: PHI in non-standard output format (modification_type indicates unstructured output)."""
        if (action.data_modified
                and action.modification_type == "creation"
                and action.involves_phi
                and not action.output_hash):
            return [_make_violation(
                "V-013",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "modification_type": action.modification_type,
                    "output_hash": "",
                    "phi_categories": action.phi_categories,
                },
                phi_impact="potential_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    "Ensure agent outputs containing PHI are captured with output_hash "
                    "for integrity verification. Review output format for compliance "
                    "with §164.312(c) integrity requirements."
                ),
            )]
        return []

    def _check_v014(self, action: AgentAction) -> list[ViolationRecord]:
        """V-014: Incomplete delegation chain."""
        if len(action.delegation_chain) < 2:
            return [_make_violation(
                "V-014",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "delegation_chain": action.delegation_chain,
                    "chain_length": len(action.delegation_chain),
                    "required_minimum": 2,
                },
                phi_impact="potential_phi_exposure" if action.involves_phi else "no_phi_impact",
                patient_count=action.phi_volume,
                remediation=(
                    "Update integration to include complete delegation chain with ≥2 entries: "
                    "[human_authorizer, ..., agent]. "
                    "The chain must trace from an authenticated human to the AI agent."
                ),
            )]
        return []

    def _check_v015(self, action: AgentAction) -> list[ViolationRecord]:
        """V-015: Shadow agent — unregistered agent in action log."""
        if action.agent_id and action.agent_id not in self.known_agent_ids:
            return [_make_violation(
                "V-015",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "unregistered_agent_id": action.agent_id,
                    "operation": action.operation,
                    "phi_categories": action.phi_categories,
                    "source_system": action.source_system,
                },
                phi_impact="confirmed_phi_exposure" if action.involves_phi else "no_phi_impact",
                patient_count=action.phi_volume,
                remediation=(
                    f"Register agent '{action.agent_id}' in the identity registry immediately "
                    "or block its access. Investigate how this unregistered agent came to be "
                    "performing actions. This may indicate unauthorized software deployment."
                ),
            )]
        return []

    def _check_v016(self, action: AgentAction) -> list[ViolationRecord]:
        """V-016: PHI access outside business hours."""
        if not action.involves_phi:
            return []
        try:
            dt = datetime.fromisoformat(action.timestamp)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            hour = dt.hour  # UTC hour
            is_after_hours = hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END
            if is_after_hours:
                return [_make_violation(
                    "V-016",
                    agent_id=action.agent_id,
                    action_id=action.action_id,
                    evidence={
                        "timestamp": action.timestamp,
                        "utc_hour": hour,
                        "after_hours_window": f"{AFTER_HOURS_END:02d}:00–{AFTER_HOURS_START:02d}:00",
                        "operation": action.operation,
                        "phi_categories": action.phi_categories,
                    },
                    phi_impact="potential_phi_exposure",
                    patient_count=action.phi_volume,
                    remediation=(
                        "Review this after-hours PHI access. If legitimate (e.g., night shift), "
                        "document business justification. If unexpected, investigate for "
                        "unauthorized access or compromised agent credentials."
                    ),
                )]
        except (ValueError, TypeError):
            pass
        return []

    def _check_v017(
        self, agent: AgentIdentity, agent_actions: list[AgentAction]
    ) -> list[ViolationRecord]:
        """V-017: Deprecated agent still generating actions."""
        if agent.status in {"decommissioned", "under_review"} and agent_actions:
            return [_make_violation(
                "V-017",
                agent_id=agent.agent_id,
                action_id=agent_actions[-1].action_id,
                evidence={
                    "agent_status": agent.status,
                    "agent_name": agent.agent_name,
                    "action_count_in_period": len(agent_actions),
                    "latest_action": agent_actions[-1].timestamp,
                },
                phi_impact="potential_phi_exposure" if any(a.involves_phi for a in agent_actions) else "no_phi_impact",
                patient_count=sum(a.phi_volume for a in agent_actions if a.involves_phi),
                remediation=(
                    f"Revoke credentials for agent '{agent.agent_name}' (status={agent.status}) "
                    "immediately. Decommissioned agents must have all access terminated. "
                    "Review all actions performed after decommission date."
                ),
            )]
        return []

    def _check_v018(self, action: AgentAction) -> list[ViolationRecord]:
        """V-018: Missing operation_detail for PHI actions."""
        if action.involves_phi and not action.operation_detail:
            return [_make_violation(
                "V-018",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "operation": action.operation,
                    "resource_type": action.resource_type,
                    "operation_detail": "",
                },
                phi_impact="no_phi_impact",
                patient_count=0,
                remediation=(
                    "Populate operation_detail for all PHI access actions. "
                    "This field provides the operation-level granularity required by §164.312(b)."
                ),
            )]
        return []

    def _check_v019(self, action: AgentAction) -> list[ViolationRecord]:
        """V-019: Long query response time (>30 seconds)."""
        if action.duration_ms > 30_000 and action.involves_phi:
            return [_make_violation(
                "V-019",
                agent_id=action.agent_id,
                action_id=action.action_id,
                evidence={
                    "duration_ms": action.duration_ms,
                    "duration_seconds": round(action.duration_ms / 1000, 1),
                    "operation": action.operation,
                    "threshold_ms": 30_000,
                },
                phi_impact="potential_phi_exposure",
                patient_count=action.phi_volume,
                remediation=(
                    f"Investigate why operation '{action.operation}' on {action.resource_type} "
                    f"took {action.duration_ms/1000:.1f}s. "
                    "Long PHI operations may indicate data harvesting or API performance issues."
                ),
            )]
        return []

    def _detect_bulk_exfiltration_from_actions(
        self, actions: list[AgentAction]
    ) -> list[ViolationRecord]:
        """V-005: Bulk exfiltration detection across a set of actions."""
        session_volume: dict[str, dict] = defaultdict(lambda: {"agent_id": "", "volume": 0, "action_id": ""})
        for a in actions:
            if a.involves_phi:
                session_volume[a.session_id]["agent_id"] = a.agent_id
                session_volume[a.session_id]["volume"] += a.phi_volume
                session_volume[a.session_id]["action_id"] = a.action_id

        violations: list[ViolationRecord] = []
        for session_id, info in session_volume.items():
            if info["volume"] > BULK_ACCESS_THRESHOLD:
                violations.append(_make_violation(
                    "V-005",
                    agent_id=info["agent_id"],
                    action_id=info["action_id"],
                    evidence={
                        "session_id": session_id,
                        "phi_volume": info["volume"],
                        "threshold": BULK_ACCESS_THRESHOLD,
                    },
                    phi_impact="confirmed_phi_exposure",
                    patient_count=info["volume"],
                    remediation=(
                        f"Session {session_id} accessed {info['volume']} patient records "
                        f"(threshold: {BULK_ACCESS_THRESHOLD}). Review for minimum necessary compliance. "
                        "If unauthorized, initiate breach analysis under §164.402."
                    ),
                ))
        return violations

    def _detect_excessive_sessions(self, actions: list[AgentAction]) -> list[ViolationRecord]:
        """V-012: Detect sessions exceeding MAX_SESSION_HOURS."""
        session_times: dict[str, dict] = defaultdict(lambda: {"agent_id": "", "action_id": "", "timestamps": []})
        for a in actions:
            session_times[a.session_id]["agent_id"] = a.agent_id
            session_times[a.session_id]["action_id"] = a.action_id
            session_times[a.session_id]["timestamps"].append(a.timestamp)

        violations: list[ViolationRecord] = []
        for session_id, info in session_times.items():
            if len(info["timestamps"]) < 2:
                continue
            sorted_ts = sorted(info["timestamps"])
            try:
                t_start = datetime.fromisoformat(sorted_ts[0])
                t_end = datetime.fromisoformat(sorted_ts[-1])
                if t_start.tzinfo is None:
                    t_start = t_start.replace(tzinfo=timezone.utc)
                if t_end.tzinfo is None:
                    t_end = t_end.replace(tzinfo=timezone.utc)
                hours = (t_end - t_start).total_seconds() / 3600
                if hours > MAX_SESSION_HOURS:
                    violations.append(_make_violation(
                        "V-012",
                        agent_id=info["agent_id"],
                        action_id=info["action_id"],
                        evidence={
                            "session_id": session_id,
                            "duration_hours": round(hours, 2),
                            "max_hours": MAX_SESSION_HOURS,
                            "session_start": sorted_ts[0],
                            "session_end": sorted_ts[-1],
                        },
                        phi_impact="potential_phi_exposure",
                        patient_count=0,
                        remediation=(
                            f"Session {session_id} lasted {hours:.1f} hours, "
                            f"exceeding the {MAX_SESSION_HOURS}-hour limit. "
                            "Implement automatic session termination and re-authentication."
                        ),
                    ))
            except (ValueError, TypeError):
                pass
        return violations

    def _detect_redundant_access(self, actions: list[AgentAction]) -> list[ViolationRecord]:
        """V-020: Detect redundant PHI access (same resource re-read within window)."""
        from collections import defaultdict
        # Group by agent+resource_id
        access_map: dict[str, list[AgentAction]] = defaultdict(list)
        for a in actions:
            if a.involves_phi and a.operation in {"read", "query"} and a.resource_id:
                key = f"{a.agent_id}::{a.resource_id}"
                access_map[key].append(a)

        violations: list[ViolationRecord] = []
        for key, resource_actions in access_map.items():
            if len(resource_actions) < 2:
                continue
            sorted_actions = sorted(resource_actions, key=lambda a: a.timestamp)
            for i in range(1, len(sorted_actions)):
                prev = sorted_actions[i - 1]
                curr = sorted_actions[i]
                try:
                    t1 = datetime.fromisoformat(prev.timestamp)
                    t2 = datetime.fromisoformat(curr.timestamp)
                    if t1.tzinfo is None:
                        t1 = t1.replace(tzinfo=timezone.utc)
                    if t2.tzinfo is None:
                        t2 = t2.replace(tzinfo=timezone.utc)
                    gap_minutes = (t2 - t1).total_seconds() / 60
                    if gap_minutes <= REDUNDANT_ACCESS_MINUTES:
                        violations.append(_make_violation(
                            "V-020",
                            agent_id=curr.agent_id,
                            action_id=curr.action_id,
                            evidence={
                                "resource_id": curr.resource_id,
                                "gap_minutes": round(gap_minutes, 2),
                                "threshold_minutes": REDUNDANT_ACCESS_MINUTES,
                                "previous_access": prev.timestamp,
                                "current_access": curr.timestamp,
                                "session_ids": [prev.session_id, curr.session_id],
                            },
                            phi_impact="potential_phi_exposure",
                            patient_count=curr.phi_volume,
                            remediation=(
                                f"Resource '{curr.resource_id}' was re-read within "
                                f"{gap_minutes:.1f} minutes. Review for data harvesting pattern. "
                                "If the agent caches results properly, this read should be unnecessary."
                            ),
                        ))
                        break  # One violation per resource_id pair is sufficient
                except (ValueError, TypeError):
                    pass
        return violations


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

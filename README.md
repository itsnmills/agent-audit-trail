# AI Agent Audit Trail Generator

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-63%20passing-brightgreen)
![HIPAA Compliant](https://img.shields.io/badge/HIPAA-%C2%A7164.312%20Compliant-blue)
![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%20Aligned-informational)

**HIPAA-compliant audit trail and compliance engine for AI agents operating in healthcare environments.**

Healthcare organizations are deploying AI agents to handle clinical documentation, prior authorization, and diagnostic decision support — yet most have no governance infrastructure to audit what those agents access, detect PHI exposure, or demonstrate compliance with HIPAA's Technical Safeguards. This tool closes that gap: it ingests AI agent action records in five standard formats, maintains a tamper-evident SHA-256 hash chain audit log, evaluates 33 HIPAA controls across 8 control families, detects 20 categories of compliance violations in real time, and generates executive-ready PDF compliance reports — all grounded in the 2025 HIPAA Security Rule amendments, NIST SP 800-66r2, and the NIST AI RMF.

---

## The Problem

Hospitals are deploying large language models and specialized ML agents into clinical workflows at an unprecedented rate. Systems like Epic DAX transcribe physician encounters. Prior authorization automation agents query insurance APIs using patient PHI. Sepsis early-warning classifiers run continuously on vitals streams across entire emergency departments. Radiology AI triage tools process imaging studies and push alerts. Each of these systems is a *software program* accessing electronic Protected Health Information — and under HIPAA §164.312(a)(1), software programs are explicitly in scope for the same access control requirements as human users.

HIPAA §164.312(b) requires covered entities to "implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI." For AI agents, this means capturing the agent's authenticated identity, the human authorizer who delegated the workflow, the specific operation performed, the PHI records accessed, the policy context governing the access decision, and a tamper-evident timestamp — for every action, not just sessions. Standard API gateway logs are insufficient: they operate at the wrong granularity and contain none of the delegation chain context that §164.312(d) requires. The [2025 HIPAA Security Rule amendments](https://csrc.nist.gov/News/2024/nist-publishes-sp-80066-revision-2-implementing-th) make this more urgent by mandating encryption (previously addressable), tightening risk analysis requirements to explicitly cover AI systems, and imposing direct Security Rule liability on business associates — meaning third-party AI vendors can no longer disclaim responsibility for their agents' PHI access patterns.

Most healthcare organizations have no governance infrastructure for AI agent PHI access. Agents share service account credentials, run without BAAs, generate no delegation chains, and trigger no alerts when they access 3,000 patient records in a single session. [Imprivata's Agentic Identity Management framework](https://www.imprivata.com/company/press/imprivata-introduces-agentic-identity-management-secure-and-govern-ai-agents), unveiled at HIMSS 2026, treats AI agents as managed identities requiring authentication, least-privilege enforcement, and real-time monitoring — the same principles that underpin this tool's compliance engine. This is not a hypothetical future requirement: it is the current state of HIPAA enforcement applied to a category of software that most compliance teams have not yet inventoried.

> **§164.312(b):** *"Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information."*
> — HIPAA Security Rule, 45 CFR §164.312(b)

---

## Features

### Agent Identity Management — §164.312(a)(2)(i)
- Unique agent ID registry with vendor, model version, deployment environment, owner, and role
- Complete human delegation chains: every action is traceable to an authenticated human authorizer
- Credential rotation tracking with configurable maximum age enforcement
- Business Associate Agreement (BAA) reference tracking for third-party AI vendors
- Authentication method classification: OAuth 2.0, mTLS, SAML, API key
- FAVES-aligned metadata fields per ONC HTI-1 (intended use, cautioned uses, demographic representativeness)

### Tamper-Evident Audit Trail — §164.312(b)
- SHA-256 hash chain linking every audit record to its predecessor (blockchain-style integrity)
- Append-only SQLite store with hash chain gap detection (violation V-010)
- Captures: agent ID, human authorizer, operation, PHI categories, patient count, network zone, encryption state, session ID, target system, response time, and delegation chain — per action
- FHIR R4 AuditEvent native support for EHR-native ingestion
- ALCOA+ compliant record structure: Attributable, Legible, Contemporaneous, Original, Accurate

### Compliance Assessment Engine — 33 Controls, 8 Families
- Full §164.312 Technical Safeguards coverage: AC, AU, IN, PA, TS
- Minimum Necessary (MN) controls: §164.502(b) operation-level enforcement and scope drift detection
- Risk Management (RM) controls: NIST AI RMF Govern/Map/Measure/Manage alignment scoring
- ONC HTI-1 Transparency (OT) controls: FAVES principles and FDA ALCOA+ compliance
- Each control produces a pass/partial/fail finding grounded in actual audit data, with evidence citations and remediation guidance
- Weighted scoring: required controls outweigh addressable controls per §164.312 implementation spec hierarchy

### Real-Time Violation Detection — 20 Rules
- 5 critical rules: unencrypted PHI access, missing human authorizer, unencrypted external transmission, unauthenticated PHI access, bulk exfiltration pattern
- 5 high rules: minimum necessary violations, stale credentials, missing BAA, cross-department access, audit log chain gap
- 5 medium rules: non-FIPS encryption, excessive session duration, PHI in unstructured output, incomplete delegation chain, shadow agent detection
- 5 low rules: after-hours access, deprecated agent still active, missing operation detail, long query response time, redundant PHI access
- CVSS-inspired risk scoring (0.0–10.0) with PHI impact and patient count amplifiers
- Evidence-based: every violation record includes the specific fields that triggered it

### Multi-Format Ingestion — 5 Formats
- **JSON** — native `AgentAction` model (full field set)
- **JSONL** — streaming log ingestion
- **CSV** — tabular export from existing SIEM or EHR audit systems
- **CEF** — ArcSight Common Event Format for SIEM integration
- **FHIR R4 AuditEvent** — native HL7 FHIR format for Epic/Cerner interoperability

### PDF + Markdown Compliance Reports
- Executive Summary with overall compliance score and risk rating
- Per-control findings with evidence citations and remediation deadlines
- Violation inventory with severity distribution and PHI impact assessment
- Regulatory reference mapping (HIPAA §164.312, NIST CSF, NIST 800-53, NIST AI RMF)
- 6-year retention metadata per §164.316(b)(2)(i)

### FastAPI Dashboard with Real-Time Alerts
- Dark-mode terminal UI at `localhost:8090`
- Server-Sent Events (SSE) real-time violation stream — no polling required
- Agent status overview, recent violations, compliance score trend
- REST API for programmatic integration with existing SIEM/SOAR infrastructure

### NIST AI RMF Alignment Scoring
- Scores each AI agent across the four RMF functions: GOVERN, MAP, MEASURE, MANAGE
- Detects missing governance artifacts: no FAVES assessment, no PCCP, no drift monitoring
- Maps findings to specific NIST AI RMF subcategories and corresponding NIST 800-53 controls

### Demo Mode — 8 Healthcare AI Personas
- Realistic scenario data covering the full violation spectrum
- Each agent models a real-world product category (Nuance DAX, Aidoc, 3M CDI, Abridge, Orbita)
- Includes intentionally misconfigured agents to demonstrate violation detection end-to-end

---

## Architecture

```
                        ┌─────────────────────────────────────────────────────┐
                        │              AI Agent Audit Trail Generator          │
                        └─────────────────────────────────────────────────────┘

  Agent Actions
  (JSON/JSONL/CSV/CEF/FHIR R4)
          │
          ▼
  ┌───────────────┐     ┌─────────────────┐     ┌──────────────────────────────┐
  │   Ingestion   │────▶│  Normalization  │────▶│  AuditStore (SQLite)         │
  │   Layer       │     │  (AgentAction   │     │  Tamper-Evident Hash Chain   │
  │               │     │   model)        │     │  SHA-256 per record          │
  └───────────────┘     └─────────────────┘     └──────────────┬───────────────┘
                                                               │
                                           ┌───────────────────┼───────────────────────┐
                                           │                   │                       │
                                           ▼                   ▼                       ▼
                                ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
                                │ Compliance Engine│  │ Violation Detect.│  │ Report Generator │
                                │ 33 controls      │  │ 20 rules         │  │ PDF + Markdown   │
                                │ 8 control fams.  │  │ Real-time SSE    │  │ §164.316(b) ret. │
                                └──────────────────┘  └──────────────────┘  └──────────────────┘
                                           │                   │
                                           └─────────┬─────────┘
                                                     ▼
                                         ┌─────────────────────┐
                                         │  FastAPI Dashboard  │
                                         │  localhost:8090     │
                                         │  Dark-mode terminal │
                                         └─────────────────────┘
```

---

## Compliance Framework Mapping

The control library maps every control to its HIPAA section, NIST CSF subcategory, NIST 800-53 control, and NIST AI RMF function. A representative cross-section:

| Control | HIPAA Section | NIST CSF | NIST 800-53 | AI RMF | Description |
|---------|--------------|----------|-------------|--------|-------------|
| AC-001 | §164.312(a)(2)(i) | PR.AC-1 | IA-2 | Govern | Unique Agent Identification |
| AC-002 | §164.312(a)(2)(i) | PR.AC-4 | AC-2 | Govern | Human Delegation Traceability |
| AC-005 | §164.312(a)(2)(iv) | PR.DS-1 | SC-28 | Manage | Encryption at Rest (2025 Mandatory) |
| AC-007 | §164.502(b) | PR.DS-5 | AC-3 | Govern | Minimum Necessary — Operation-Level |
| AU-001 | §164.312(b) | DE.CM-3 | AU-2 | Measure | Audit Trail Completeness |
| AU-002 | §164.312(b) | PR.DS-6 | AU-9 | Manage | Tamper-Evident Audit Log |
| AU-004 | §164.312(b) | DE.AE-2 | SI-4 | Measure | Real-Time Anomaly Detection |
| IN-003 | §164.312(b) | PR.DS-6 | AU-9 | Manage | Hash Chain Validation |
| PA-001 | §164.312(d) | PR.AC-7 | IA-3 | Govern | Agent Authentication Before PHI Access |
| PA-004 | §164.308(b) | GV.SC-4 | SA-9 | Govern | Business Associate Agreement Coverage |
| TS-001 | §164.312(e)(2)(ii) | PR.DS-2 | SC-8 | Manage | Encryption in Transit (2025 Mandatory) |
| TS-002 | §164.312(e)(2)(ii) | PR.DS-2 | SC-13 | Manage | FIPS 140-3 Validated Encryption |
| MN-003 | §164.502(b) | DE.AE-3 | AC-2 | Measure | PHI Scope Drift Detection |
| RM-002 | §164.308(a)(1) | ID.AM-2 | PM-5 | Map | AI System Inventory and Risk Mapping |
| OT-001 | ONC HTI-1 | GV.OC-5 | SA-4 | Govern | AI Transparency — FAVES Principles |
| OT-002 | FDA AI Guidance | PR.DS-6 | AU-3 | Measure | FDA ALCOA+ Audit Record Quality |

> **Note on the 2025 amendments:** Controls AC-005 (encryption at rest) and TS-001 (encryption in transit) are marked `required` rather than `addressable` in the control library, reflecting the [2025 HIPAA Security Rule amendments](https://csrc.nist.gov/News/2024/nist-publishes-sp-80066-revision-2-implementing-th) that removed encryption's addressable status. Compliance reports flag any deviation as a critical finding.

---

## Quick Start

```bash
git clone https://github.com/itsnmills/agent-audit-trail.git
cd agent-audit-trail
pip install -r requirements.txt

# Populate the database with 8 realistic healthcare AI agent scenarios
python -m agent_audit demo

# Launch the real-time dashboard at http://localhost:8090
python -m agent_audit serve

# Run a full HIPAA compliance assessment
python -m agent_audit assess

# Generate a PDF compliance report
python -m agent_audit report --format pdf --output report.pdf
```

---

## Usage Examples

### 1. Run Demo Mode

Populates the audit database with 8 healthcare AI agent personas and their action histories, covering the full spectrum of compliance violations.

```bash
python -m agent_audit demo --seed 42
```

```
[demo] Registering 8 healthcare AI agents...
[demo] Seeding action records for agent-dax-001 (Clinical Documentation Assistant v2.3)...
[demo] Seeding action records for agent-prior-auth-002 (Prior Authorization Automation v1.4)...
[demo] Seeding action records for agent-cds-003 (Sepsis Early Warning System v3.1)...
...
[demo] Running violation detection on seeded data...
[demo] Detected 14 violations (3 critical, 4 high, 4 medium, 3 low)
[demo] Done. Run 'python -m agent_audit assess' to view compliance status.
```

### 2. Assess Compliance

Evaluates all 33 controls against live audit data and prints a summary.

```bash
python -m agent_audit assess
```

```
HIPAA Compliance Assessment
────────────────────────────────────────────────────────
Overall Score:     67.3 / 100   [PARTIAL COMPLIANCE]
Controls Passed:   21 / 33
Controls Failed:    7 / 33
Controls Partial:   5 / 33

Control Family Summary:
  AC (Access Control)          6/8   PARTIAL
  AU (Audit Controls)          5/6   PARTIAL
  IN (Integrity)               3/3   COMPLIANT
  PA (Authentication)          2/4   PARTIAL
  TS (Transmission Security)   2/4   NON-COMPLIANT
  MN (Minimum Necessary)       1/3   NON-COMPLIANT
  RM (Risk Management)         1/3   NON-COMPLIANT
  OT (Transparency)            1/2   PARTIAL
```

### 3. Generate a Compliance Report

```bash
# PDF report
python -m agent_audit report --format pdf --output compliance_report.pdf

# Markdown report
python -m agent_audit report --format markdown --output compliance_report.md
```

```
[report] Generating PDF compliance report...
[report] Fetching 33 control assessments...
[report] Fetching 14 open violations...
[report] Writing compliance_report.pdf (47 pages)
[report] Done.
```

### 4. Verify Hash Chain Integrity

Validates the SHA-256 hash chain across the entire audit log. Detects deletions, insertions, or modifications.

```bash
python -m agent_audit verify
```

```
[verify] Checking hash chain integrity across 1,247 audit records...
[verify] Chain intact. No gaps or modifications detected.
[verify] First record: 2026-01-15T08:22:14Z  Hash: a3f7c2...
[verify] Last record:  2026-04-07T10:44:53Z  Hash: 9e12b8...
```

### 5. Detect Violations

```bash
# Show all open violations
python -m agent_audit violations

# Filter by severity
python -m agent_audit violations --severity critical

# Detect shadow (unregistered) agents
python -m agent_audit detect-shadow

# Detect bulk PHI exfiltration for a specific agent
python -m agent_audit detect-exfil --agent-id agent-prior-auth-002

# Detect PHI scope drift over the past 30 days
python -m agent_audit detect-scope-drift --agent-id agent-prior-auth-002 --window 30
```

```
Open Violations (3 critical)
────────────────────────────────────────────────────────
V-001  CRITICAL  agent-cds-003    Unencrypted PHI Access           §164.312(a)(2)(iv)  Score: 9.2
V-003  CRITICAL  agent-radiology-005  PHI Transmitted Unencrypted  §164.312(e)         Score: 9.8
V-005  CRITICAL  agent-prior-auth-002 Bulk PHI Exfiltration        §164.502(b)         Score: 9.5
```

### 6. Ingest Custom Data

```bash
# Ingest a FHIR R4 AuditEvent bundle from an Epic export
python -m agent_audit ingest --format fhir --file epic_audit_export.json

# Ingest from a CSV export
python -m agent_audit ingest --format csv --file siem_export.csv

# Ingest CEF-format logs from ArcSight
python -m agent_audit ingest --format cef --file arcsight.log
```

### 7. Launch the Dashboard

```bash
python -m agent_audit serve --port 8090
```

Open `http://localhost:8090` to access the dark-mode terminal dashboard with:
- Live agent status grid
- Real-time violation stream (SSE — no polling)
- Compliance score gauges by control family
- Hash chain status indicator

---

## Demo Agents

The 8 demo agents model real-world healthcare AI product categories. Each is configured to trigger specific violations, demonstrating the detection engine end-to-end.

| Agent | Type | Vendor | Risk Tier | Violations Triggered |
|-------|------|--------|-----------|----------------------|
| Clinical Documentation Assistant v2.3 (DAX) | Clinical Documentation | Nuance/DAX | High | Nominal — no violations (baseline) |
| Prior Authorization Automation v1.4 | Prior Auth | Custom | High | V-005 Bulk PHI Exfiltration, V-007 Stale Credentials |
| Sepsis Early Warning System v3.1 | Decision Support | Custom | Critical | V-016 After-Hours Access, V-001 Unencrypted PHI |
| Medical Coding Assistant v2.0 | Coding | 3M | Medium | V-007 Stale Credentials (100+ days) |
| Radiology AI Triage v1.2 (Aidoc) | Diagnostic Imaging | Aidoc | High | V-011 Non-FIPS Encryption, V-003 External Unencrypted PHI |
| Patient Triage Chatbot v1.0 (Orbita) | Chatbot | Orbita | High | V-008 Missing Business Associate Agreement |
| Discharge Summary Generator v1.5 (Abridge) | Clinical Documentation | Abridge | High | Nominal — full compliance (positive baseline) |
| Clinical Research Query Agent v1.0 | Research | Custom | Medium | V-017 Deprecated Agent Still Active |

The demo also injects a ninth **shadow agent** (`agent-shadow-unregistered`) that does not appear in the identity registry, triggering V-015 (Shadow Agent Detected).

---

## Violation Detection Rules

All 20 rules with their severity tier, HIPAA grounding, and detection logic:

| Rule | Severity | HIPAA Section | Description |
|------|----------|--------------|-------------|
| V-001 | Critical | §164.312(a)(2)(iv) + §164.312(e)(2)(ii) | Unencrypted PHI access — encryption_in_transit or encryption_at_rest is False |
| V-002 | Critical | §164.312(d) | Missing human authorizer — no human_authorizer_id in action record |
| V-003 | Critical | §164.312(e) | PHI transmitted to external system without encryption in transit |
| V-004 | Critical | §164.312(d) | Agent accessed PHI with no last_authenticated timestamp on record |
| V-005 | Critical | §164.502(b) | Bulk PHI exfiltration — >500 distinct patient records in a single session |
| V-006 | High | §164.502(b) | Minimum necessary violation — unrestricted scope with no access justification |
| V-007 | High | §164.312(d) | Stale credentials — last rotation >90 days ago |
| V-008 | High | §164.308(b) | Third-party agent operating without a Business Associate Agreement |
| V-009 | High | §164.312(a) | Cross-department PHI access outside the agent's designated scope |
| V-010 | High | §164.312(b) | Audit log hash chain gap — records may have been deleted or modified |
| V-011 | Medium | §164.312(e)(2)(ii) | Encryption present but non-FIPS 140-3 validated module used |
| V-012 | Medium | §164.312(a)(2)(iii) | Session duration exceeded maximum hours without re-authentication |
| V-013 | Medium | §164.312(c) | PHI produced in unstructured output format outside classification controls |
| V-014 | Medium | §164.312(d) | Delegation chain has fewer than 2 entries — incomplete chain of custody |
| V-015 | Medium | §164.312(a) | Shadow agent — agent_id in action records not found in identity registry |
| V-016 | Low | §164.312(b) | Agent PHI operations outside business hours (00:00–06:00 default window) |
| V-017 | Low | §164.312(a) | Decommissioned or under-review agent still generating action records |
| V-018 | Low | §164.312(b) | Missing operation_detail field — audit record below §164.312(b) granularity |
| V-019 | Low | §164.312(a) | Query response time >30 seconds — potential data harvesting or API abuse |
| V-020 | Low | §164.502(b) | Redundant PHI access — same record re-read within 5 minutes without an intervening write |

Risk scores use a CVSS-inspired formula: base severity score × PHI impact multiplier, amplified by patient count (>100 records: +0.75; >500 records: +1.5), capped at 10.0.

---

## Compliance Reports

PDF and Markdown reports are generated from live assessment data and include:

1. **Executive Summary** — overall compliance score, risk rating (Compliant / Substantial / Partial / Critical), and top-line findings
2. **Scope and Regulatory Basis** — HIPAA sections assessed, amendment status, assessment date and period
3. **Control Family Summaries** — pass/partial/fail counts for AC, AU, IN, PA, TS, MN, RM, OT
4. **Detailed Control Findings** — per-control evidence citations, test procedure results, and specific remediation actions with suggested owners and deadlines
5. **Violation Inventory** — all open violations with severity, PHI impact, patient count, and evidence
6. **Remediation Roadmap** — prioritized action items sorted by risk score
7. **Regulatory Reference Matrix** — cross-reference table mapping findings to HIPAA, NIST CSF, NIST 800-53, and NIST AI RMF
8. **Audit Log Metadata** — hash chain status, record count, retention period, log integrity attestation

Reports include a retention timestamp and are suitable for presentation to a HIPAA Security Officer, Privacy Officer, or external auditor. The 6-year retention requirement of §164.316(b)(2)(i) is noted in each report header.

---

## Python API

The tool can be used as a library in existing healthcare security tooling:

```python
from agent_audit import AuditStore, ActionIngester, ComplianceEngine, ViolationDetector

# Initialize the audit store (creates SQLite DB if not present)
store = AuditStore("data/audit.db")

# Ingest agent actions from a FHIR R4 AuditEvent file
ingester = ActionIngester(store)
ingester.ingest_file("epic_export.json", format="fhir")

# Run the compliance assessment
engine = ComplianceEngine(store)
report = engine.assess_all()
print(f"Compliance score: {report.overall_score:.1f}/100 [{report.rating}]")

# Detect violations across all recent actions
detector = ViolationDetector(store)
actions = store.query_actions(start="2026-04-01T00:00:00Z")
violations = detector.analyze_batch(actions)
for v in violations:
    print(f"[{v.severity.upper()}] {v.violation_type} — agent: {v.agent_id} — score: {v.severity_score}")
    store.store_violation(v)

# Check for shadow agents
shadow_violations = detector.detect_shadow_agents()

# Detect bulk exfiltration for a specific agent
exfil = detector.detect_exfiltration_pattern("agent-prior-auth-002", window_minutes=60)

# Verify hash chain integrity
is_intact = store.verify_chain_integrity()

# Generate a PDF report
from agent_audit import ReportGenerator
gen = ReportGenerator(store)
gen.generate_pdf("compliance_report.pdf")
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `python -m agent_audit demo` | Populate database with 8 realistic healthcare AI agent scenarios |
| `python -m agent_audit ingest` | Ingest agent action records (JSON, JSONL, CSV, CEF, FHIR R4) |
| `python -m agent_audit assess` | Run full 33-control HIPAA compliance assessment |
| `python -m agent_audit report` | Generate PDF or Markdown compliance report |
| `python -m agent_audit verify` | Validate SHA-256 hash chain integrity |
| `python -m agent_audit violations` | List open violations (filterable by severity/agent) |
| `python -m agent_audit agents` | List registered agents and their compliance status |
| `python -m agent_audit serve` | Launch FastAPI dashboard at localhost:8090 |
| `python -m agent_audit detect-shadow` | Find unregistered agents in action logs |
| `python -m agent_audit detect-exfil` | Detect bulk PHI exfiltration patterns |
| `python -m agent_audit detect-scope-drift` | Detect gradual PHI access scope expansion over time |

---

## Regulatory References

This tool is grounded in the following primary regulatory and standards documents:

| Document | Relevance |
|----------|-----------|
| [HIPAA Security Rule — 45 CFR §164.312](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html) | Technical Safeguards — primary compliance target |
| [NIST SP 800-66r2 — Implementing the HIPAA Security Rule](https://csrc.nist.gov/News/2024/nist-publishes-sp-80066-revision-2-implementing-th) | HIPAA implementation guidance, published February 2024 |
| [NIST AI Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf) | GOVERN / MAP / MEASURE / MANAGE functions for healthcare AI |
| [NIST Cybersecurity Framework 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf) | Control subcategory mappings (PR.AC, DE.CM, PR.DS) |
| [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) | Security control baseline (IA, AU, AC, SC, SI families) |
| [ONC HTI-1 Rule — 45 CFR Part 170](https://www.federalregister.gov/documents/2024/04/18/2024-07953/health-data-technology-and-interoperability-certification-program-updates-algorithm-transparency-and) | AI transparency (FAVES), predictive DSI governance |
| [FDA AI/ML Action Plan & 2025 Guidance](https://www.fda.gov/medical-devices/software-medical-device-samd/artificial-intelligence-and-machine-learning-software-medical-device) | ALCOA+, GMLP, PCCP requirements for AI in medical devices |
| [Kiteworks — AI Agents and HIPAA PHI Access](https://www.kiteworks.com/hipaa-compliance/ai-agents-hipaa-phi-access/) | Analysis of §164.312 applied to AI agents |
| [Imprivata — Agentic Identity Management (HIMSS 2026)](https://www.imprivata.com/company/press/imprivata-introduces-agentic-identity-management-secure-and-govern-ai-agents) | Zero Trust principles applied to AI agent identities |
| [Prefactor — AI Agent Identity Audit Standards](https://prefactor.tech/blog/ai-agent-identity-audits-reporting-standards/) | Agent audit metrics, reporting structure, ISACA alignment |

---

## Project Structure

```
agent-audit-trail/
├── agent_audit/
│   ├── __init__.py          # Public API exports
│   ├── models.py            # AgentIdentity, AgentAction, ViolationRecord, ComplianceControl
│   ├── storage.py           # AuditStore — tamper-evident SQLite with SHA-256 hash chain
│   ├── ingestion.py         # ActionIngester — JSON, JSONL, CSV, CEF, FHIR R4 parsers
│   ├── compliance.py        # ComplianceEngine — 33 controls, 8 control families
│   ├── violations.py        # ViolationDetector — 20 detection rules
│   ├── reporting.py         # ReportGenerator — PDF and Markdown output
│   ├── dashboard.py         # FastAPI app with SSE real-time violation stream
│   ├── demo.py              # 8 healthcare AI agent personas with realistic scenarios
│   ├── cli.py               # 11-command CLI (argparse)
│   └── config.py            # Thresholds, constants, FIPS algorithm lists
├── tests/
│   └── test_models.py       # 63 passing tests
├── requirements.txt
├── setup.py
└── README.md
```

**Statistics:** 10,073 lines of Python across 13 source files, 63 passing tests.

---

## Contributing

Contributions are welcome. Areas of particular interest:

- Additional ingestion formats (HL7 v2, X12 270/271, OpenTelemetry)
- Additional compliance controls (HITRUST CSF, SOC 2 Type II crosswalk)
- SIEM export connectors (Splunk HEC, Elastic, Microsoft Sentinel)
- PostgreSQL backend option for enterprise-scale deployments
- MFA and network segmentation control assessments (2025 HIPAA amendment requirements)

Please open an issue before submitting a pull request for significant changes. All contributions must include tests and must not reduce the current test pass rate.

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=agent_audit --cov-report=term-missing
```

---

## License

MIT License. See `LICENSE` for details.

This tool is provided for educational and professional portfolio purposes. It is not a substitute for legal advice or a formal HIPAA compliance audit conducted by a qualified healthcare compliance professional.

---

## Author

**Noah Mills** — Cybersecurity professional focused on healthcare AI security, HIPAA technical safeguards, and the governance of AI systems operating in clinical environments.

- GitHub: [@itsnmills](https://github.com/itsnmills)
- Focus: Healthcare IT security, HIPAA compliance engineering, AI governance, identity and access management for clinical AI systems

---

*Grounded in HIPAA 45 CFR §164.312, NIST SP 800-66r2, NIST AI RMF 1.0, NIST CSF 2.0, NIST SP 800-53 Rev. 5, ONC HTI-1, and FDA 2025 AI/ML Guidance.*

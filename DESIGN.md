# CRA-AGENT — Design Document

## 1. Problem Statement

The EU Cyber Resilience Act (CRA) mandates that manufacturers of products with digital elements ensure cybersecurity throughout the product lifecycle. This includes:

- Continuous vulnerability identification and assessment
- Timely remediation of discovered vulnerabilities
- Transparent reporting to authorities and users
- Maintaining an SBOM (Software Bill of Materials)

Manual compliance is expensive, error-prone, and slow. CRA-AGENT automates the vulnerability management loop end-to-end.

## 2. System Goals

| Goal | Description |
|------|-------------|
| **Continuous Scanning** | Scan every commit for new vulnerabilities |
| **Intelligent Triage** | Classify and prioritize findings using LLM reasoning |
| **Automated Ticketing** | Create Jira tickets with actionable recommendations |
| **Reactive Autonomy** | Respond to Jira updates — suppress or fix |
| **Audit Trail** | Every decision is logged with reasoning |
| **CRA Mapping** | Map findings to CRA articles/annexes |

## 3. Architecture

### 3.1 High-Level Flow

```
                    ┌──────────────┐
                    │  Git Commit  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Git Monitor  │  (polling or webhook)
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │Diff Analyzer │  (changed files + hunks)
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │     Scanner Agent       │
              │  ┌────────┐ ┌────────┐  │
              │  │Dep Scan│ │SAST   │  │
              │  └────────┘ └────────┘  │
              │  ┌────────┐ ┌────────┐  │
              │  │Secrets │ │Custom │  │
              │  └────────┘ └────────┘  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Suppression Filter    │  (remove known/ignored)
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │     Triage Agent        │  (LLM-powered classification)
              │  - Severity scoring     │
              │  - Exploitability       │
              │  - CRA relevance        │
              │  - Fix recommendation   │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │      Jira Agent         │
              │  - Create tickets       │
              │  - Attach evidence      │
              │  - Set priority/labels  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Jira Webhook Server   │
              │  (listens for updates)  │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │    Action Router        │
              │  ┌────────┐ ┌────────┐  │
              │  │Suppress│ │Fix     │  │
              │  └────────┘ └────────┘  │
              └─────────────────────────┘
```

### 3.2 Agent Orchestration (LangGraph)

The agent layer uses a **LangGraph state machine** with the following states:

```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ SCANNING│───▶│FILTERING │───▶│ TRIAGING │───▶│ TICKETING│───▶│ COMPLETE │
└─────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
                     │               │                │
                     │          ┌────▼────┐     ┌─────▼─────┐
                     │          │ FIXING  │     │ SUPPRESSING│
                     │          └─────────┘     └───────────┘
                     │
              ┌──────▼──────┐
              │ NO FINDINGS │
              └─────────────┘
```

**State Schema:**
```python
class AgentState(TypedDict):
    commit_hash: str
    changed_files: list[FileChange]
    raw_findings: list[Finding]
    filtered_findings: list[Finding]
    triaged_findings: list[TriagedFinding]
    jira_tickets: list[JiraTicket]
    actions_taken: list[Action]
    errors: list[str]
```

### 3.3 Jira Webhook Reaction Flow

```
Jira Issue Updated
        │
        ▼
  Parse Webhook Payload
        │
        ▼
  Extract Issue Key + Transition/Comment
        │
        ├──▶ Transition = "Ignore" / "Won't Fix" / "Known Issue"
        │         │
        │         ▼
        │    Add Suppression Rule
        │    (vuln_id, reason, expiry)
        │         │
        │         ▼
        │    Confirm on Jira ticket
        │
        ├──▶ Transition = "Fix Required" / "To Do"
        │         │
        │         ▼
        │    FixerAgent generates fix
        │         │
        │         ▼
        │    Create branch + PR
        │         │
        │         ▼
        │    Update Jira with PR link
        │
        └──▶ Transition = "Reopen"
                  │
                  ▼
             Re-scan the finding
                  │
                  ▼
             Update triage if needed
```

## 4. Component Design

### 4.1 Git Monitor

- **Polling mode**: Periodically checks for new commits on configured branches
- **Webhook mode**: Receives push events from GitHub/GitLab/Bitbucket
- **State**: Tracks last-seen commit hash per branch in SQLite

### 4.2 Diff Analyzer

- Extracts changed files between commits
- Produces structured `FileChange` objects with:
  - File path, change type (added/modified/deleted)
  - Line-level hunks (added/removed lines)
  - File content (for scanner context)

### 4.3 Scanners

All scanners implement `BaseScanner`:

```python
class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, files: list[FileChange]) -> list[Finding]:
        """Scan files and return findings."""
        ...

    @abstractmethod
    def name(self) -> str:
        """Scanner identifier."""
        ...
```

| Scanner | Tool | Detects |
|---------|------|---------|
| `DependencyScanner` | pip-audit / osv-scanner | Known CVEs in dependencies |
| `SASTScanner` | semgrep | Code-level vulnerabilities (injection, XSS, etc.) |
| `SecretsScanner` | gitleaks / detect-secrets | Hardcoded secrets, API keys |

### 4.4 Suppression Store

SQLite-backed store for vulnerability suppressions:

```sql
CREATE TABLE suppressions (
    id TEXT PRIMARY KEY,
    vuln_id TEXT NOT NULL,          -- e.g., CVE-2024-1234
    file_pattern TEXT,              -- optional file glob
    reason TEXT NOT NULL,           -- why suppressed
    jira_issue_key TEXT,            -- linked Jira ticket
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,           -- optional expiry
    created_by TEXT DEFAULT 'agent'
);
```

### 4.5 Triage Agent

LLM-powered classification with structured output:

```python
class TriageResult(BaseModel):
    severity: Literal["critical", "high", "medium", "low", "info"]
    exploitability: Literal["confirmed", "likely", "possible", "unlikely"]
    cra_relevance: Literal["annex_i", "annex_ii", "article_13", "none"]
    recommended_action: Literal["fix_now", "fix_soon", "suppress", "investigate"]
    reasoning: str
    fix_suggestion: str | None
```

### 4.6 Fixer Agent

Generates code fixes using LLM with:
- Vulnerability context (type, location, CWE)
- Surrounding code context
- Language-specific fix patterns
- Creates a git branch and PR with the fix

### 4.7 Jira Agent

Manages the full Jira lifecycle:
- Creates issues with structured descriptions
- Attaches scan evidence (JSON + human-readable)
- Sets labels, priority, components
- Updates tickets based on agent actions

## 5. Data Models

### 5.1 Finding

```python
class Finding(BaseModel):
    id: str  # Unique finding ID (hash)
    scanner: str  # Which scanner found it
    vuln_id: str | None  # CVE/CWE identifier
    title: str
    description: str
    severity: str  # raw scanner severity
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    metadata: dict  # scanner-specific metadata
    commit_hash: str
    timestamp: datetime
```

### 5.2 TriagedFinding

```python
class TriagedFinding(Finding):
    triage: TriageResult
    cra_mapping: list[str]  # applicable CRA articles
    sbom_component: str | None  # affected SBOM component
```

### 5.3 JiraTicket

```python
class JiraTicket(BaseModel):
    key: str  # e.g., CRA-123
    finding_id: str
    status: str
    url: str
    created_at: datetime
    updated_at: datetime
```

## 6. Configuration

All configuration via environment variables + YAML:

```yaml
# config/scanner_rules.yaml
scanners:
  dependency:
    enabled: true
    tools: ["pip-audit", "osv-scanner"]
    severity_threshold: "medium"
  sast:
    enabled: true
    tool: "semgrep"
    rulesets: ["owasp-top-ten", "cwe-top-25"]
  secrets:
    enabled: true
    tool: "gitleaks"
    allowlist: [".env.example", "test/fixtures/*"]

triage:
  auto_fix_severity: ["critical", "high"]
  suppress_on_jira_labels: ["known-issue", "false-positive", "accepted-risk"]
  fix_on_jira_transitions: ["Fix Required", "To Do"]

cra:
  sbom_format: "cyclonedx"
  reporting_authority: "BSI"  # German CRA authority
  report_exploited_within_hours: 24
```

## 7. Security Considerations

- LLM prompts never include full file contents — only relevant hunks
- Jira credentials stored in environment variables, never in code
- Webhook server validates Jira webhook signatures
- Suppression store requires audit trail (who suppressed, why, when)
- Fixer agent creates PRs — never pushes directly to main
- All agent decisions are logged with full reasoning chains

## 8. Deployment

```
┌─────────────────────────────────────────┐
│              Docker Compose              │
│                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────┐ │
│  │ Agent    │  │ Webhook  │  │SQLite │ │
│  │ Worker   │  │ Server   │  │  DB   │ │
│  └──────────┘  └──────────┘  └───────┘ │
│                                          │
│  Volumes:                                │
│  - ./data:/app/data (suppression DB)    │
│  - ./.git:/app/repo (target codebase)   │
└─────────────────────────────────────────┘
```

## 9. Future Enhancements

- [ ] Multi-repo support (scan multiple repositories)
- [ ] Slack/Teams notifications for critical findings
- [ ] CRA compliance report generation (PDF/HTML)
- [ ] SBOM generation and diffing (CycloneDX/SPDX)
- [ ] Custom scanner plugin system
- [ ] Human-in-the-loop approval for auto-fixes
- [ ] Metrics dashboard (findings over time, MTTR, etc.)
- [ ] Integration with vulnerability databases (NVD, OSV)
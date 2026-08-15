# CRA-AGENT — Cyber Resilience Act Compliance Agent

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.11%2B-green.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red.svg)](https://streamlit.io/)

An autonomous agentic AI system for continuous CRA compliance monitoring. It scans every commit, identifies vulnerabilities, creates Jira tickets with triage recommendations, and reacts to Jira webhook updates (suppress known issues or auto-fix).

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CRA-AGENT Orchestrator                       │
│                              (main.py)                               │
└──────────────┬──────────────────────────────────────┬───────────────┘
               │                                      │
     ┌─────────▼──────────┐                ┌──────────▼──────────┐
     │   Git Monitor      │                │  Webhook Server     │
     │  (commit watcher)  │                │  (Jira updates)     │
     └─────────┬──────────┘                └──────────┬──────────┘
               │                                      │
     ┌─────────▼──────────┐                ┌──────────▼──────────┐
     │  Diff Analyzer     │                │  Jira Handler       │
     │  (changed files)   │                │  (route actions)    │
     └─────────┬──────────┘                └──────────┬──────────┘
               │                                      │
     ┌─────────▼──────────────────────────────────────▼──────────┐
     │                    Agent Layer (LangGraph)                  │
     │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────┐ │
     │  │ Scanner    │ │ Triage     │ │ Fixer      │ │ Jira   │ │
     │  │ Agent      │ │ Agent      │ │ Agent      │ │ Agent  │ │
     │  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └───┬────┘ │
     └────────┼──────────────┼──────────────┼────────────┼───────┘
              │              │              │            │
     ┌────────▼──────────────▼──────────────▼────────────▼───────┐
     │                      Scanner Layer                         │
     │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │
     │  │ Dependency   │ │ SAST         │ │ Secrets          │   │
     │  │ Scanner      │ │ Scanner      │ │ Scanner          │   │
     │  └──────────────┘ └──────────────┘ └──────────────────┘   │
     │  ┌──────────────────────────────────────────────────────┐  │
     │  │ Suppression Store (SQLite) — known/ignored vulns    │  │
     │  └──────────────────────────────────────────────────────┘  │
     └────────────────────────────────────────────────────────────┘
              │
     ┌────────▼──────────────────────────────────────────────────┐
     │                   Integrations                             │
     │  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐   │
     │  │ Jira Client  │  │ LLM Client   │  │ Git Client     │   │
     │  └──────────────┘  └──────────────┘  └────────────────┘   │
     └────────────────────────────────────────────────────────────┘
```

## Project Structure

```
CRA-AGENT/
├── Project.md                  # Project requirements
├── README.md                   # This file
├── DESIGN.md                   # Detailed design document
├── pyproject.toml              # Python project config & dependencies
├── .env.example                # Environment variable template
├── config/
│   ├── __init__.py
│   ├── settings.py             # App settings (pydantic-settings)
│   └── scanner_rules.yaml      # Scanner rule definitions
├── src/
│   ├── __init__.py
│   ├── main.py                 # Entry point / orchestrator
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py           # Pydantic data models
│   │   ├── git_monitor.py      # Commit watcher (polling / webhook)
│   │   └── diff_analyzer.py    # Analyze commit diffs
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── orchestrator.py     # LangGraph state machine
│   │   ├── scanner_agent.py    # Runs scanners on diffs
│   │   ├── triage_agent.py     # Recommends triage actions
│   │   ├── fixer_agent.py      # Auto-fixes vulnerabilities
│   │   └── jira_agent.py       # Creates/updates Jira tickets
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base_scanner.py     # Abstract scanner interface
│   │   ├── dependency_scanner.py
│   │   ├── sast_scanner.py
│   │   ├── secrets_scanner.py
│   │   └── suppression_store.py
│   ├── integrations/
│   │   ├── __init__.py
│   │   ├── jira_client.py      # Jira REST API client
│   │   ├── llm_client.py       # LLM provider abstraction
│   │   └── git_client.py       # Git operations wrapper
│   ├── webhook/
│   │   ├── __init__.py
│   │   ├── server.py           # FastAPI webhook server
│   │   └── handlers.py         # Jira webhook event handlers
│   └── utils/
│       ├── __init__.py
│       ├── logger.py           # Structured logging
│       └── helpers.py          # Shared utilities
├── skills/                     # Agent skill definitions (markdown)
│   ├── scan_commit.md
│   ├── triage_vulnerability.md
│   ├── fix_vulnerability.md
│   └── handle_jira_update.md
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_scanners/
│   ├── test_agents/
│   └── test_webhook/
└── docker-compose.yml          # Local dev services
```

## Tech Stack

| Layer          | Technology                          |
|----------------|-------------------------------------|
| Language       | Python 3.11+                        |
| Agent Framework| LangGraph + LangChain               |
| Webhook Server | FastAPI + Uvicorn                   |
| Data Models    | Pydantic v2                         |
| Git            | GitPython                           |
| Jira           | httpx (async REST)                  |
| LLM            | OpenAI / Anthropic (pluggable)      |
| Suppression DB | SQLite (via sqlite3)                |
| Scanners       | semgrep, pip-audit, gitleaks (CLI)  |
| Config         | pydantic-settings + YAML            |
| Testing        | pytest + pytest-asyncio             |

## Quick Start (planned)

```bash
# 1. Install dependencies
pip install -e ".[dev]"

# 2. Configure environment
cp .env.example .env
# Edit .env with your Jira, LLM, and Git credentials

# 3. Run the agent
python -m src.main

# 4. Run webhook server (separate process)
uvicorn src.webhook.server:app --reload --port 8080
```

## Workflow

### Commit-Triggered Scan
1. `GitMonitor` detects a new commit (polling or webhook).
2. `DiffAnalyzer` extracts changed files and hunks.
3. `ScannerAgent` runs all scanners on changed files.
4. `SuppressionStore` filters out known/ignored vulnerabilities.
5. `TriageAgent` classifies remaining vulns (severity, exploitability, CRA relevance).
6. `JiraAgent` creates Jira tickets with triage recommendations.

### Jira Webhook Reaction
1. `WebhookServer` receives Jira issue update event.
2. `JiraHandler` parses the transition/comment.
3. If **"Ignore / Known Issue"** → `SuppressionStore` adds a suppression rule.
4. If **"Fix Required"** → `FixerAgent` generates and applies a fix, then opens a PR.
5. `JiraAgent` updates the ticket with the fix status.

## CRA Compliance Mapping

The agent maps findings to CRA Annex I essential requirements:
- **Annex I §1** — Security requirements (vulnerability handling)
- **Annex I §2** — Vulnerability handling process
- **Annex II** — SBOM / software component transparency
- **Article 13** — Reporting obligations for actively exploited vulnerabilities

## Features

- **Automated Vulnerability Scanning**: Scans every commit using multiple scanners (SAST, dependency, secrets)
- **AI-Powered Triage**: Uses LLMs to classify severity and recommend actions
- **Jira Integration**: Automatically creates and updates tickets
- **EUVD Sync**: Synchronizes with EU Vulnerability Database every 4 hours
- **Auto-Fix Capability**: Generates fixes and opens pull requests
- **Enterprise Dashboard**: Real-time monitoring with Streamlit UI
- **CRA Compliance Mapping**: Maps findings to CRA Annex I requirements

## Dashboard

Run the enterprise-grade dashboard:

```bash
streamlit run src/dashboard/app.py
```

Features:
- Real-time vulnerability monitoring
- EUVD auto-sync with countdown timer
- Today's top 10 vulnerabilities report
- Scan history and metrics
- ROI tracking

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:
- How to submit pull requests
- Coding standards
- Reporting issues
- Feature requests

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

```
Copyright 2026 Rohit Kulkarni

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

## Acknowledgments

- [ENISA EU Vulnerability Database](https://www.enisa.europa.eu/)
- [Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [LangGraph](https://github.com/langchain-ai/langgraph)
- [Streamlit](https://streamlit.io/)

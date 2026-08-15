# Security Policy

## Supported Versions

CRA-AGENT is pre-1.0 and under active development. Security fixes are made
against the `main` branch only.

| Version | Supported |
| ------- | --------- |
| main    | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report privately using one of:

1. [GitHub Security Advisories](https://github.com/kulkarnirohit123/cra-agent/security/advisories/new) (preferred)
2. Email: kulkarnirohit123@gmail.com

Include, where possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce (PoC code or commands, if applicable)
- Affected version/commit

You should expect an initial response within 5 business days. We'll work
with you to understand and validate the issue, and to agree on a disclosure
timeline once a fix is available.

## Scope

CRA-AGENT integrates with third-party services (GitHub, Jira, LLM
providers) and runs security scanners (bandit, semgrep, trivy, gitleaks)
against configured repositories. Vulnerabilities of interest include, but
aren't limited to:

- Credential or secret exposure (API keys, GitHub App private keys, webhook
  secrets)
- Injection issues in webhook handling or scanner invocation
- Authentication/authorization bypass in the webhook server or dashboard
- Vulnerabilities in the fixer agent that could lead to unintended code
  execution or malicious PR content

Issues in third-party dependencies should generally be reported upstream,
but flag them here too if they materially affect CRA-AGENT's security
posture.

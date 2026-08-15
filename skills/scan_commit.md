# Skill: Scan Commit

## Description
Scans a git commit for security vulnerabilities using multiple scanner types.

## Agent
ScannerAgent

## Inputs
- `commit_hash`: The git commit hash to scan
- `branch`: The branch name
- `changed_files`: List of files changed in the commit

## Outputs
- `findings`: List of vulnerability findings detected

## Scanners Used
1. **DependencyScanner**: Scans dependencies for known CVEs
   - Tools: pip-audit, osv-scanner
   - Detects: Vulnerable packages, outdated dependencies

2. **SASTScanner**: Static application security testing
   - Tools: semgrep
   - Detects: SQL injection, XSS, command injection, insecure code patterns

3. **SecretsScanner**: Detects hardcoded secrets
   - Tools: gitleaks
   - Detects: API keys, passwords, private keys, tokens

## Workflow
1. Receive commit information
2. Analyze diff to extract changed files
3. Run all enabled scanners on changed files
4. Aggregate findings from all scanners
5. Apply severity threshold filtering
6. Return list of findings

## Configuration
- `scanners_enabled`: List of scanners to run (dependency, sast, secrets)
- `severity_threshold`: Minimum severity to report (critical, high, medium, low, info)

## Example Usage
```python
scanner_agent = ScannerAgent(repo_path, suppression_store)
findings = await scanner_agent.scan_commit(commit_info, changed_files)
```

## Error Handling
- Scanner failures are logged but don't stop the workflow
- Individual scanner timeouts are handled gracefully
- Missing scanner tools are reported as warnings
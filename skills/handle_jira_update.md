# Skill: Handle Jira Update

## Description
Processes Jira webhook events and routes them to appropriate actions (suppress, fix, rescan).

## Agent
JiraWebhookHandler

## Inputs
- `webhook_payload`: Raw Jira webhook event payload

## Outputs
- `result`: Dict describing the action taken

## Supported Events
1. **jira:issue_updated**: Issue status transitions
2. **comment_created**: Comments with @cra-agent commands
3. **jira:issue_created**: New issue creation (logged only)

## Transition Routing

### Suppress Transitions
Triggered by: "Won't Fix", "Ignore", "Known Issue", "Duplicate", "Rejected", "False Positive", "Accepted Risk"

**Action**: Add suppression rule to SuppressionStore
- Extract vulnerability ID from issue
- Create suppression with reason and Jira link
- Add comment confirming suppression
- Future scans will ignore this vulnerability

### Fix Transitions
Triggered by: "Fix Required", "To Do", "In Progress", "Start Fix"

**Action**: Initiate fix workflow
- Extract vulnerability ID from issue
- Add comment acknowledging fix request
- Trigger FixerAgent to generate and apply fix
- Create PR and update Jira with link

### Rescan Transitions
Triggered by: "Reopened", "Reopen"

**Action**: Remove suppression and rescan
- Remove any existing suppressions for the vulnerability
- Add comment confirming suppression removal
- Vulnerability will be re-scanned on next commit

## Comment Commands
Users can trigger actions via comments:
- `@cra-agent suppress` → Add suppression
- `@cra-agent fix` → Trigger fix workflow
- `@cra-agent rescan` → Remove suppression and rescan

## Vulnerability ID Extraction
The handler extracts vulnerability IDs from:
1. **Issue Summary**: e.g., "[HIGH] CVE-2024-1234: SQL Injection"
2. **Labels**: e.g., "cve-2024-1234"
3. **Description**: Regex search for CVE/CWE patterns

## Workflow
1. Receive webhook payload
2. Parse into JiraWebhookEvent
3. Route based on event type
4. For issue_updated:
   - Check transition name against routing rules
   - Execute appropriate action (suppress/fix/rescan)
5. For comment_created:
   - Check for @cra-agent commands
   - Execute command action
6. Return result dict

## Suppression Store Integration
When suppressing:
```python
suppression = suppression_store.add_suppression(
    vuln_id=vuln_id,
    reason=f"Suppressed via Jira: {transition_name}",
    jira_issue_key=issue_key,
    created_by=user_name,
)
```

When rescanning:
```python
suppressions = suppression_store.get_suppressions_for_vuln(vuln_id)
for suppression in suppressions:
    if suppression.jira_issue_key == issue_key:
        suppression_store.remove_suppression(suppression.id)
```

## Jira Comment Updates
After each action, the handler adds a comment to the Jira issue:
- **Suppress**: "CRA-AGENT: Suppression rule added for {vuln_id}. Future scans will ignore this vulnerability."
- **Fix**: "CRA-AGENT: Fix workflow initiated for {vuln_id}. A pull request will be created shortly."
- **Rescan**: "CRA-AGENT: Suppression removed for {vuln_id}. Vulnerability will be re-scanned on next commit."

## Error Handling
- Missing vulnerability IDs are logged and reported
- Jira API failures are caught and logged
- Suppression store errors don't stop the workflow
- All errors are included in the result dict

## Example Usage
```python
handler = JiraWebhookHandler(jira_client, llm_client, git_client, suppression_store)
result = await handler.handle_event(webhook_payload)
```

## Webhook Server Integration
The handler is used by the FastAPI webhook server:
```python
@app.post("/webhook/jira")
async def jira_webhook(request: Request):
    payload = await request.json()
    result = await webhook_handler.handle_event(payload)
    return JSONResponse(content={"status": "processed", "result": result})
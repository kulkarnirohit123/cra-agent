Weclome to CRA project 
We will write agentic AI for CRA complance 
1. Scan the codebase based on every commit 
2. identify vulnerabilities 
3. create a jira of these identified vulns , recomend triage 
4. read jira updates from webhook for jira and take necessary actions 
e.g. If jira says ignore vulns , known one , then updates scanner so that it wont flag same vulns 
if jira says need fix > run triage on own and fix the vulns 
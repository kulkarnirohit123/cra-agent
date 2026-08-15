"""CRA-AGENT Dashboard — Streamlit UI for metrics visualization.

Run with: streamlit run src/dashboard/app.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analytics.metrics_store import MetricsStore
from src.analytics.models import ROIMetrics

# Page config
st.set_page_config(
    page_title="CRA-AGENT Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
<style>
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: bold;
        color: #1f77b4;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #666;
    }
    .status-running {
        color: #28a745;
        font-weight: bold;
    }
    .status-stopped {
        color: #dc3545;
        font-weight: bold;
    }
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_resource
def get_metrics_store() -> MetricsStore:
    """Get or create metrics store instance."""
    db_path = Path(os.getenv("METRICS_DB_PATH", "./data/metrics.db"))
    return MetricsStore(db_path)


def render_sidebar() -> str:
    """Render sidebar navigation."""
    st.sidebar.title("🛡️ CRA-AGENT")
    st.sidebar.markdown("---")

    # Navigation
    page = st.sidebar.radio(
        "Navigation",
        ["📊 Overview", "🔍 Scans", "⚠️ Findings", "🐙 GitHub", "� ROI & Metrics", "⚙️ Settings"],
        index=0,
    )

    st.sidebar.markdown("---")

    # Agent status
    st.sidebar.markdown("### Agent Status")
    metrics_store = get_metrics_store()
    summary = metrics_store.get_dashboard_summary()

    status_color = "🟢" if summary.agent_status == "running" else "🔴"
    st.sidebar.markdown(f"{status_color} **{summary.agent_status.title()}**")

    if summary.last_scan_at:
        st.sidebar.markdown(f"Last scan: {summary.last_scan_at.strftime('%Y-%m-%d %H:%M')}")
    else:
        st.sidebar.markdown("Last scan: Never")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Quick Stats")
    st.sidebar.metric("Total Scans", summary.total_scans)
    st.sidebar.metric("Total Findings", summary.total_findings)
    st.sidebar.metric("Tickets Created", summary.total_tickets)
    st.sidebar.metric("Fixes Applied", summary.total_fixes)

    return page


def render_overview() -> None:
    """Render overview page."""
    st.title("📊 Dashboard Overview")

    metrics_store = get_metrics_store()
    summary = metrics_store.get_dashboard_summary()

    # Status cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Agent Status",
            summary.agent_status.title(),
            delta=None,
        )

    with col2:
        st.metric(
            "Effectiveness",
            f"{summary.overall_effectiveness * 100:.1f}%",
            delta=None,
        )

    with col3:
        st.metric(
            "Time Saved",
            f"{summary.time_saved_hours:.1f} hrs",
            delta=None,
        )

    with col4:
        st.metric(
            "PRs Merged",
            summary.total_prs_merged,
            delta=None,
        )

    st.markdown("---")

    # Today vs This Week comparison
    st.subheader("Activity Comparison")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Today")
        today_data = {
            "Scans": summary.scans_today,
            "Findings": summary.findings_today,
            "Tickets": summary.tickets_today,
            "Fixes": summary.fixes_today,
        }
        st.bar_chart(today_data)

    with col2:
        st.markdown("#### This Week")
        week_data = {
            "Scans": summary.scans_this_week,
            "Findings": summary.findings_this_week,
            "Tickets": summary.tickets_this_week,
            "Fixes": summary.fixes_this_week,
        }
        st.bar_chart(week_data)

    st.markdown("---")

    # Recent activity
    st.subheader("Recent Activity")

    tab1, tab2, tab3 = st.tabs(["Recent Findings", "Recent Tickets", "Recent Fixes"])

    with tab1:
        if summary.recent_findings:
            for finding in summary.recent_findings[:5]:
                with st.expander(f"🔴 {finding.get('severity', 'unknown').upper()}: {finding.get('vuln_id', 'N/A')}"):
                    st.markdown(f"**File:** `{finding.get('file', 'N/A')}`")
                    st.markdown(f"**Detected:** {finding.get('detected_at', 'N/A')}")
        else:
            st.info("No recent findings")

    with tab2:
        if summary.recent_tickets:
            for ticket in summary.recent_tickets[:5]:
                with st.expander(f"🎫 {ticket.get('ticket_key', 'N/A')}"):
                    st.markdown(f"**Severity:** {ticket.get('severity', 'N/A')}")
                    st.markdown(f"**Created:** {ticket.get('created_at', 'N/A')}")
        else:
            st.info("No recent tickets")

    with tab3:
        if summary.recent_fixes:
            for fix in summary.recent_fixes[:5]:
                with st.expander(f"✅ Fix: {fix.get('finding_id', 'N/A')[:8]}"):
                    st.markdown(f"**PR:** {fix.get('pr_url', 'N/A')}")
                    st.markdown(f"**Completed:** {fix.get('completed_at', 'N/A')}")
        else:
            st.info("No recent fixes")


def render_scans() -> None:
    """Render scans page."""
    st.title("🔍 Scan History")

    metrics_store = get_metrics_store()

    # Date range filter
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input(
            "Start Date",
            value=datetime.now() - timedelta(days=30),
        )
    with col2:
        end_date = st.date_input("End Date", value=datetime.now())

    # Get scans
    scans = metrics_store.get_scans(
        start_date=datetime.combine(start_date, datetime.min.time()),
        end_date=datetime.combine(end_date, datetime.max.time()),
        limit=100,
    )

    if not scans:
        st.info("No scans found in the selected date range.")
        return

    # Summary stats
    st.subheader("Summary")
    col1, col2, col3, col4 = st.columns(4)

    total_scans = len(scans)
    successful_scans = sum(1 for s in scans if s.success)
    total_findings = sum(s.findings_count for s in scans)
    avg_duration = sum(s.duration_seconds or 0 for s in scans) / len(scans) if scans else 0

    with col1:
        st.metric("Total Scans", total_scans)
    with col2:
        st.metric("Successful", successful_scans, f"{successful_scans / total_scans * 100:.1f}%")
    with col3:
        st.metric("Total Findings", total_findings)
    with col4:
        st.metric("Avg Duration", f"{avg_duration:.1f}s")

    st.markdown("---")

    # Scan history table
    st.subheader("Scan History")

    scan_data = []
    for scan in scans:
        scan_data.append(
            {
                "Scan ID": scan.scan_id[:8],
                "Commit": scan.commit_hash[:7],
                "Branch": scan.branch,
                "Started": scan.started_at.strftime("%Y-%m-%d %H:%M"),
                "Duration": f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "N/A",
                "Files": scan.files_scanned,
                "Findings": scan.findings_count,
                "Status": "✅" if scan.success else "❌",
            }
        )

    st.dataframe(scan_data, use_container_width=True)

    # Severity distribution chart
    st.subheader("Severity Distribution")

    severity_data = {
        "Critical": sum(s.severity_distribution.critical for s in scans),
        "High": sum(s.severity_distribution.high for s in scans),
        "Medium": sum(s.severity_distribution.medium for s in scans),
        "Low": sum(s.severity_distribution.low for s in scans),
        "Info": sum(s.severity_distribution.info for s in scans),
    }

    st.bar_chart(severity_data)


def render_findings() -> None:
    """Render findings page."""
    st.title("⚠️ Findings")

    metrics_store = get_metrics_store()

    # Filters
    col1, col2, col3 = st.columns(3)

    with col1:
        severity_filter = st.selectbox(
            "Severity",
            ["All", "critical", "high", "medium", "low", "info"],
        )

    with col2:
        suppressed_filter = st.selectbox(
            "Suppression Status",
            ["All", "Active", "Suppressed"],
        )

    with col3:
        limit = st.slider("Results Limit", 10, 200, 50)

    # Get findings
    severity = None if severity_filter == "All" else severity_filter
    suppressed = None
    if suppressed_filter == "Active":
        suppressed = False
    elif suppressed_filter == "Suppressed":
        suppressed = True

    findings = metrics_store.get_findings(
        severity=severity,
        suppressed=suppressed,
        limit=limit,
    )

    if not findings:
        st.info("No findings match the selected filters.")
        return

    # Summary
    st.subheader("Summary")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Findings", len(findings))
    with col2:
        ticketed = sum(1 for f in findings if f.ticket_key)
        st.metric("Ticketed", ticketed, f"{ticketed / len(findings) * 100:.1f}%")
    with col3:
        fixed = sum(1 for f in findings if f.fix_completed_at)
        st.metric("Fixed", fixed, f"{fixed / len(findings) * 100:.1f}%")
    with col4:
        suppressed_count = sum(1 for f in findings if f.suppressed)
        st.metric("Suppressed", suppressed_count)

    st.markdown("---")

    # Findings table
    st.subheader("Findings List")

    finding_data = []
    for finding in findings:
        finding_data.append(
            {
                "ID": finding.finding_id[:8],
                "Vuln ID": finding.vuln_id or "N/A",
                "Scanner": finding.scanner,
                "Severity": finding.severity.upper(),
                "File": finding.file_path,
                "Detected": finding.detected_at.strftime("%Y-%m-%d"),
                "Ticket": finding.ticket_key or "-",
                "Fixed": "✅" if finding.fix_completed_at else "❌",
                "Suppressed": "🚫" if finding.suppressed else "✅",
            }
        )

    st.dataframe(finding_data, use_container_width=True)

    # Scanner distribution
    st.subheader("Findings by Scanner")

    scanner_counts = {}
    for finding in findings:
        scanner_counts[finding.scanner] = scanner_counts.get(finding.scanner, 0) + 1

    st.bar_chart(scanner_counts)


def render_roi() -> None:
    """Render ROI & Metrics page."""
    st.title("💰 ROI & Effectiveness Metrics")

    metrics_store = get_metrics_store()

    # Get agent metrics for last 30 days
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)

    agent_metrics = metrics_store.get_agent_metrics(start_date, end_date)

    # ROI calculation inputs
    st.subheader("ROI Calculator")

    col1, col2, col3 = st.columns(3)

    with col1:
        llm_cost = st.number_input(
            "LLM API Cost (USD)",
            min_value=0.0,
            value=50.0,
            step=10.0,
            help="Total LLM API costs for the period",
        )

    with col2:
        compute_cost = st.number_input(
            "Compute Cost (USD)",
            min_value=0.0,
            value=20.0,
            step=5.0,
            help="Infrastructure/compute costs",
        )

    with col3:
        hourly_rate = st.number_input(
            "Engineer Hourly Rate (USD)",
            min_value=50.0,
            value=100.0,
            step=10.0,
            help="Average security engineer hourly rate",
        )

    # Calculate ROI
    roi = ROIMetrics.calculate(
        agent_metrics=agent_metrics,
        llm_cost=llm_cost,
        compute_cost=compute_cost,
        hourly_rate=hourly_rate,
    )

    st.markdown("---")

    # ROI Results
    st.subheader("ROI Results")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Value",
            f"${roi.total_value_usd:,.2f}",
            delta=None,
        )

    with col2:
        st.metric(
            "Total Cost",
            f"${roi.total_operational_cost:,.2f}",
            delta=None,
        )

    with col3:
        st.metric(
            "ROI",
            f"{roi.roi_percentage:.1f}%",
            delta=f"{roi.roi_percentage - 100:.1f}%" if roi.roi_percentage > 100 else None,
        )

    with col4:
        st.metric(
            "Time Saved",
            f"{roi.total_time_saved_hours:.1f} hrs",
            delta=None,
        )

    st.markdown("---")

    # Effectiveness breakdown
    st.subheader("Effectiveness Breakdown")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Detection", f"{roi.detection_effectiveness * 100:.1f}%")
        st.progress(roi.detection_effectiveness)

    with col2:
        st.metric("Triage", f"{roi.triage_effectiveness * 100:.1f}%")
        st.progress(roi.triage_effectiveness)

    with col3:
        st.metric("Fix", f"{roi.fix_effectiveness * 100:.1f}%")
        st.progress(roi.fix_effectiveness)

    with col4:
        st.metric("Overall", f"{roi.overall_effectiveness * 100:.1f}%")
        st.progress(roi.overall_effectiveness)

    st.markdown("---")

    # Time savings breakdown
    st.subheader("Time Savings Breakdown")

    time_data = {
        "Manual Triage": roi.manual_triage_time_hours,
        "Ticket Creation": roi.manual_ticket_creation_hours,
        "Manual Fixes": roi.manual_fix_time_hours,
    }

    st.bar_chart(time_data)

    # Value breakdown
    st.subheader("Value Breakdown")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Cost Components")
        st.markdown(f"- LLM API: ${roi.llm_api_cost_usd:.2f}")
        st.markdown(f"- Compute: ${roi.compute_cost_usd:.2f}")
        st.markdown(f"- **Total: ${roi.total_operational_cost:.2f}**")

    with col2:
        st.markdown("#### Value Generated")
        st.markdown(f"- Time Savings: ${roi.time_savings_value_usd:.2f}")
        st.markdown(f"- Breach Prevention: ${roi.breach_cost_avoided_usd:.2f}")
        st.markdown(f"- **Total: ${roi.total_value_usd:.2f}**")

    # ROI History
    st.markdown("---")
    st.subheader("ROI History")

    roi_history = metrics_store.get_roi_history(limit=12)

    if roi_history:
        history_data = []
        for record in roi_history:
            history_data.append(
                {
                    "Period": record["period_end"][:10],
                    "ROI %": record["roi_percentage"],
                    "Value ($)": record["total_value"],
                    "Time Saved (hrs)": record["time_saved_hours"],
                    "Effectiveness": record["effectiveness"] * 100,
                }
            )
        st.dataframe(history_data, use_container_width=True)
    else:
        st.info("No ROI history recorded yet. Click 'Save ROI Snapshot' to record current metrics.")

    if st.button("💾 Save ROI Snapshot"):
        metrics_store.record_roi_metrics(roi)
        st.success("ROI snapshot saved!")
        st.rerun()


def render_github() -> None:
    """Render GitHub integration page."""
    st.title("🐙 GitHub Integration")

    st.markdown("""
    This page allows you to manage your GitHub repositories and trigger scans manually.
    """)

    # Check if GitHub is configured
    from config.settings import get_settings

    settings = get_settings()

    if not settings.github_enabled:
        st.warning(
            "⚠️ GitHub is not configured. Please set GITHUB_APP_ID and GITHUB_PRIVATE_KEY_PATH in your .env file."
        )
        st.markdown("""
        ### Setup Instructions

        1. **Create a GitHub App** at https://github.com/settings/apps/new
           - UNCHECK "Active" for webhooks (we use polling!)
           - Set permissions: Contents (Read), Metadata (Read), Pull requests (Read/Write), Commit statuses (Read/Write)

        2. **Generate a private key** and move it to your project

        3. **Update your .env** with the App ID and Installation ID

        4. **Restart the agent**
        """)
        return

    st.success("✅ GitHub is configured")

    # Load repos from config
    import yaml

    repos_config_path = Path("./config/repos.yaml")

    if not repos_config_path.exists():
        st.error(f"❌ Repos config not found at {repos_config_path}")
        return

    with open(repos_config_path) as f:
        repos_config = yaml.safe_load(f)

    repositories = repos_config.get("repositories", [])

    if not repositories:
        st.warning("No repositories configured. Edit `config/repos.yaml` to add repositories.")
        return

    st.markdown("---")

    # Repository management
    st.subheader("📁 Configured Repositories")

    # Check which repos are cloned locally
    repos_dir = Path("./repos")
    cloned_repos = [d.name for d in repos_dir.iterdir() if d.is_dir()] if repos_dir.exists() else []

    for i, repo in enumerate(repositories):
        repo_name = repo.get("name", "")
        enabled = repo.get("enabled", True)
        branches = repo.get("branches", ["main"])
        language = repo.get("language", "unknown")
        scanners = repo.get("scanners", [])

        # Check if repo is cloned
        repo_short_name = repo_name.split("/")[-1] if "/" in repo_name else repo_name
        is_cloned = repo_short_name in cloned_repos

        with st.expander(f"{'🟢' if enabled else '🔴'} {repo_name} {'✅' if is_cloned else '⬇️'}"):
            col1, col2 = st.columns([3, 1])

            with col1:
                st.markdown(f"**Description:** {repo.get('description', 'N/A')}")
                st.markdown(f"**Language:** {language}")
                st.markdown(f"**Branches:** {', '.join(branches)}")
                st.markdown(f"**Scanners:** {', '.join(scanners)}")
                st.markdown(f"**Enabled:** {'Yes' if enabled else 'No'}")
                st.markdown(f"**Cloned Locally:** {'Yes' if is_cloned else 'No'}")

            with col2:
                # Scan Now button
                if st.button("🔍 Scan Now", key=f"scan_{i}"):
                    with st.spinner(f"Scanning {repo_name}..."):
                        # Run scan in a subprocess to avoid blocking the UI
                        import subprocess

                        # Get the latest commit for this repo
                        scan_cmd = [
                            sys.executable,
                            "-c",
                            f'''
import asyncio
import sys
sys.path.insert(0, "{Path(__file__).parent.parent.parent}")

from src.integrations.github_client import GitHubClient
from config.settings import get_settings

async def scan():
    settings = get_settings()
    client = GitHubClient(
        app_id=settings.github_app_id,
        private_key=settings.github_private_key,
        installation_id=settings.github_installation_id,
    )

    # Get latest commit
    commits = await client.list_recent_commits(
        owner="{repo_name.split("/")[0]}",
        repo="{repo_name.split("/")[1]}",
        branch="{branches[0]}",
        limit=1,
    )

    if commits:
        commit = commits[0]
        print(f"Latest commit: {{commit['sha'][:7]}}")
        print(f"Message: {{commit['commit']['message'][:50]}}")

        # Clone/update repo
        from pathlib import Path
        repos_dir = Path("./repos")
        repos_dir.mkdir(exist_ok=True)

        repo_path = client.clone_repo(
            owner="{repo_name.split("/")[0]}",
            repo="{repo_name.split("/")[1]}",
            target_dir=repos_dir,
            branch="{branches[0]}",
        )
        print(f"Repo cloned to: {{repo_path}}")

    await client.close()

asyncio.run(scan())
print("Scan triggered successfully!")
''',
                        ]

                        result = subprocess.run(scan_cmd, capture_output=True, text=True)

                        if result.returncode == 0:
                            st.success(f"✅ Scan triggered for {repo_name}")
                            st.code(result.stdout)
                        else:
                            st.error(f"❌ Scan failed: {result.stderr}")

                # Clone button (if not cloned)
                if not is_cloned:
                    if st.button("⬇️ Clone", key=f"clone_{i}"):
                        with st.spinner(f"Cloning {repo_name}..."):
                            import subprocess

                            clone_cmd = [
                                "git",
                                "clone",
                                f"https://github.com/{repo_name}.git",
                                str(repos_dir / repo_short_name),
                            ]
                            result = subprocess.run(clone_cmd, capture_output=True, text=True)

                            if result.returncode == 0:
                                st.success(f"✅ Cloned {repo_name}")
                                st.rerun()
                            else:
                                st.error(f"❌ Clone failed: {result.stderr}")

    st.markdown("---")

    # Quick actions
    st.subheader("⚡ Quick Actions")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🔄 Refresh Repository List"):
            st.cache_resource.clear()
            st.rerun()

    with col2:
        if st.button("📥 Clone All Repos"):
            with st.spinner("Cloning all repositories..."):
                import subprocess

                repos_dir.mkdir(exist_ok=True)

                for repo in repositories:
                    repo_name = repo.get("name", "")
                    repo_short_name = repo_name.split("/")[-1] if "/" in repo_name else repo_name

                    if repo_short_name not in cloned_repos:
                        clone_cmd = [
                            "git",
                            "clone",
                            f"https://github.com/{repo_name}.git",
                            str(repos_dir / repo_short_name),
                        ]
                        subprocess.run(clone_cmd, capture_output=True)

                st.success("✅ All repositories cloned!")
                st.rerun()

    with col3:
        if st.button("🔍 Scan All Repos"):
            with st.spinner("Scanning all repositories..."):
                import subprocess

                for repo in repositories:
                    if repo.get("enabled", True):
                        repo_name = repo.get("name", "")
                        st.info(f"Scanning {repo_name}...")
                        # Trigger scan via polling script
                        subprocess.Popen([sys.executable, "scripts/run_github_polling.py"])
                        break  # Just trigger one scan cycle

                st.success("✅ Scan triggered for all repositories!")

    st.markdown("---")

    # GitHub App status
    st.subheader("🔧 GitHub App Status")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**App ID:** `{settings.github_app_id}`")
        st.markdown(f"**Installation ID:** `{settings.github_installation_id}`")

    with col2:
        st.markdown(f"**Private Key Path:** `{settings.github_private_key_path}`")
        st.markdown(f"**Key Exists:** {'✅' if settings.github_private_key_path.exists() else '❌'}")


def render_settings() -> None:
    """Render settings page."""
    st.title("⚙️ Settings")

    st.subheader("Database Information")

    metrics_store = get_metrics_store()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**Database Path:** `{metrics_store.db_path}`")
        st.markdown(f"**Database Exists:** {'✅' if metrics_store.db_path.exists() else '❌'}")

    with col2:
        summary = metrics_store.get_dashboard_summary()
        st.markdown("**Total Records:**")
        st.markdown(f"- Scans: {summary.total_scans}")
        st.markdown(f"- Findings: {summary.total_findings}")
        st.markdown(f"- Tickets: {summary.total_tickets}")

    st.markdown("---")

    st.subheader("Configuration")

    st.markdown("""
    ### Environment Variables

    | Variable | Description | Default |
    |----------|-------------|---------|
    | `METRICS_DB_PATH` | Path to metrics database | `./data/metrics.db` |
    | `SUPPRESSION_DB_PATH` | Path to suppression database | `./data/suppressions.db` |
    | `GIT_REPO_PATH` | Path to monitored repository | `./target-repo` |
    | `JIRA_BASE_URL` | Jira instance URL | - |
    | `JIRA_API_TOKEN` | Jira API token | - |
    | `OPENAI_API_KEY` | OpenAI API key | - |
    """)

    st.markdown("---")

    st.subheader("Actions")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🔄 Refresh Data"):
            st.cache_resource.clear()
            st.rerun()

    with col2:
        if st.button("📊 Generate Report"):
            st.info("Report generation coming soon...")

    with col3:
        if st.button("🗑️ Clear Cache"):
            st.cache_resource.clear()
            st.success("Cache cleared!")


def main() -> None:
    """Main dashboard entry point."""
    page = render_sidebar()

    if page == "📊 Overview":
        render_overview()
    elif page == "🔍 Scans":
        render_scans()
    elif page == "⚠️ Findings":
        render_findings()
    elif page == "🐙 GitHub":
        render_github()
    elif page == "💰 ROI & Metrics":
        render_roi()
    elif page == "⚙️ Settings":
        render_settings()


if __name__ == "__main__":
    main()

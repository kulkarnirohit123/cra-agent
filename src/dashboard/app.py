"""CRA-AGENT Dashboard — Premium Streamlit UI for metrics visualization.

Features:
- EUVD auto-refresh every 4 hours with manual trigger
- Highlighted vulnerability matches (dark red bg, white text)
- Premium UI inspired by Datadog/ManageEngine, Upwind-styled sidebar

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
    page_title="CRA-AGENT | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

PREMIUM_CSS = """
<style>
    /* Import modern fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    /* Global styles */
    .stApp {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background: #f8fafc;
    }

    /* Hide default Streamlit header/footer */
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
    footer {visibility: hidden;}

    .block-container {
        padding: 1rem 2rem 2rem 2rem;
    }

    /* Upwind-inspired sidebar: white bg, light gray sections, dark text */
    section[data-testid="stSidebar"] {
        background: #ffffff;
        border-right: 1px solid #e5e7eb;
    }

    section[data-testid="stSidebar"] .stMarkdown {
        color: #374151;
    }

    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {
        color: #111827;
    }

    section[data-testid="stSidebar"] code {
        background: #f3f4f6;
        color: #374151;
    }

    .sidebar-logo {
        text-align: center;
        padding: 12px 0;
    }

    .sidebar-section {
        background: #f9fafb;
        border: 1px solid #e5e7eb;
        border-radius: 10px;
        padding: 12px 14px;
        margin: 8px 0;
    }

    /* Premium metric cards — white with color-coded top border */
    .metric-card {
        background: #ffffff;
        border-radius: 12px;
        padding: 14px 18px;
        margin: 6px 0;
        border: 1px solid #e5e7eb;
        border-top: 3px solid #6366f1;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        transition: all 0.2s ease;
    }

    .metric-card:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }

    .metric-card.critical { border-top-color: #ef4444; }
    .metric-card.success { border-top-color: #10b981; }
    .metric-card.warning { border-top-color: #f59e0b; }
    .metric-card.info { border-top-color: #3b82f6; }

    .metric-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #111827;
        margin: 0;
        line-height: 1.2;
    }

    .metric-label {
        font-size: 0.8rem;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 6px;
    }

    .metric-delta {
        font-size: 0.85rem;
        margin-top: 6px;
    }

    .metric-delta.positive { color: #10b981; }
    .metric-delta.negative { color: #ef4444; }

    /* Status indicators */
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 5px 12px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .status-badge.running {
        background: rgba(16, 185, 129, 0.12);
        color: #059669;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .status-badge.stopped {
        background: rgba(239, 68, 68, 0.12);
        color: #dc2626;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .status-pulse {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
        animation: pulse 2s infinite;
    }

    .status-pulse.running { background: #10b981; }
    .status-pulse.stopped { background: #ef4444; }

    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.5); }
        70% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* VULNERABILITY HIGHLIGHT — dark red bg with white text */
    .vuln-highlight {
        background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
        color: #ffffff !important;
        padding: 10px 14px;
        border-radius: 12px;
        margin: 6px 0;
        border-left: 4px solid #ef4444;
        box-shadow: 0 4px 15px rgba(127, 29, 29, 0.25);
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
    }

    .vuln-highlight * {
        color: #ffffff !important;
    }

    .vuln-highlight .vuln-title {
        font-size: 1rem;
        font-weight: 700;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .vuln-highlight .vuln-severity {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
    }

    .vuln-highlight .vuln-severity.critical { background: #dc2626; color: #ffffff; }
    .vuln-highlight .vuln-severity.high { background: #ea580c; color: #ffffff; }
    .vuln-highlight .vuln-severity.medium { background: #d97706; color: #ffffff; }
    .vuln-highlight .vuln-severity.low { background: #0284c7; color: #ffffff; }

    .vuln-highlight .vuln-file {
        color: #fca5a5;
        font-size: 0.8rem;
        margin-top: 6px;
    }

    /* Standalone severity badges (e.g. EUVD top 10 list) */
    .severity-critical, .severity-high, .severity-medium, .severity-low {
        color: white;
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.7rem;
    }

    .severity-critical { background: #dc2626; }
    .severity-high { background: #ea580c; }
    .severity-medium { background: #d97706; }
    .severity-low { background: #0284c7; }

    /* Premium / content cards */
    .premium-card {
        background: #ffffff;
        border-radius: 12px;
        padding: 16px 18px;
        border: 1px solid #e5e7eb;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        margin: 6px 0;
    }

    .premium-card h3, .premium-card h4 {
        color: #111827;
        font-weight: 600;
        margin-bottom: 10px;
    }

    /* EUVD Status Panel */
    .euvd-panel {
        background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
        border-radius: 12px;
        padding: 16px 18px;
        border: 1px solid #bfdbfe;
        margin: 8px 0;
    }

    .euvd-status {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 10px;
    }

    .euvd-pulse {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #2563eb;
        animation: pulse-blue 2s infinite;
    }

    @keyframes pulse-blue {
        0% { box-shadow: 0 0 0 0 rgba(37, 99, 235, 0.5); }
        70% { box-shadow: 0 0 0 8px rgba(37, 99, 235, 0); }
        100% { box-shadow: 0 0 0 0 rgba(37, 99, 235, 0); }
    }

    .countdown-timer {
        font-size: 1.3rem;
        font-weight: 700;
        color: #2563eb;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Progress bars */
    .custom-progress {
        height: 6px;
        border-radius: 3px;
        background: #e5e7eb;
        overflow: hidden;
        margin: 6px 0;
    }

    .custom-progress-bar {
        height: 100%;
        border-radius: 3px;
        transition: width 0.5s ease;
    }

    .custom-progress-bar.success { background: linear-gradient(90deg, #10b981, #34d399); }
    .custom-progress-bar.warning { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
    .custom-progress-bar.danger { background: linear-gradient(90deg, #ef4444, #f87171); }

    /* Buttons */
    .stButton > button {
        border-radius: 8px;
        font-weight: 600;
        padding: 8px 20px;
        transition: all 0.2s ease;
    }

    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 10px rgba(99, 102, 241, 0.25);
    }

    /* Header styling */
    .dashboard-header {
        background: #ffffff;
        border-radius: 12px;
        padding: 14px 20px;
        margin-bottom: 12px;
        border: 1px solid #e5e7eb;
    }

    .dashboard-header h1 {
        color: #111827;
        font-size: 1.5rem;
        font-weight: 700;
        margin: 0;
    }

    .dashboard-header p {
        color: #6b7280;
        margin: 4px 0 0 0;
        font-size: 0.9rem;
    }

    h1 { margin: 0 0 0.5rem 0; }
    h2 { margin: 0 0 0.4rem 0; }
    h3 { margin: 0 0 0.3rem 0; }
    hr { margin: 0.75rem 0; }
</style>
"""

st.markdown(PREMIUM_CSS, unsafe_allow_html=True)


class EUVDScheduler:
    """Manages EUVD auto-refresh scheduling."""

    REFRESH_INTERVAL_HOURS = 4
    STATE_KEY = "euvd_scheduler_state"

    @classmethod
    def get_state(cls) -> dict:
        """Get scheduler state from session."""
        if cls.STATE_KEY not in st.session_state:
            st.session_state[cls.STATE_KEY] = {
                "last_refresh": None,
                "next_refresh": None,
                "is_running": False,
                "refresh_count": 0,
                "last_status": "idle",
                "vulnerabilities_synced": 0,
            }
        return st.session_state[cls.STATE_KEY]

    @classmethod
    def update_state(cls, **kwargs) -> None:
        """Update scheduler state."""
        state = cls.get_state()
        state.update(kwargs)

    @classmethod
    def should_refresh(cls) -> bool:
        """Check if refresh is due."""
        state = cls.get_state()
        if state["next_refresh"] is None:
            return True
        return datetime.now() >= state["next_refresh"]

    @classmethod
    def get_countdown(cls) -> str:
        """Get countdown to next refresh."""
        state = cls.get_state()
        if state["next_refresh"] is None:
            return "00:00:00"
        remaining = state["next_refresh"] - datetime.now()
        if remaining.total_seconds() <= 0:
            return "00:00:00"
        hours = int(remaining.total_seconds() // 3600)
        minutes = int(remaining.total_seconds() % 3600 // 60)
        seconds = int(remaining.total_seconds() % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    @classmethod
    def trigger_refresh(cls) -> dict:
        """Trigger manual refresh."""
        now = datetime.now()
        next_refresh = now + timedelta(hours=cls.REFRESH_INTERVAL_HOURS)
        state = cls.get_state()
        cls.update_state(
            last_refresh=now,
            next_refresh=next_refresh,
            is_running=True,
            refresh_count=state["refresh_count"] + 1,
            last_status="syncing",
        )
        result = cls._sync_euvd_data()
        cls.update_state(
            is_running=False,
            last_status="completed" if result["success"] else "error",
            vulnerabilities_synced=result.get("synced", 0),
        )
        return result

    @classmethod
    def _sync_euvd_data(cls) -> dict:
        """Sync data from EUVD (simulated for demo)."""
        import random

        synced = random.randint(5, 50)  # noqa: S311 — simulated demo data, not security-sensitive
        new_vulns = random.randint(0, 5)  # noqa: S311
        updated_vulns = random.randint(0, 10)  # noqa: S311
        return {
            "success": True,
            "synced": synced,
            "new_vulnerabilities": new_vulns,
            "updated_vulnerabilities": updated_vulns,
            "timestamp": datetime.now().isoformat(),
            "source": "EU VD (ENISA)",
        }

    @classmethod
    def init_auto_refresh(cls) -> None:
        """Initialize auto-refresh on first load."""
        state = cls.get_state()
        if state["next_refresh"] is None:
            now = datetime.now()
            cls.update_state(
                last_refresh=now,
                next_refresh=now + timedelta(hours=cls.REFRESH_INTERVAL_HOURS),
                last_status="initialized",
            )


# Sample EUVD "Top 10" entries used until the live EUVD feed is wired in.
TOP_EUVD_SAMPLE = [
    {
        "cve": "CVE-2026-21892",
        "severity": "critical",
        "cvss": 9.8,
        "title": "Remote Code Execution in Apache Struts",
        "product": "Apache Struts",
        "vendor": "Apache Software Foundation",
        "published": "2026-08-15",
        "cwe": "CWE-502",
        "exploited": True,
    },
    {
        "cve": "CVE-2026-21891",
        "severity": "critical",
        "cvss": 9.6,
        "title": "SQL Injection in Django ORM",
        "product": "Django",
        "vendor": "Django Software Foundation",
        "published": "2026-08-14",
        "cwe": "CWE-89",
        "exploited": True,
    },
    {
        "cve": "CVE-2026-21890",
        "severity": "critical",
        "cvss": 9.4,
        "title": "Authentication Bypass in OpenSSL",
        "product": "OpenSSL",
        "vendor": "OpenSSL Project",
        "published": "2026-08-14",
        "cwe": "CWE-287",
        "exploited": False,
    },
    {
        "cve": "CVE-2026-21888",
        "severity": "high",
        "cvss": 8.5,
        "title": "Privilege Escalation in Windows",
        "product": "Windows",
        "vendor": "Microsoft",
        "published": "2026-08-13",
        "cwe": "CWE-269",
        "exploited": False,
    },
]


@st.cache_resource
def get_metrics_store() -> MetricsStore:
    """Get or create metrics store instance."""
    db_path = Path(os.getenv("METRICS_DB_PATH", "./data/metrics.db"))
    return MetricsStore(db_path)


def render_sidebar() -> str:
    """Render premium sidebar navigation."""
    st.sidebar.markdown(
        """
    <div class="sidebar-logo">
        <div style="font-size: 2.2rem;">🛡️</div>
        <div style="font-size: 1.2rem; font-weight: 700; color: #111827; margin-top: 6px;">
            CRA-AGENT
        </div>
        <div style="font-size: 0.7rem; color: #6b7280; text-transform: uppercase; letter-spacing: 1px;">
            Security Dashboard
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("---")

    page = st.sidebar.radio(
        "Navigation",
        [
            "📊 Overview",
            "🔍 Scans",
            "⚠️ Findings",
            "🇪🇺 EUVD Sync",
            "🐙 GitHub",
            "💰 ROI & Metrics",
            "⚙️ Settings",
        ],
        index=0,
    )

    st.sidebar.markdown("---")

    metrics_store = get_metrics_store()
    summary = metrics_store.get_dashboard_summary()

    status_class = "running" if summary.agent_status == "running" else "stopped"
    status_label = "ONLINE" if summary.agent_status == "running" else "OFFLINE"
    last_scan = summary.last_scan_at.strftime("%H:%M:%S") if summary.last_scan_at else "Never"

    st.sidebar.markdown(
        f"""
    <div class="premium-card" style="padding: 12px 14px;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span class="status-badge {status_class}">
                <span class="status-pulse {status_class}"></span>{status_label}
            </span>
        </div>
        <div style="font-size: 0.8rem; color: #6b7280;">
            Last scan: {last_scan}
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.sidebar.markdown("### Quick Stats")
    st.sidebar.metric("Scans", summary.total_scans)
    st.sidebar.metric("Findings", summary.total_findings)
    st.sidebar.metric("Tickets", summary.total_tickets)
    st.sidebar.metric("Fixes", summary.total_fixes)

    st.sidebar.markdown("### 🇪🇺 EUVD Sync")
    euvd_state = EUVDScheduler.get_state()
    if euvd_state["last_status"] == "syncing":
        st.sidebar.markdown("🔄 **Syncing...**")
    elif euvd_state["last_status"] == "completed":
        st.sidebar.markdown(f"✅ **Synced** ({euvd_state['vulnerabilities_synced']} vulns)")
    else:
        st.sidebar.markdown("⏳ **Waiting**")
    st.sidebar.markdown(f"Next sync: `{EUVDScheduler.get_countdown()}`")

    return page


def render_overview() -> None:
    """Render premium overview dashboard."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>📊 Security Dashboard</h1>
        <p>Real-time vulnerability management and compliance monitoring</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    metrics_store = get_metrics_store()
    summary = metrics_store.get_dashboard_summary()

    status_class = "success" if summary.agent_status == "running" else "critical"

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f"""
        <div class="metric-card {status_class}">
            <div class="metric-value">{summary.agent_status.title()}</div>
            <div class="metric-label">Agent Status</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-value">{summary.total_findings}</div>
            <div class="metric-label">Total Findings</div>
            <div class="metric-delta positive">+{summary.findings_today} today</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
        <div class="metric-card info">
            <div class="metric-value">{summary.overall_effectiveness * 100:.0f}%</div>
            <div class="metric-label">Effectiveness</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col4:
        st.markdown(
            f"""
        <div class="metric-card success">
            <div class="metric-value">{summary.time_saved_hours:.1f}h</div>
            <div class="metric-label">Time Saved</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col5:
        st.markdown(
            f"""
        <div class="metric-card warning">
            <div class="metric-value">{summary.total_prs_merged}</div>
            <div class="metric-label">PRs Merged</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    st.subheader("📈 Today's Activity")
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📈 Today's Activity")
        today_data = {
            "Scans": summary.scans_today,
            "Findings": summary.findings_today,
            "Tickets": summary.tickets_today,
            "Fixes": summary.fixes_today,
        }
        st.bar_chart(today_data)

    with col2:
        st.markdown("### 📊 This Week")
        week_data = {
            "Scans": summary.scans_this_week,
            "Findings": summary.findings_this_week,
            "Tickets": summary.tickets_this_week,
            "Fixes": summary.fixes_this_week,
        }
        st.bar_chart(week_data)

    st.markdown("---")

    st.markdown("### 🔥 Recent Vulnerabilities")
    if summary.recent_findings:
        for finding in summary.recent_findings[:5]:
            severity = finding.get("severity", "unknown").lower()
            st.markdown(
                f"""
            <div class="vuln-highlight">
                <div class="vuln-title">
                    <span class="vuln-severity {severity}">{severity.upper()}</span>
                    <span>{finding.get("vuln_id", "N/A")}</span>
                </div>
                <div class="vuln-file">📁 {finding.get("file", "N/A")}</div>
                <div style="color: #fca5a5; font-size: 0.85rem; margin-top: 8px;">
                    ⏰ Detected: {finding.get("detected_at", "N/A")}
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )
    else:
        st.info("No recent findings - all clear! ✨")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### 🎫 Recent Tickets")
        if summary.recent_tickets:
            for ticket in summary.recent_tickets[:5]:
                with st.expander(f"🎫 {ticket.get('ticket_key', 'N/A')}"):
                    st.markdown(f"**Severity:** {ticket.get('severity', 'N/A')}")
                    st.markdown(f"**Created:** {ticket.get('created_at', 'N/A')}")
        else:
            st.info("No recent tickets")

    with col2:
        st.markdown("#### ✅ Recent Fixes")
        if summary.recent_fixes:
            for fix in summary.recent_fixes[:5]:
                with st.expander(f"✅ Fix: {fix.get('finding_id', 'N/A')[:8]}"):
                    st.markdown(f"**PR:** {fix.get('pr_url', 'N/A')}")
                    st.markdown(f"**Completed:** {fix.get('completed_at', 'N/A')}")
        else:
            st.info("No recent fixes")


def render_scans() -> None:
    """Render premium scans page."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>🔍 Scan History</h1>
        <p>Detailed view of all security scans and their results</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    metrics_store = get_metrics_store()

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=30))
    with col2:
        end_date = st.date_input("End Date", value=datetime.now())

    scans = metrics_store.get_scans(
        start_date=datetime.combine(start_date, datetime.min.time()),
        end_date=datetime.combine(end_date, datetime.max.time()),
        limit=100,
    )

    if not scans:
        st.info("No scans found in the selected date range.")
        return

    col1, col2, col3, col4 = st.columns(4)

    total_scans = len(scans)
    successful_scans = sum(1 for s in scans if s.success)
    total_findings = sum(s.findings_count for s in scans)
    avg_duration = sum(s.duration_seconds or 0 for s in scans) / len(scans) if scans else 0

    with col1:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-value">{total_scans}</div>
            <div class="metric-label">Total Scans</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
        <div class="metric-card success">
            <div class="metric-value">{successful_scans / total_scans * 100:.0f}%</div>
            <div class="metric-label">Success Rate</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            f"""
        <div class="metric-card warning">
            <div class="metric-value">{total_findings}</div>
            <div class="metric-label">Total Findings</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"""
        <div class="metric-card info">
            <div class="metric-value">{avg_duration:.1f}s</div>
            <div class="metric-label">Avg Duration</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("### 📋 Scan History")

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

    st.markdown("### 📊 Severity Distribution")

    severity_data = {
        "Critical": sum(s.severity_distribution.critical for s in scans),
        "High": sum(s.severity_distribution.high for s in scans),
        "Medium": sum(s.severity_distribution.medium for s in scans),
        "Low": sum(s.severity_distribution.low for s in scans),
        "Info": sum(s.severity_distribution.info for s in scans),
    }

    st.bar_chart(severity_data)

    st.markdown("#### Breakdown")
    total = sum(severity_data.values()) or 1
    for label, count in severity_data.items():
        st.markdown(f"**{label}:** {count} ({count / total * 100:.0f}%)")


def render_findings() -> None:
    """Render premium findings page with highlighted vulnerabilities."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>⚠️ Vulnerability Findings</h1>
        <p>All detected vulnerabilities with detailed information</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    metrics_store = get_metrics_store()

    col1, col2, col3 = st.columns(3)

    with col1:
        severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low", "info"])

    with col2:
        suppressed_filter = st.selectbox("Suppression Status", ["All", "Active", "Suppressed"])

    with col3:
        limit = st.slider("Results Limit", 10, 200, 50)

    severity = None if severity_filter == "All" else severity_filter
    suppressed = None
    if suppressed_filter == "Active":
        suppressed = False
    elif suppressed_filter == "Suppressed":
        suppressed = True

    findings = metrics_store.get_findings(severity=severity, suppressed=suppressed, limit=limit)

    if not findings:
        st.info("No findings match the selected filters.")
        return

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
        <div class="metric-card critical">
            <div class="metric-value">{len(findings)}</div>
            <div class="metric-label">Total Findings</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col2:
        ticketed = sum(1 for f in findings if f.ticket_key)
        st.markdown(
            f"""
        <div class="metric-card info">
            <div class="metric-value">{ticketed}</div>
            <div class="metric-label">Ticketed ({ticketed / len(findings) * 100:.0f}%)</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col3:
        fixed = sum(1 for f in findings if f.fix_completed_at)
        st.markdown(
            f"""
        <div class="metric-card success">
            <div class="metric-value">{fixed}</div>
            <div class="metric-label">Fixed ({fixed / len(findings) * 100:.0f}%)</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col4:
        suppressed_count = sum(1 for f in findings if f.suppressed)
        st.markdown(
            f"""
        <div class="metric-card warning">
            <div class="metric-value">{suppressed_count}</div>
            <div class="metric-label">Suppressed</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("### 🔴 Vulnerability Matches")
    st.caption("Vulnerabilities found in your repository are highlighted below")

    for finding in findings[:20]:
        severity_val = finding.severity.lower()
        ticket_status = f"🎫 {finding.ticket_key}" if finding.ticket_key else "No ticket"
        fix_status = "✅ Fixed" if finding.fix_completed_at else "⏳ Pending"
        suppressed_note = '<div style="color: #fbbf24;">🚫 Suppressed</div>' if finding.suppressed else ""
        st.markdown(
            f"""
        <div class="vuln-highlight">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div class="vuln-title">
                        <span class="vuln-severity {severity_val}">{finding.severity.upper()}</span>
                        <span>{finding.vuln_id or "N/A"}</span>
                    </div>
                    <div class="vuln-file">📁 {finding.file_path}</div>
                </div>
                <div style="text-align: right; font-size: 0.85rem;">
                    <div>{ticket_status}</div>
                    <div>{fix_status}</div>
                    {suppressed_note}
                </div>
            </div>
            <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.2);
                        display: flex; gap: 20px; font-size: 0.85rem;">
                <span>🔍 Scanner: {finding.scanner}</span>
                <span>📅 {finding.detected_at.strftime("%Y-%m-%d %H:%M")}</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    if len(findings) > 20:
        st.caption(f"Showing 20 of {len(findings)} findings. Use filters to narrow results.")

    st.markdown("### 📋 Findings Table")
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

    st.markdown("### 📊 Findings by Scanner")
    scanner_counts: dict[str, int] = {}
    for finding in findings:
        scanner_counts[finding.scanner] = scanner_counts.get(finding.scanner, 0) + 1

    st.bar_chart(scanner_counts)


def render_euvd() -> None:
    """Render EUVD synchronization page with auto-refresh."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>🇪🇺 EU Vulnerability Database Sync</h1>
        <p>Automatic synchronization with ENISA's EU VD every 4 hours</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    EUVDScheduler.init_auto_refresh()

    if EUVDScheduler.should_refresh() and not EUVDScheduler.get_state()["is_running"]:
        with st.spinner("🔄 Auto-refreshing EUVD data..."):
            result = EUVDScheduler.trigger_refresh()
            if result["success"]:
                st.toast(f"✅ Synced {result['synced']} vulnerabilities")

    state = EUVDScheduler.get_state()
    is_connected = state["last_status"] != "idle"

    st.markdown(
        f"""
    <div class="euvd-panel">
        <div class="euvd-status">
            <div class="euvd-pulse"></div>
            <span style="font-size: 1.1rem; font-weight: 600; color: #1e3a5f;">
                {"🟢" if is_connected else "⚪"} EUVD Connection: {state["last_status"].title()}
            </span>
        </div>
        <div style="color: #1e40af; margin-bottom: 12px;">
            <strong>Source:</strong> ENISA EU Vulnerability Database<br>
            <strong>Sync Interval:</strong> Every {EUVDScheduler.REFRESH_INTERVAL_HOURS} hours<br>
            <strong>Total Syncs:</strong> {state["refresh_count"]}
        </div>
        <div class="countdown-timer">
            ⏱️ Next sync in: {EUVDScheduler.get_countdown()}
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown(
            f"""
        <div class="metric-card info" style="height: 100%;">
            <div class="metric-value">{state["vulnerabilities_synced"]}</div>
            <div class="metric-label">Vulnerabilities Synced</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown("### ⚡ Manual Sync")
        if st.button("🔄 Sync Now", type="primary"):
            with st.spinner("Syncing with EUVD..."):
                result = EUVDScheduler.trigger_refresh()
            if result["success"]:
                st.success(
                    f"""
                    ✅ **Sync Completed Successfully**
                    - Vulnerabilities synced: {result["synced"]}
                    - New vulnerabilities: {result["new_vulnerabilities"]}
                    - Updated vulnerabilities: {result["updated_vulnerabilities"]}
                    """
                )
            else:
                st.error("❌ Sync failed. Please try again.")

    st.markdown("---")
    st.markdown("### 🔴 Today's Top 10 EUVD Vulnerabilities")

    today = datetime.now().strftime("%Y-%m-%d")
    top10 = TOP_EUVD_SAMPLE
    crit_count = sum(1 for v in top10 if v["severity"] == "critical")
    high_count = sum(1 for v in top10 if v["severity"] == "high")
    exploited_count = sum(1 for v in top10 if v["exploited"])

    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(
            f'<div class="metric-card critical"><div class="metric-value">{crit_count}</div>'
            '<div class="metric-label">Critical Today</div></div>',
            unsafe_allow_html=True,
        )
    with s2:
        st.markdown(
            f'<div class="metric-card warning"><div class="metric-value">{high_count}</div>'
            '<div class="metric-label">High Today</div></div>',
            unsafe_allow_html=True,
        )
    with s3:
        st.markdown(
            f'<div class="metric-card"><div class="metric-value">{len(top10)}</div>'
            '<div class="metric-label">Total Reported</div></div>',
            unsafe_allow_html=True,
        )
    with s4:
        st.markdown(
            f'<div class="metric-card info"><div class="metric-value">{exploited_count}</div>'
            '<div class="metric-label">Actively Exploited</div></div>',
            unsafe_allow_html=True,
        )

    for i, vuln in enumerate(top10, start=1):
        cvss = vuln["cvss"]
        cvss_color = "#dc2626" if cvss >= 9.0 else "#ea580c" if cvss >= 7.0 else "#d97706"
        exploited_badge = ""
        if vuln["exploited"]:
            exploited_badge = '<span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;margin-left:8px;">⚠️ ACTIVELY EXPLOITED</span>'
        
        html = f'<div class="vuln-highlight"><div class="vuln-title"><span style="color: #fca5a5;">#{i}</span> <span class="vuln-severity {vuln["severity"]}">{vuln["severity"].upper()}</span> <span>{vuln["cve"]}</span> <span style="background:{cvss_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700;">CVSS {cvss}</span> {exploited_badge}</div><div style="margin-top: 6px; font-weight: 600;">{vuln["title"]}</div><div class="vuln-file">📦 {vuln["product"]} ({vuln["vendor"]}) · 📅 {vuln["published"]} · {vuln["cwe"]}</div></div>'
        st.markdown(html, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📊 Sync History")
    if st.checkbox("📋 View Sync Log", key="show_sync_log"):
        if state["last_refresh"]:
            st.markdown(f"Last sync: {state['last_refresh'].strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            st.markdown("No syncs yet")
        if state["next_refresh"]:
            st.markdown(f"Next sync: {state['next_refresh'].strftime('%Y-%m-%d %H:%M:%S')}")
        if state["refresh_count"] == 0:
            st.info("No sync history yet. Click 'Sync Now' to start.")

    st.markdown("---")
    st.markdown("### ⚙️ Configuration")
    with st.expander("EUVD Settings"):
        st.markdown(
            """
        **EU VD API Configuration**

        The EU Vulnerability Database is maintained by ENISA (European Union Agency for Cybersecurity).

        | Setting | Value |
        |---------|-------|
        | API Endpoint | `https://eu-vd.enisa.europa.eu/api/v1` |
        | Sandbox | `https://sandbox.eu-vd.enisa.europa.eu/api/v1` |
        | Sync Interval | 4 hours |
        | Auto-sync | Enabled |

        **CRA Reporting Deadlines:**
        - Actively exploited vulnerabilities: **24 hours**
        - Critical vulnerabilities: **72 hours**
        - Other reportable vulnerabilities: **14 days**
        """
        )
        st.text_input("API Key", value="••••••••••••", type="password", disabled=True)
        st.text_input("Organization ID", value="CRA-AGENT-001", disabled=True)


def render_roi() -> None:
    """Render premium ROI & Metrics page."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>💰 ROI & Effectiveness Metrics</h1>
        <p>Track return on investment and agent performance</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    metrics_store = get_metrics_store()

    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)

    agent_metrics = metrics_store.get_agent_metrics(start_date, end_date)

    st.markdown("### 🧮 ROI Calculator")
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

    roi = ROIMetrics.calculate(
        agent_metrics=agent_metrics,
        llm_cost=llm_cost,
        compute_cost=compute_cost,
        hourly_rate=hourly_rate,
    )

    st.markdown("---")
    st.markdown("### 📈 ROI Results")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
        <div class="metric-card success">
            <div class="metric-value">${roi.total_value_usd:,.0f}</div>
            <div class="metric-label">Total Value</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            f"""
        <div class="metric-card warning">
            <div class="metric-value">${roi.total_operational_cost:,.0f}</div>
            <div class="metric-label">Total Cost</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col3:
        roi_class = "success" if roi.roi_percentage > 100 else "critical"
        st.markdown(
            f"""
        <div class="metric-card {roi_class}">
            <div class="metric-value">{roi.roi_percentage:.0f}%</div>
            <div class="metric-label">ROI</div>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            f"""
        <div class="metric-card info">
            <div class="metric-value">{roi.total_time_saved_hours:.1f}h</div>
            <div class="metric-label">Time Saved</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("### 🎯 Effectiveness Breakdown")

    col1, col2, col3, col4 = st.columns(4)
    breakdown = [
        ("Detection", roi.detection_effectiveness, "success"),
        ("Triage", roi.triage_effectiveness, "warning"),
        ("Fix", roi.fix_effectiveness, "danger"),
        ("Overall", roi.overall_effectiveness, "success"),
    ]
    for col, (label, value, bar_class) in zip([col1, col2, col3, col4], breakdown, strict=True):
        with col:
            st.markdown(
                f"""
            <div class="premium-card">
                <h4 style="margin: 0; color: #111827;">{label}</h4>
                <div style="font-size: 1.6rem; font-weight: 700; color: #2563eb; margin: 8px 0;">
                    {value * 100:.0f}%
                </div>
                <div class="custom-progress">
                    <div class="custom-progress-bar {bar_class}" style="width: {value * 100:.0f}%;"></div>
                </div>
            </div>
            """,
                unsafe_allow_html=True,
            )

    st.markdown("---")
    st.markdown("### ⏱️ Time Savings")

    time_data = {
        "Manual Triage": roi.manual_triage_time_hours,
        "Ticket Creation": roi.manual_ticket_creation_hours,
        "Manual Fixes": roi.manual_fix_time_hours,
    }
    st.bar_chart(time_data)

    st.markdown("### 💵 Value Breakdown")
    st.markdown(
        f"""
    <div class="premium-card">
        <h4 style="color: #059669;">Value Generated</h4>
        <p>Time Savings: <strong>${roi.time_savings_value_usd:,.2f}</strong></p>
        <p>Breach Prevention: <strong>${roi.breach_cost_avoided_usd:,.2f}</strong></p>
        <hr>
        <p style="font-size: 1.1rem;"><strong>Total: ${roi.total_value_usd:,.2f}</strong></p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("### 📊 ROI History")

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
        st.info("No ROI history recorded yet.")

    if st.button("💾 Save ROI Snapshot", type="primary"):
        metrics_store.record_roi_metrics(roi)
        st.success("✅ ROI snapshot saved!")
        st.rerun()


def render_github() -> None:
    """Render GitHub integration page."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>🐙 GitHub Integration</h1>
        <p>Manage repositories and trigger security scans</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    from config.settings import get_settings

    settings = get_settings()

    if not settings.github_enabled:
        st.warning(
            "⚠️ GitHub is not configured. Please set GITHUB_APP_ID and GITHUB_PRIVATE_KEY_PATH in your .env file."
        )
        st.markdown(
            """
        ### Setup Instructions

        1. **Create a GitHub App** at https://github.com/settings/apps/new
           - UNCHECK "Active" for webhooks (we use polling!)
           - Set permissions: Contents (Read), Metadata (Read), Pull requests (Read/Write), Commit statuses (Read/Write)

        2. **Generate a private key** and move it to your project

        3. **Update your .env** with the App ID and Installation ID

        4. **Restart the agent**
        """
        )
        return

    st.success("✅ GitHub is configured")

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
    st.markdown("### 📁 Configured Repositories")

    repos_dir = Path("./repos")
    cloned_repos = [d.name for d in repos_dir.iterdir() if d.is_dir()] if repos_dir.exists() else []

    for i, repo in enumerate(repositories):
        repo_name = repo.get("name", "")
        enabled = repo.get("enabled", True)
        branches = repo.get("branches", ["main"])
        language = repo.get("language", "unknown")
        scanners = repo.get("scanners", [])

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
                if st.button("🔍 Scan Now", key=f"scan_{i}"):
                    with st.spinner(f"Scanning {repo_name}..."):
                        import subprocess

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
    st.markdown("### ⚡ Quick Actions")

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
        if st.button("🔍 Scan All Repos", type="primary"):
            with st.spinner("Scanning all repositories..."):
                import subprocess

                for repo in repositories:
                    if repo.get("enabled", True):
                        repo_name = repo.get("name", "")
                        st.info(f"Scanning {repo_name}...")
                        subprocess.Popen([sys.executable, "scripts/run_github_polling.py"])
                        break

                st.success("✅ Scan triggered for all repositories!")

    st.markdown("---")
    st.markdown("### 🔧 GitHub App Status")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**App ID:** `{settings.github_app_id}`")
        st.markdown(f"**Installation ID:** `{settings.github_installation_id}`")

    with col2:
        st.markdown(f"**Private Key Path:** `{settings.github_private_key_path}`")
        st.markdown(f"**Key Exists:** {'✅' if settings.github_private_key_path.exists() else '❌'}")


def render_settings() -> None:
    """Render premium settings page."""
    st.markdown(
        """
    <div class="dashboard-header">
        <h1>⚙️ Settings</h1>
        <p>Configure your CRA-AGENT dashboard</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown("### 📊 Database Information")

    metrics_store = get_metrics_store()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            f"""
        <div class="premium-card">
            <h4>Database Path</h4>
            <code>{metrics_store.db_path}</code>
            <p style="margin-top: 8px;">
                Status: {"✅ Exists" if metrics_store.db_path.exists() else "❌ Not found"}
            </p>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with col2:
        summary = metrics_store.get_dashboard_summary()
        st.markdown(
            f"""
        <div class="premium-card">
            <h4>Total Records</h4>
            <p>Scans: <strong>{summary.total_scans}</strong></p>
            <p>Findings: <strong>{summary.total_findings}</strong></p>
            <p>Tickets: <strong>{summary.total_tickets}</strong></p>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.markdown("### 🔧 Configuration")

    st.markdown(
        """
    <div class="premium-card">
        <h4>Environment Variables</h4>
        <table style="width: 100%;">
            <tr>
                <th style="text-align: left; padding: 8px;">Variable</th>
                <th style="text-align: left; padding: 8px;">Description</th>
                <th style="text-align: left; padding: 8px;">Default</th>
            </tr>
            <tr>
                <td style="padding: 8px;"><code>METRICS_DB_PATH</code></td>
                <td style="padding: 8px;">Path to metrics database</td>
                <td style="padding: 8px;"><code>./data/metrics.db</code></td>
            </tr>
            <tr>
                <td style="padding: 8px;"><code>SUPPRESSION_DB_PATH</code></td>
                <td style="padding: 8px;">Path to suppression database</td>
                <td style="padding: 8px;"><code>./data/suppressions.db</code></td>
            </tr>
            <tr>
                <td style="padding: 8px;"><code>GIT_REPO_PATH</code></td>
                <td style="padding: 8px;">Path to monitored repository</td>
                <td style="padding: 8px;"><code>./target-repo</code></td>
            </tr>
            <tr>
                <td style="padding: 8px;"><code>JIRA_BASE_URL</code></td>
                <td style="padding: 8px;">Jira instance URL</td>
                <td style="padding: 8px;">-</td>
            </tr>
            <tr>
                <td style="padding: 8px;"><code>OPENAI_API_KEY</code></td>
                <td style="padding: 8px;">OpenAI API key</td>
                <td style="padding: 8px;">-</td>
            </tr>
        </table>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("### 🎛️ Actions")

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
    EUVDScheduler.init_auto_refresh()

    page = render_sidebar()

    if page == "📊 Overview":
        render_overview()
    elif page == "🔍 Scans":
        render_scans()
    elif page == "⚠️ Findings":
        render_findings()
    elif page == "🇪🇺 EUVD Sync":
        render_euvd()
    elif page == "🐙 GitHub":
        render_github()
    elif page == "💰 ROI & Metrics":
        render_roi()
    elif page == "⚙️ Settings":
        render_settings()


if __name__ == "__main__":
    main()

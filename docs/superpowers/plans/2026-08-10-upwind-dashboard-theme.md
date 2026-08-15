# Upwind-Inspired Dashboard Theme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the Streamlit dashboard (`src/dashboard/app.py`) to match upwind.io's visual language — dark navy sidebar, cyan/amber accents, light content area with card-styled metrics and charts — while keeping every page working exactly as before.

**Architecture:** Hybrid theming: `.streamlit/config.toml` sets the base light theme and primary accent color for native widgets; a custom CSS block in `app.py` overrides the sidebar to dark navy (which `config.toml` alone cannot do, since it themes the whole app uniformly) and adds pill/badge components. Sidebar navigation moves from `st.sidebar.radio` to `st.sidebar.button` per page so the active page can be visually highlighted using Streamlit's native `type="primary"` button styling — this also fixes a pre-existing bug where the "ROI & Metrics" nav option used a different (broken/mojibake) emoji than the string `main()` checked against, making that page unreachable. All 4 `st.bar_chart` call sites are replaced with Plotly for full color control.

**Tech Stack:** Streamlit 1.61 (already pinned `>=1.38.0`), Plotly `>=5.24.0` (already a dependency), pandas `>=2.2.0` (already a dependency) — no new dependencies. Tests use `streamlit.testing.v1.AppTest` (Streamlit's official headless test harness) plus pytest.

## Global Constraints

- No new dependencies — `streamlit`, `plotly`, `pandas` are already in `pyproject.toml`.
- Severity colors (critical/high/medium/low/info) stay semantic (red/orange/yellow/blue/gray) — never remapped to brand cyan/amber.
- Sidebar: dark navy `#0F172A` background, `#E2E8F0` text, `#22D3EE` cyan accent for the active nav item.
- Content area: light `#F8FAFC` background, `#1E293B` text, white `#FFFFFF` cards with `#E2E8F0` borders and a `12px` border radius.
- Primary accent `#22D3EE` (cyan), secondary accent `#F59E0B` (amber).
- Every existing feature (filters, expanders, buttons, the "Scan Now"/"Clone"/ROI-snapshot actions) must keep working identically — this is a visual-only change.
- CSS/visual correctness can't be asserted by pytest — each task pairs an automated `AppTest`-based smoke test (no exception raised, correct page/session-state behavior) with a manual browser-verification step for color/layout.

---

## File Structure

- Create: `.streamlit/config.toml` — Streamlit native theme config.
- Modify: `src/dashboard/app.py` — CSS block, constants, helper functions, `render_sidebar`, `render_overview`, `render_scans`, `render_findings`, `render_roi`, `main`.
- Create: `tests/test_dashboard/__init__.py`
- Create: `tests/test_dashboard/test_app.py` — `AppTest`-based smoke tests.

---

### Task 1: Streamlit theme config

**Files:**
- Create: `.streamlit/config.toml`

**Interfaces:**
- Produces: base theme (`primaryColor`, `backgroundColor`, `secondaryBackgroundColor`, `textColor`, `font`) consumed automatically by every native Streamlit widget (buttons, inputs, sliders, metrics) app-wide. No Python API — pure config.

- [ ] **Step 1: Write the config file**

```toml
[theme]
base = "light"
primaryColor = "#22D3EE"
backgroundColor = "#F8FAFC"
secondaryBackgroundColor = "#FFFFFF"
textColor = "#1E293B"
font = "sans serif"
```

- [ ] **Step 2: Verify Streamlit picks it up**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && streamlit config show | grep -A6 "\[theme\]"`
Expected: output includes `primaryColor = "#22D3EE"` and the other values from the file (confirms the TOML is valid and loaded).

- [ ] **Step 3: Commit**

```bash
git add .streamlit/config.toml
git commit -m "feat: add Upwind-inspired Streamlit theme config"
```

---

### Task 2: Design tokens, CSS, and chart/badge helpers

**Files:**
- Modify: `src/dashboard/app.py:1-56` (imports + CSS block)
- Test: `tests/test_dashboard/__init__.py`, `tests/test_dashboard/test_app.py`

**Interfaces:**
- Produces:
  - `SEVERITY_COLORS: dict[str, str]` — keys `"critical"|"high"|"medium"|"low"|"info"` (lowercase) → hex color.
  - `ACCENT_PRIMARY: str` = `"#22D3EE"`, `ACCENT_SECONDARY: str` = `"#F59E0B"`.
  - `render_severity_badge(severity: str) -> str` — returns an HTML `<span>` pill; caller must render with `unsafe_allow_html=True`.
  - `render_status_pill(status: str) -> str` — returns an HTML `<span>` pill for agent status; caller must render with `unsafe_allow_html=True`.
  - `make_bar_chart(data: dict[str, float], color: str | list[str] = ACCENT_PRIMARY, height: int = 300) -> go.Figure` — themed Plotly bar chart, consumed by Tasks 4-7 via `st.plotly_chart(fig, use_container_width=True)`.
- Consumes: nothing new (pure additions).

- [ ] **Step 1: Write the smoke test first**

Create `tests/test_dashboard/__init__.py` (empty file).

Create `tests/test_dashboard/test_app.py`:

```python
"""Smoke tests for the Streamlit dashboard using AppTest."""

from __future__ import annotations

from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from src.analytics.metrics_store import MetricsStore

APP_PATH = str(Path(__file__).parent.parent.parent / "src" / "dashboard" / "app.py")


@pytest.fixture
def dashboard_env(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the dashboard at an isolated, empty metrics DB.

    get_metrics_store() is @st.cache_resource'd with no args, so its cache
    key is identical across every test in this file/process. Without
    clearing it here, the second test to run would silently reuse the
    first test's cached MetricsStore (pointed at the first test's temp_dir)
    instead of picking up this test's env vars.
    """
    st.cache_resource.clear()
    metrics_db = temp_dir / "metrics.db"
    suppressions_db = temp_dir / "suppressions.db"
    MetricsStore(metrics_db)  # creates schema
    monkeypatch.setenv("METRICS_DB_PATH", str(metrics_db))
    monkeypatch.setenv("SUPPRESSION_DB_PATH", str(suppressions_db))
    return temp_dir


def test_dashboard_loads_without_exception(dashboard_env: Path) -> None:
    at = AppTest.from_file(APP_PATH, default_timeout=30).run()
    assert not at.exception
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: currently should actually PASS already (app.py runs fine pre-change) — this step instead confirms the harness works. If it fails, read the exception message before proceeding; it means something in the *current* app already errors under `AppTest` (e.g. a missing env var) and must be understood before adding more code on top.

- [ ] **Step 3: Add constants and helpers to app.py**

Replace `src/dashboard/app.py:1-56` with:

```python
"""CRA-AGENT Dashboard — Streamlit UI for metrics visualization.

Run with: streamlit run src/dashboard/app.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analytics.metrics_store import MetricsStore
from src.analytics.models import AgentMetrics, ROIMetrics

# Page config
st.set_page_config(
    page_title="CRA-AGENT Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Design tokens
ACCENT_PRIMARY = "#22D3EE"
ACCENT_SECONDARY = "#F59E0B"
SEVERITY_COLORS = {
    "critical": "#DC2626",
    "high": "#F97316",
    "medium": "#EAB308",
    "low": "#3B82F6",
    "info": "#64748B",
}

# Sidebar nav: (button label, session_state key)
PAGES = [
    ("📊 Overview", "overview"),
    ("🔍 Scans", "scans"),
    ("⚠️ Findings", "findings"),
    ("🐙 GitHub", "github"),
    ("💰 ROI & Metrics", "roi"),
    ("⚙️ Settings", "settings"),
]

# Custom CSS
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', system-ui, -apple-system, sans-serif;
    }

    h1, h2, h3, h4 {
        font-weight: 600;
        color: #1E293B;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #0F172A;
    }
    [data-testid="stSidebar"] * {
        color: #E2E8F0;
    }
    [data-testid="stSidebar"] hr {
        border-color: #1E293B;
    }
    [data-testid="stSidebar"] .stButton button {
        background-color: transparent;
        border: 1px solid transparent;
        color: #E2E8F0;
        text-align: left;
        justify-content: flex-start;
        width: 100%;
    }
    [data-testid="stSidebar"] .stButton button[kind="primary"] {
        background-color: rgba(34, 211, 238, 0.15);
        border: 1px solid #22D3EE;
        color: #22D3EE;
    }
    [data-testid="stSidebar"] .stButton button[kind="secondary"]:hover {
        background-color: #1E293B;
        color: #FFFFFF;
    }

    /* Native st.metric widgets, styled as cards everywhere they appear */
    [data-testid="stMetric"] {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-top: 3px solid #22D3EE;
        border-radius: 12px;
        padding: 16px 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.06);
    }
    [data-testid="stMetricValue"] {
        color: #0F172A;
        font-weight: 700;
    }
    [data-testid="stMetricLabel"] {
        color: #64748B;
    }

    /* Status pill (sidebar agent status) */
    .status-pill {
        font-weight: 600;
        font-size: 0.95rem;
    }

    /* Severity badge pill */
    .severity-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.02em;
    }
</style>
""",
    unsafe_allow_html=True,
)


def render_severity_badge(severity: str) -> str:
    """Return HTML for a colored severity pill badge (semantic, not brand colors)."""
    color = SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["info"])
    return (
        f'<span class="severity-badge" '
        f'style="background-color:{color}1A;color:{color};border:1px solid {color}66;">'
        f"{severity.upper()}</span>"
    )


def render_status_pill(status: str) -> str:
    """Return HTML for the agent-status pill (green=running, red=stopped)."""
    color = "#22C55E" if status == "running" else "#EF4444"
    return f'<span class="status-pill" style="color:{color};">● {status.title()}</span>'


def make_bar_chart(
    data: dict[str, float],
    color: str | list[str] = ACCENT_PRIMARY,
    height: int = 300,
) -> go.Figure:
    """Build a themed Plotly bar chart matching the dashboard's light card style."""
    fig = go.Figure(data=[go.Bar(x=list(data.keys()), y=list(data.values()), marker_color=color)])
    fig.update_layout(
        template="plotly_white",
        height=height,
        margin=dict(l=10, r=10, t=10, b=10),
        font=dict(family="Inter, system-ui, sans-serif", color="#1E293B"),
        plot_bgcolor="#FFFFFF",
        paper_bgcolor="#FFFFFF",
        showlegend=False,
    )
    fig.update_xaxes(gridcolor="#E2E8F0")
    fig.update_yaxes(gridcolor="#E2E8F0")
    return fig
```

- [ ] **Step 4: Run the smoke test again**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: PASS (app still loads with no exception — the new constants/CSS/helpers aren't wired into any render function yet, so behavior is unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/dashboard/app.py tests/test_dashboard/
git commit -m "feat: add Upwind design tokens, CSS, and chart/badge helpers"
```

---

### Task 3: Sidebar navigation rebuild (fixes dead ROI page bug)

**Files:**
- Modify: `src/dashboard/app.py:66-101` (`render_sidebar`)
- Modify: `src/dashboard/app.py:825-844` (`main`)
- Test: `tests/test_dashboard/test_app.py`

**Interfaces:**
- Consumes: `PAGES`, `render_status_pill` from Task 2.
- Produces: `render_sidebar() -> str` now returns a page **key** (`"overview"`, `"scans"`, etc. — one of the second elements of `PAGES` tuples), not the old emoji-label string. `main()` dispatches via a `PAGE_RENDERERS: dict[str, Callable[[], None]]` built from the six `render_*` functions, keyed the same way.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_dashboard/test_app.py`:

```python
def test_sidebar_nav_reaches_every_page(dashboard_env: Path) -> None:
    at = AppTest.from_file(APP_PATH, default_timeout=30).run()
    assert not at.exception

    # 6 nav buttons: Overview, Scans, Findings, GitHub, ROI & Metrics, Settings
    nav_buttons = at.sidebar.button
    assert len(nav_buttons) == 6

    for i in range(len(nav_buttons)):
        at.sidebar.button[i].click().run()
        assert not at.exception, f"page at nav index {i} raised: {at.exception}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py::test_sidebar_nav_reaches_every_page -v`
Expected: FAIL — `at.sidebar.button` is empty (current sidebar uses `st.sidebar.radio`, not buttons).

- [ ] **Step 3: Rebuild render_sidebar**

Replace `src/dashboard/app.py:66-101` with:

```python
def render_sidebar() -> str:
    """Render sidebar navigation. Returns the active page key."""
    st.sidebar.title("🛡️ CRA-AGENT")
    st.sidebar.markdown("---")

    if "current_page" not in st.session_state:
        st.session_state.current_page = PAGES[0][1]

    for label, key in PAGES:
        is_active = st.session_state.current_page == key
        if st.sidebar.button(
            label,
            key=f"nav_{key}",
            type="primary" if is_active else "secondary",
            use_container_width=True,
        ):
            st.session_state.current_page = key
            st.rerun()

    st.sidebar.markdown("---")

    # Agent status
    st.sidebar.markdown("### Agent Status")
    metrics_store = get_metrics_store()
    summary = metrics_store.get_dashboard_summary()

    st.sidebar.markdown(render_status_pill(summary.agent_status), unsafe_allow_html=True)

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

    return st.session_state.current_page
```

- [ ] **Step 4: Update main() to dispatch by key**

Replace `src/dashboard/app.py:825-844` with:

```python
PAGE_RENDERERS = {
    "overview": render_overview,
    "scans": render_scans,
    "findings": render_findings,
    "github": render_github,
    "roi": render_roi,
    "settings": render_settings,
}


def main() -> None:
    """Main dashboard entry point."""
    page_key = render_sidebar()
    PAGE_RENDERERS[page_key]()


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: PASS — all 6 nav buttons present, clicking each reaches its page with no exception (this also proves the ROI page, previously unreachable due to the emoji-mismatch bug, now renders).

- [ ] **Step 6: Manual visual check**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && streamlit run src/dashboard/app.py`
Open the browser tab Streamlit prints. Confirm: sidebar is dark navy, the active nav button (Overview, by default) is highlighted with a cyan border/background, clicking another nav item switches pages and moves the highlight, "Agent Status" shows a colored dot pill instead of plain emoji text.

- [ ] **Step 7: Commit**

```bash
git add src/dashboard/app.py tests/test_dashboard/test_app.py
git commit -m "feat: rebuild sidebar nav as highlighted buttons, fix dead ROI page"
```

---

### Task 4: Overview page — Plotly charts + severity badge

**Files:**
- Modify: `src/dashboard/app.py` (`render_overview`, currently at lines 103-201 before this task's edits)

**Interfaces:**
- Consumes: `make_bar_chart`, `render_severity_badge` from Task 2.
- Produces: no change to `render_overview`'s signature (`() -> None`).

- [ ] **Step 1: Replace the two `st.bar_chart` calls**

In `render_overview`, replace:

```python
        st.bar_chart(today_data)
```

with:

```python
        st.plotly_chart(make_bar_chart(today_data), use_container_width=True)
```

And replace:

```python
        st.bar_chart(week_data)
```

with:

```python
        st.plotly_chart(make_bar_chart(week_data), use_container_width=True)
```

- [ ] **Step 2: Replace the recent-findings expander badge**

Replace:

```python
with st.expander(f"🔴 {finding.get('severity', 'unknown').upper()}: {finding.get('vuln_id', 'N/A')}"):
    st.markdown(f"**File:** `{finding.get('file', 'N/A')}`")
    st.markdown(f"**Detected:** {finding.get('detected_at', 'N/A')}")
```

with:

```python
                severity = finding.get("severity", "unknown")
                with st.expander(f"{finding.get('vuln_id', 'N/A')}"):
                    st.markdown(render_severity_badge(severity), unsafe_allow_html=True)
                    st.markdown(f"**File:** `{finding.get('file', 'N/A')}`")
                    st.markdown(f"**Detected:** {finding.get('detected_at', 'N/A')}")
```

- [ ] **Step 3: Run the full test suite**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: PASS (no exception on any page, including Overview with its new Plotly charts).

- [ ] **Step 4: Manual visual check**

With `streamlit run src/dashboard/app.py` still running (rerun/refresh the browser tab), go to Overview. Confirm the "Today"/"This Week" bar charts render with cyan bars and a white background matching the surrounding cards, and expanding a recent finding shows a colored severity pill above the file/detected-at lines.

- [ ] **Step 5: Commit**

```bash
git add src/dashboard/app.py
git commit -m "feat: theme Overview page charts and severity badge"
```

---

### Task 5: Scans page — severity-colored Plotly chart

**Files:**
- Modify: `src/dashboard/app.py` (`render_scans`)

**Interfaces:**
- Consumes: `make_bar_chart`, `SEVERITY_COLORS` from Task 2.

- [ ] **Step 1: Replace the severity distribution chart**

Replace:

```python
    st.bar_chart(severity_data)
```

with:

```python
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    ordered_colors = [SEVERITY_COLORS[s.lower()] for s in severity_order]
    st.plotly_chart(
        make_bar_chart(severity_data, color=ordered_colors),
        use_container_width=True,
    )
```

Note: `severity_data` (built two steps earlier in this function) is already an ordered dict with keys `"Critical", "High", "Medium", "Low", "Info"` in that exact order — `ordered_colors` must line up 1:1 with it.

- [ ] **Step 2: Run the test suite**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: PASS.

- [ ] **Step 3: Manual visual check**

In the browser, go to Scans (pick a date range covering existing scan data if any, or confirm the "No scans found" empty state still shows correctly for an empty range). Confirm the severity chart's bars are colored red/orange/yellow/blue/gray matching `SEVERITY_COLORS`, not a single flat color.

- [ ] **Step 4: Commit**

```bash
git add src/dashboard/app.py
git commit -m "feat: theme Scans page severity chart with semantic colors"
```

---

### Task 6: Findings page — Plotly chart + colored severity column

**Files:**
- Modify: `src/dashboard/app.py` (`render_findings`)

**Interfaces:**
- Consumes: `make_bar_chart`, `SEVERITY_COLORS` from Task 2; `pandas` (new import in this file).

- [ ] **Step 1: Add the pandas import**

At the top of `src/dashboard/app.py`, in the import block established in Task 2, add:

```python
import pandas as pd
```

(alongside the existing `import plotly.graph_objects as go` line).

- [ ] **Step 2: Color the Severity column in the findings table**

Replace:

```python
    st.dataframe(finding_data, use_container_width=True)
```

with:

```python
findings_df = pd.DataFrame(finding_data)


def _color_severity(val: str) -> str:
    color = SEVERITY_COLORS.get(val.lower(), SEVERITY_COLORS["info"])
    return f"color: {color}; font-weight: 600;"


styled_df = findings_df.style.map(_color_severity, subset=["Severity"])
st.dataframe(styled_df, use_container_width=True)
```

- [ ] **Step 3: Replace the scanner distribution chart**

Replace:

```python
    st.bar_chart(scanner_counts)
```

with:

```python
    st.plotly_chart(make_bar_chart(scanner_counts), use_container_width=True)
```

- [ ] **Step 4: Run the test suite**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: PASS. If it fails with an `AttributeError` on `.style.map`, the installed pandas version predates `Styler.map` (added in pandas 2.1, replacing the deprecated `applymap`) — check with `python -c "import pandas; print(pandas.__version__)"`; the project already pins `pandas>=2.2.0` so this should not occur, but if it does, use `.style.applymap(_color_severity, subset=["Severity"])` instead.

- [ ] **Step 5: Manual visual check**

Go to Findings. If there's existing finding data, confirm the Severity column text is colored per severity; if not, note the "No findings match the selected filters" empty state still works, and confirm the scanner-count chart (once data exists) renders with cyan bars.

- [ ] **Step 6: Commit**

```bash
git add src/dashboard/app.py
git commit -m "feat: theme Findings page chart and severity-colored table"
```

---

### Task 7: ROI & Metrics page — Plotly chart

**Files:**
- Modify: `src/dashboard/app.py` (`render_roi`)

**Interfaces:**
- Consumes: `make_bar_chart` from Task 2.

- [ ] **Step 1: Replace the time-savings chart**

Replace:

```python
    st.bar_chart(time_data)
```

with:

```python
    st.plotly_chart(make_bar_chart(time_data, color=ACCENT_SECONDARY), use_container_width=True)
```

(This chart uses the amber secondary accent rather than cyan, to visually distinguish "cost/time" charts from "activity" charts elsewhere in the dashboard.)

- [ ] **Step 2: Run the test suite**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/test_app.py -v`
Expected: PASS.

- [ ] **Step 3: Manual visual check**

Go to ROI & Metrics (previously unreachable before Task 3's fix — confirm it loads at all, then check the theme). Confirm the "Time Savings Breakdown" chart renders with amber bars, the four `st.metric` cards above it show the cyan-top-border card style from Task 2's CSS, and the "Save ROI Snapshot" button still works (click it, confirm the success message and table update still happen).

- [ ] **Step 4: Commit**

```bash
git add src/dashboard/app.py
git commit -m "feat: theme ROI page time-savings chart"
```

---

### Task 8: Full pass — GitHub and Settings pages, final review

**Files:**
- None expected to change (GitHub and Settings pages use no `st.bar_chart` and have no severity data — Global Constraints' card/metric/font styling from Task 2 already applies automatically via the `[data-testid="stMetric"]` CSS selectors and Google Font import, with no code changes needed in `render_github`/`render_settings`).

**Interfaces:** none new.

- [ ] **Step 1: Run the full test suite one more time**

Run: `cd /Users/rohit/Github/CRA-AGENT && source .venv/bin/activate && python -m pytest tests/test_dashboard/ -v`
Expected: all tests PASS.

- [ ] **Step 2: Full manual walkthrough**

With `streamlit run src/dashboard/app.py` running, click through all 6 sidebar pages in order (Overview → Scans → Findings → GitHub → ROI & Metrics → Settings). For each, confirm:
- No Streamlit error/traceback banner appears.
- Sidebar stays dark navy with the correct page highlighted the whole time.
- Any `st.metric` widgets show the white card / cyan top-border style.
- Fonts look like Inter (sans-serif, not the Streamlit default serif-ish fallback) — if the Google Fonts CDN is blocked in this environment, the CSS falls back to `system-ui`, which is an acceptable degradation, not a bug.

Also specifically re-verify GitHub page: if a GitHub App is configured (per `.env`), confirm the repo list expanders, "Scan Now"/"Clone"/"Clone All"/"Scan All" buttons still work exactly as before (this task changes no code there, but it's the one page most likely to be affected by global CSS/font changes since it has the most custom markdown).

- [ ] **Step 3: Commit (only if Step 2 surfaced fixes)**

If the manual walkthrough required any small CSS tweak (e.g. a contrast issue), make the fix in `app.py`'s CSS block, rerun the test suite, then:

```bash
git add src/dashboard/app.py
git commit -m "fix: theme polish from full walkthrough"
```

If no fixes were needed, skip this commit — Task 7's commit is the last one.

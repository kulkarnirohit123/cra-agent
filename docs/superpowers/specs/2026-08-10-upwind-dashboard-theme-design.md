# Upwind-Inspired Dashboard Theme

## Context

CRA-AGENT's Streamlit dashboard (`src/dashboard/app.py`) currently uses default
Streamlit styling: a light gray `.metric-card` block, plain-text status colors,
and native `st.bar_chart` for all visualizations. The goal is to restyle it to
match the visual language of upwind.io — a dark-navy, cyan/amber-accented
modern security-product aesthetic — while keeping the dashboard's content area
readable for dense tables and charts.

Reference site color analysis (upwind.io): deep navy background (~`#0F172A`),
electric-cyan accents, amber/orange secondary accent, glassmorphism cards,
generous spacing, rounded corners, minimal SVG iconography.

## Scope

Full dashboard theme, applied consistently across all 6 pages: Overview,
Scans, Findings, GitHub, ROI & Metrics, Settings.

Theme mode: **dark sidebar, light content area** — sidebar/nav styled dark
navy like Upwind's header/nav; main content area stays light for readability
of dense tables and charts.

Charts: swap all `st.bar_chart` calls to Plotly for full color control.

## Color Palette (Design Tokens)

| Token | Value | Usage |
|---|---|---|
| `sidebar-bg` | `#0F172A` | Sidebar background |
| `sidebar-text` | `#E2E8F0` | Sidebar text |
| `sidebar-active-bg` | `#1E293B` with cyan tint | Active nav item background |
| `accent-primary` | `#22D3EE` (cyan) | Buttons, links, primary chart series, active states |
| `accent-secondary` | `#F59E0B` (amber) | CTAs, in-progress/pending states |
| `content-bg` | `#F8FAFC` | Main content background |
| `content-text` | `#1E293B` | Main content text |
| `card-bg` | `#FFFFFF` | Card backgrounds |
| `card-border` | `#E2E8F0` | Card borders |
| `severity-critical` | `#DC2626` | Critical severity (semantic, not brand) |
| `severity-high` | `#F97316` | High severity |
| `severity-medium` | `#EAB308` | Medium severity |
| `severity-low` | `#3B82F6` | Low severity |
| `severity-info` | `#64748B` | Info severity |

Severity colors are kept semantic (red/orange/yellow/blue) rather than
remapped to brand colors, since they carry safety meaning independent of
the visual theme.

## Implementation Mechanism

Hybrid approach, required because Streamlit's native theming
(`.streamlit/config.toml`) themes the whole app uniformly and cannot style
the sidebar differently from the content area:

1. **`.streamlit/config.toml`** (new file) sets the base light theme and
   `primaryColor = "#22D3EE"`, covering buttons, inputs, radio/select
   widgets, and other native components for free.
2. **Custom CSS block** in `app.py` (replacing the existing block at
   app.py:30-56) overrides `[data-testid="stSidebar"]` and its descendants
   to dark navy, and adds the new component classes described below.

## Components

- **`.metric-card`**: white background, cyan top border accent (3px),
  rounded corners (12px), soft shadow, larger bold value text.
- **Status pill** (Agent Status in sidebar): rounded pill with colored dot
  (green=running, red=stopped) + label, replacing the current plain
  emoji + bold text.
- **Severity badges** (Findings page): colored pill chips using the
  semantic severity colors above, replacing the current emoji + plain text
  in expander titles.
- **Sidebar nav**: active page item gets a subtle cyan-tinted background
  and left border accent.

## Charts

Replace all 4 `st.bar_chart` call sites with Plotly (`plotly.express` or
`plotly.graph_objects`):

- `render_overview` (app.py:156, app.py:166) — today/week scan activity,
  cyan single-series bars.
- `render_scans` (app.py:279) — severity distribution, bars colored per
  severity token above.
- `render_findings` (app.py:368) — scanner counts, cyan single-series bars.
- `render_roi` (app.py:492) — time-saved trend, cyan single-series bars.

Chart template: `plotly_white`, customized with the palette's fonts/colors
so charts sit visually consistent with the light content-area cards.

## Typography

`Inter` (Google Fonts CDN, with `system-ui` fallback for offline/blocked
environments) for both sidebar and content area. Heading weights tightened
(600 for h2/h3) to match Upwind's cleaner look. Applied via the same custom
CSS block.

## Files Touched

- `src/dashboard/app.py` — CSS block, all 6 `render_*` functions (chart
  calls + badge/pill markup)
- `.streamlit/config.toml` — new file, base theme + primary color

## Testing Plan

Run `streamlit run src/dashboard/app.py` locally and manually verify each
of the 6 pages in a browser: sidebar dark styling + active-nav highlight,
metric cards, severity badges/pills render with correct colors, all 4
charts render with the new palette and no console/runtime errors, existing
functionality (filters, expanders, buttons) still works unchanged.

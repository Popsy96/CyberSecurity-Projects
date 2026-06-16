"""
streamlit_app.py — AU CTI Dashboard v2
=======================================
CYB815 Cybersecurity Capstone — Group 14
AAHE · Australasian Academy of Higher Education

Run:
    pip install streamlit plotly pandas
    cd C:\\CyberLabs\\Group14-CTI-Project
    streamlit run dashboard/streamlit_app.py

Changes from v1:
  - Date filter with Apply button (no auto-fire)
  - Project Period preset (13 Apr 2026 → now)
  - Risk Matrix (ISO 27005) with dynamic bubble sizing
  - Risk tab redesigned — no IOC redundancy
  - Threat Intel Feed: 7 filters + Apply + CSV export
  - IR tab: inline expander per playbook (no giant panel)
  - MITRE weighted by cumulative CVSS score
  - Attack Categories above map on Overview
  - Brief requirements in header as pills
  - All charts use consistent dark theme
"""

import json, os
from datetime import datetime, date, timedelta

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ── PAGE CONFIG ──────────────────────────────────────────────
st.set_page_config(
    page_title="AU CTI Dashboard — Group 14",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── GLOBAL THEME & CSS ───────────────────────────────────────
st.markdown("""
<style>
  /* Base */
  .stApp { background:#060b18; color:#cde0ff; }
  [data-testid="stSidebar"] { background:#0a1020; border-right:1px solid #1a2d5a; }

  /* Metrics */
  [data-testid="stMetric"] {
    background:#0b1225; border:1px solid #1a2d5a;
    border-radius:10px; padding:16px;
  }
  [data-testid="stMetricLabel"]  { color:#3a5878 !important; font-size:10px !important;
    text-transform:uppercase; letter-spacing:1px; }
  [data-testid="stMetricValue"]  { color:#fff !important; font-size:26px !important; font-weight:800 !important; }
  [data-testid="stMetricDelta"]  { color:#00e5a0 !important; font-size:10px !important; }

  /* Tabs */
  div[data-testid="stTabs"] button { color:#7a9cc8 !important; font-weight:500; }
  div[data-testid="stTabs"] button[aria-selected="true"] {
    color:#fff !important; border-bottom:2px solid #2979ff !important; font-weight:700;
  }

  /* Table */
  .stDataFrame { border:1px solid #1a2d5a; border-radius:8px; }
  h1,h2,h3 { color:#cde0ff !important; }
  hr { border-color:#1a2d5a; }

  /* Pills */
  .pill {
    display:inline-block; font-size:10px; padding:2px 9px;
    border-radius:20px; font-weight:600; margin-right:4px; border:1px solid;
  }
  .pill-red    { color:#ff7a90; background:rgba(255,61,90,.1);  border-color:rgba(255,61,90,.3); }
  .pill-blue   { color:#6ba3ff; background:rgba(41,121,255,.1); border-color:rgba(41,121,255,.3); }
  .pill-orange { color:#ffb74d; background:rgba(255,152,0,.1);  border-color:rgba(255,152,0,.3); }
  .pill-green  { color:#00e5a0; background:rgba(0,229,160,.1);  border-color:rgba(0,229,160,.3); }
  .pill-purple { color:#b388ff; background:rgba(156,107,255,.1);border-color:rgba(156,107,255,.3); }

  /* Brief pills */
  .brief-pill {
    display:inline-flex; align-items:center; gap:5px;
    font-size:10px; padding:3px 10px; border-radius:20px;
    font-weight:600; border:1px solid; margin-right:5px;
  }

  /* IR phase card */
  .phase-card {
    background:#0b1225; border:1px solid #1a2d5a; border-radius:8px;
    padding:12px 14px; margin-bottom:8px;
  }
  .phase-title {
    color:#2979ff; font-weight:700; font-size:11px;
    text-transform:uppercase; letter-spacing:1px; margin-bottom:7px;
  }
  .phase-item { color:#7a9cc8; font-size:11px; padding:2px 0; }
  .phase-item::before { content:"› "; color:#2979ff; }

  /* Info card */
  .info-card {
    background:#0b1225; border:1px solid #1a2d5a; border-radius:8px; padding:14px;
  }
  .info-card-title { color:#3a5878; font-size:9px; text-transform:uppercase; letter-spacing:1.5px; margin-bottom:8px; }
  .info-card-item  { color:#7a9cc8; font-size:11px; padding:3px 0; border-bottom:1px solid #0f1a35; }
  .info-card-item::before { content:"› "; color:#2979ff; }

  /* Risk register row */
  .risk-row {
    display:flex; align-items:center; gap:8px; padding:5px 0;
    border-bottom:1px solid #0a1628; font-size:11px;
  }

  /* Severity colours */
  .cr { color:#ff3d5a; font-weight:800; }
  .co { color:#ff9800; font-weight:800; }
  .cy { color:#ffd740; font-weight:800; }
  .cg { color:#00e5a0; font-weight:800; }
  .cc { color:#00d4ff; font-weight:800; }
</style>
""", unsafe_allow_html=True)

# ── CONSTANTS ────────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    plot_bgcolor='#0b1225', paper_bgcolor='#060b18',
    font=dict(color='#7a9cc8', size=11),
    margin=dict(l=10, r=10, t=30, b=10),
)
PAL      = ['#2979ff','#ff3d5a','#ff9800','#ffd740','#00e5a0','#9c6bff','#00d4ff','#fd7e14']
SEV_COL  = {'Critical':'#ff3d5a','High':'#ff9800','Medium':'#ffd740','Low':'#00e5a0'}
NIST_COL = {'Identify':'#00e5a0','Protect':'#6ba3ff','Detect':'#ff9800','Respond':'#ff3d5a','Recover':'#9c6bff'}
PROJECT_START = date(2026, 4, 13)

# ── LOAD DATA ────────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_data():
    path = os.path.join(os.path.dirname(__file__), '..', 'data.json')
    if not os.path.exists(path):
        return None, None, None
    with open(path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    threats = raw.get('threats', [])
    df = pd.DataFrame(threats) if threats else pd.DataFrame()
    if 'cvss_score' in df.columns:
        df['cvss_score'] = pd.to_numeric(df['cvss_score'], errors='coerce').fillna(0)
    if 'timestamp_utc' in df.columns:
        df['_dt'] = pd.to_datetime(df['timestamp_utc'], errors='coerce', utc=True)
    return raw.get('stats', {}), df, raw.get('ir_data', {})

stats, df, ir_data = load_data()
if stats is None or df is None or df.empty:
    st.error("⚠️ data.json not found. Run `python main.py` first, then refresh.")
    st.stop()

# ── HEADER ───────────────────────────────────────────────────
cat_counts = stats.get('category_counts', {})
phishing_n   = cat_counts.get('Phishing', 0)
malware_n    = cat_counts.get('Malware Distribution', 0)
suspicious_n = (cat_counts.get('Brute Force', 0) +
                cat_counts.get('SSH Brute Force', 0) +
                cat_counts.get('Suspicious Activity', 0))

st.markdown(f"""
<div style="background:linear-gradient(135deg,#071035,#0d1e4a,#071035);
  border:1px solid #1a2d5a;border-radius:10px;padding:14px 20px;margin-bottom:16px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:10px">
    <div>
      <span style="color:#6ba3ff;font-weight:700;font-size:13px;margin-right:10px">AAHE</span>
      <span style="color:#fff;font-weight:700;font-size:18px">Australia Cyber Threat Intelligence Dashboard</span>
      <span style="color:#3a5878;font-size:12px;margin-left:10px">CYB815 Cybersecurity Capstone &nbsp;·&nbsp;
        <span style="color:#ffd740;font-weight:700">Group 14</span></span>
      <br/>
      <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:5px;align-items:center">
        <span class="pill pill-red">MITRE ATT&amp;CK</span>
        <span class="pill pill-blue">NIST CSF</span>
        <span class="pill pill-orange">CVSS v3.1</span>
        <span class="pill pill-green">ASD Essential 8</span>
        <span class="pill pill-purple">ISO 27001</span>
        &nbsp;
        <span class="brief-pill" style="color:#ff9800;border-color:rgba(255,152,0,.3);background:rgba(255,152,0,.07)">
          ✓ Malware: <b>{malware_n:,}</b></span>
        <span class="brief-pill" style="color:#ff3d5a;border-color:rgba(255,61,90,.3);background:rgba(255,61,90,.07)">
          ✓ Phishing: <b>{phishing_n:,}</b></span>
        <span class="brief-pill" style="color:#ffd740;border-color:rgba(255,215,64,.3);background:rgba(255,215,64,.07)">
          ✓ Suspicious: <b>{suspicious_n:,}</b></span>
      </div>
    </div>
    <div style="text-align:right;color:#3a5878;font-size:11px">
      Last updated<br/>
      <span style="color:#00d4ff;font-size:12px">{stats.get('last_updated','—')}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── SIDEBAR ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="font-size:10px;color:#3a5878;text-transform:uppercase;
      letter-spacing:1.5px;font-weight:700;padding:4px 0 10px">
      AU CTI · Group 14
    </div>""", unsafe_allow_html=True)

    # ── Date Filter ──────────────────────────────────────────
    st.markdown("**📅 Date Range**")
    st.caption("Select preset or custom, then click Apply")

    preset = st.radio(
        "Preset",
        ["All Time", "Last 7 Days", "Last 30 Days", "Project Period (Apr 13→)", "Custom Range"],
        index=0, label_visibility="collapsed",
    )

    from_date = to_date = None
    if preset == "Custom Range":
        col_fd, col_td = st.columns(2)
        from_date = col_fd.date_input("From", value=PROJECT_START, key="from_d")
        to_date   = col_td.date_input("To",   value=date.today(),  key="to_d")

    apply_date = st.button("▶ Apply Date Filter", use_container_width=True, type="primary")
    if st.button("✕ Clear", use_container_width=True):
        st.session_state['date_applied'] = 'All Time'
        st.rerun()

    # Store applied preset in session state — only updates on Apply
    if apply_date:
        st.session_state['date_applied'] = preset
        if preset == "Custom Range":
            st.session_state['from_date'] = from_date
            st.session_state['to_date']   = to_date

    active_preset = st.session_state.get('date_applied', 'All Time')
    st.caption(f"Active: **{active_preset}**")

    st.divider()

    # ── IOC Filters ─────────────────────────────────────────
    st.markdown("**🔍 Threat Intel Filters**")
    st.caption("Used in Threat Intel Feed tab")

    sev_opts  = ['All'] + sorted(df['severity'].dropna().unique().tolist())  if 'severity'  in df.columns else ['All']
    cat_opts  = ['All'] + sorted(df['category'].dropna().unique().tolist())  if 'category'  in df.columns else ['All']
    city_opts = ['All'] + sorted([c for c in df['city'].dropna().unique().tolist()
                                   if c not in ('AU','Unknown','')]) if 'city' in df.columns else ['All']
    type_opts = ['All'] + sorted(df['type'].dropna().unique().tolist())      if 'type'      in df.columns else ['All']
    nist_opts = ['All'] + ['Identify','Protect','Detect','Respond','Recover']
    src_opts  = ['All'] + sorted(df['source'].dropna().unique().tolist())    if 'source'    in df.columns else ['All']
    mal_opts  = ['All'] + sorted([m for m in df['malware_type'].dropna().unique().tolist()
                                   if m not in ('Unknown','')]) if 'malware_type' in df.columns else ['All']

    sel_sev   = st.selectbox("Severity",      sev_opts,  key="sev_f")
    sel_cat   = st.selectbox("Category",      cat_opts,  key="cat_f")
    sel_city  = st.selectbox("City",          city_opts, key="city_f")
    sel_type  = st.selectbox("IOC Type",      type_opts, key="type_f")
    sel_nist  = st.selectbox("NIST Function", nist_opts, key="nist_f")
    sel_src   = st.selectbox("Source Feed",   src_opts,  key="src_f")
    sel_mal   = st.selectbox("Malware Type",  mal_opts,  key="mal_f")

    apply_ioc = st.button("▶ Apply Filters", use_container_width=True, type="primary")
    if st.button("✕ Reset Filters", use_container_width=True):
        for k in ['sev_f','cat_f','city_f','type_f','nist_f','src_f','mal_f']:
            st.session_state[k] = 'All'
        st.rerun()

    st.divider()

    # ── Feed Status ──────────────────────────────────────────
    st.markdown("**📡 Feed Status**")
    sc = stats.get('source_counts', {})
    for feed, col in [('AlienVault OTX','#2979ff'),('AbuseIPDB','#ff3d5a'),
                      ('URLhaus','#ff9800'),('Feodo Tracker','#9c6bff')]:
        c  = sc.get(feed, 0)
        on = c > 0
        dot = "🟢" if on else "⚫"
        st.markdown(f"{dot} **{feed}** — `{c:,}`")


# ── APPLY DATE FILTER ─────────────────────────────────────────
def apply_date_filter(data: pd.DataFrame) -> pd.DataFrame:
    d = data.copy()
    if '_dt' not in d.columns:
        return d
    active = st.session_state.get('date_applied', 'All Time')
    today_ts = pd.Timestamp.now(tz='UTC').normalize()
    project_start_ts = pd.Timestamp(PROJECT_START, tz='UTC')

    if active == "Last 7 Days":
        d = d[d['_dt'] >= today_ts - pd.Timedelta(days=6)]
    elif active == "Last 30 Days":
        d = d[d['_dt'] >= today_ts - pd.Timedelta(days=29)]
    elif active == "Project Period (Apr 13→)":
        d = d[d['_dt'] >= project_start_ts]
    elif active == "Custom Range":
        fd = st.session_state.get('from_date')
        td = st.session_state.get('to_date')
        if fd: d = d[d['_dt'] >= pd.Timestamp(fd, tz='UTC')]
        if td: d = d[d['_dt'] <= pd.Timestamp(td, tz='UTC') + pd.Timedelta(days=1)]
    return d

# ── APPLY IOC FILTERS ─────────────────────────────────────────
def apply_ioc_filters(data: pd.DataFrame) -> pd.DataFrame:
    d = data.copy()
    if sel_sev  != 'All' and 'severity'     in d.columns: d = d[d['severity']     == sel_sev]
    if sel_cat  != 'All' and 'category'     in d.columns: d = d[d['category']     == sel_cat]
    if sel_city != 'All' and 'city'         in d.columns: d = d[d['city']         == sel_city]
    if sel_type != 'All' and 'type'         in d.columns: d = d[d['type']         == sel_type]
    if sel_nist != 'All' and 'nist_function'in d.columns: d = d[d['nist_function']== sel_nist]
    if sel_src  != 'All' and 'source'       in d.columns: d = d[d['source']       == sel_src]
    if sel_mal  != 'All' and 'malware_type' in d.columns: d = d[d['malware_type'] == sel_mal]
    return d

# Date-filtered base (used everywhere)
date_filtered = apply_date_filter(df)
# IOC-filtered (used in Threat Feed tab only)
ioc_filtered  = apply_ioc_filters(date_filtered) if apply_ioc else date_filtered

active_n  = len(date_filtered)
total_n   = len(df)
st.sidebar.info(f"**{active_n:,}** of **{total_n:,}** threats (date filter)")

# ── TABS ──────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠 Overview",
    "🔎 Threat Intel Feed",
    "📊 Analytics",
    "⚠️ Risk & CVSS",
    "🛡 IR & Mitigation",
])

# ══════════════════════════════════════════════════════════════
#  TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════
with tab1:
    filtered = date_filtered

    # KPI Row
    c1,c2,c3,c4,c5,c6 = st.columns(6)
    c1.metric("Total IOCs",          f"{len(filtered):,}", f"of {total_n:,} total")
    c2.metric("Critical",            f"{len(filtered[filtered['severity']=='Critical']):,}" if 'severity' in filtered.columns else "—", "CVSS ≥ 9.0")
    c3.metric("High",                f"{len(filtered[filtered['severity']=='High']):,}"     if 'severity' in filtered.columns else "—", "CVSS ≥ 7.0")
    c4.metric("Avg CVSS",            f"{filtered['cvss_score'].mean():.1f}" if 'cvss_score' in filtered.columns and len(filtered) else "—", "/ 10.0")
    c5.metric("Phishing",            f"{len(filtered[filtered['category']=='Phishing']):,}" if 'category' in filtered.columns else "—", "campaigns")
    c6.metric("Suspicious Activity", f"{len(filtered[filtered['category'].isin(['Brute Force','SSH Brute Force','Suspicious Activity'])]):,}" if 'category' in filtered.columns else "—", "network threats")

    st.divider()

    # Timeline — from 13 Apr 2026
    st.subheader("IOC Detections Over Time")
    st.caption("From 13 April 2026 — CYB815 project start date")
    tl = stats.get('timeline', [])
    if tl:
        tl_df = pd.DataFrame(tl)
        tl_df = tl_df[tl_df['date'] >= '2026-04-13']
        if len(tl_df):
            fig = px.area(tl_df, x='date', y='count',
                          color_discrete_sequence=['#2979ff'], template='plotly_dark',
                          labels={'date': 'Date', 'count': 'IOC Count'})
            fig.update_traces(line_width=2, fillcolor='rgba(41,121,255,0.1)')
            fig.update_layout(**PLOTLY_LAYOUT, height=180)
            fig.update_xaxes(showgrid=False)
            fig.update_yaxes(gridcolor='#0f1a35')
            st.plotly_chart(fig, use_container_width=True, key="ov_timeline")

    st.divider()

    # Attack Categories — ABOVE the map
    st.subheader("Attack Categories")
    if 'category' in filtered.columns and len(filtered):
        cats = (filtered[~filtered['category'].isin(['Suspicious Activity','Unknown',''])]
                ['category'].value_counts().head(8).reset_index())
        cats.columns = ['Category', 'Count']
        cats = cats.sort_values('Count')
        fig = px.bar(cats, x='Count', y='Category', orientation='h',
                     color='Count', color_continuous_scale='Blues', template='plotly_dark')
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                          coloraxis_showscale=False, height=250)
        fig.update_xaxes(showgrid=False)
        st.plotly_chart(fig, use_container_width=True, key="ov_cats")

    st.divider()

    # Map + Severity side by side
    col_map, col_right = st.columns([2, 1])

    with col_map:
        st.subheader("Australia Threat Map")
        if len(filtered) and 'lat' in filtered.columns and 'lng' in filtered.columns:
            map_df = filtered.dropna(subset=['lat', 'lng'])
            if len(map_df):
                fig = px.scatter_mapbox(
                    map_df, lat='lat', lon='lng',
                    color='severity', color_discrete_map=SEV_COL,
                    size='cvss_score' if 'cvss_score' in map_df.columns else None,
                    size_max=12,
                    hover_data=['ioc', 'category', 'mitre_technique', 'source', 'city'],
                    zoom=3.8, center={'lat': -27.0, 'lon': 133.5},
                    mapbox_style='carto-darkmatter', template='plotly_dark',
                )
                fig.update_layout(
                    margin={'r': 0, 't': 0, 'l': 0, 'b': 0},
                    height=340, paper_bgcolor='#060b18',
                    legend=dict(orientation='h', yanchor='bottom', y=1.01, x=0,
                                bgcolor='rgba(6,11,24,.8)', font=dict(size=10)),
                    mapbox=dict(
                        center=dict(lat=-27.0, lon=133.5),
                        zoom=3.8,
                        # Lock bounds to Australia — users cannot pan outside
                        bounds=dict(
                            west=112.0, east=154.5,
                            south=-44.0, north=-9.5,
                        ),
                    ),
                )
                st.plotly_chart(fig, use_container_width=True, key="ov_map")
        else:
            st.info("Map requires lat/lng fields in data.json")

    with col_right:
        st.subheader("Severity Breakdown")
        if 'severity' in filtered.columns and len(filtered):
            sev = filtered['severity'].value_counts()
            sev_order = ['Critical', 'High', 'Medium', 'Low']
            sev = sev.reindex([s for s in sev_order if s in sev.index])
            fig = go.Figure(go.Bar(
                x=list(sev.index), y=list(sev.values),
                marker_color=[SEV_COL.get(s, '#7a9cc8') for s in sev.index],
                text=[f"{v:,}" for v in sev.values], textposition='outside',
                textfont=dict(color='#cde0ff', size=11),
            ))
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, height=180,
                              yaxis=dict(showgrid=False), xaxis=dict(showgrid=False))
            st.plotly_chart(fig, use_container_width=True, key="ov_sev")

        st.subheader("Recent Collection Runs")
        runs = stats.get('fetch_runs', [])
        if runs:
            for r in runs[:4]:
                st.markdown(
                    f"**{r.get('run_time_au', '—')}**  \n"
                    f"🔴 `{r.get('critical',0):,}` &nbsp; "
                    f"🟠 `{r.get('high',0):,}` &nbsp; "
                    f"✅ `+{r.get('new_threats',0):,}` new"
                )
        else:
            st.caption("No run history yet.")


# ══════════════════════════════════════════════════════════════
#  TAB 2 — THREAT INTEL FEED
# ══════════════════════════════════════════════════════════════
with tab2:
    filtered_feed = ioc_filtered

    # Active filter summary
    active_filters = [f for f, v in [
        ('Severity', sel_sev), ('Category', sel_cat), ('City', sel_city),
        ('Type', sel_type), ('NIST', sel_nist), ('Source', sel_src), ('Malware', sel_mal)
    ] if v != 'All']

    if active_filters:
        st.info(f"🔍 Active filters: {' · '.join(active_filters)} — "
                f"**{len(filtered_feed):,}** of **{len(date_filtered):,}** threats")
    else:
        st.caption(f"Showing all **{len(filtered_feed):,}** threats — use sidebar filters to narrow down")

    if len(filtered_feed):
        show_cols = ['severity', 'cvss_score', 'type', 'ioc', 'category',
                     'mitre_technique', 'nist_function', 'asd_e8',
                     'industry', 'source', 'city', 'timestamp_au']
        cols_exist = [c for c in show_cols if c in filtered_feed.columns]
        display_df = (filtered_feed[cols_exist]
                      .sort_values('cvss_score', ascending=False)
                      .rename(columns={
                          'cvss_score': 'CVSS', 'mitre_technique': 'MITRE',
                          'nist_function': 'NIST', 'asd_e8': 'ASD E8',
                          'timestamp_au': 'Timestamp', 'severity': 'Severity',
                          'type': 'Type', 'ioc': 'Indicator', 'category': 'Category',
                          'industry': 'Industry', 'source': 'Source', 'city': 'City',
                      }))

        st.dataframe(display_df, use_container_width=True, height=520,
                     column_config={
                         'CVSS':     st.column_config.NumberColumn(format="%.1f"),
                         'Indicator':st.column_config.TextColumn(width='medium'),
                     })

        csv = filtered_feed[cols_exist].to_csv(index=False)
        st.download_button(
            label=f"⬇ Export CSV ({len(filtered_feed):,} threats)",
            data=csv,
            file_name=f"au-cti-group14-{datetime.now().strftime('%Y-%m-%d')}.csv",
            mime="text/csv",
        )
    else:
        st.warning("No threats match the current filters. Try adjusting the sidebar filters.")


# ══════════════════════════════════════════════════════════════
#  TAB 3 — ANALYTICS
# ══════════════════════════════════════════════════════════════
with tab3:
    filtered = date_filtered

    # NIST CSF KPI row
    nd = stats.get('nist_dist', {})
    n1, n2, n3, n4, n5 = st.columns(5)
    n1.metric("IDENTIFY", f"{nd.get('Identify',0):,}",  "assets & risk")
    n2.metric("PROTECT",  f"{nd.get('Protect',0):,}",   "safeguards")
    n3.metric("DETECT",   f"{nd.get('Detect',0):,}",    "find events")
    n4.metric("RESPOND",  f"{nd.get('Respond',0):,}",   "take action")
    n5.metric("RECOVER",  f"{nd.get('Recover',0):,}",   "restore ops")

    st.divider()

    # Row 1: Cities + Industries
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Threats by Australian City")
        if 'city' in filtered.columns and len(filtered):
            city_df = filtered[~filtered['city'].isin(['AU', 'Unknown', ''])]
            if len(city_df):
                cc = city_df['city'].value_counts().head(8).reset_index()
                cc.columns = ['City', 'Count']
                fig = px.bar(cc.sort_values('Count'), x='Count', y='City',
                             orientation='h', color='Count',
                             color_continuous_scale='Blues', template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                                  coloraxis_showscale=False, height=270)
                st.plotly_chart(fig, use_container_width=True, key="an_cities")

    with col2:
        st.subheader("Affected Industries")
        if 'industry' in filtered.columns and len(filtered):
            ind_df = filtered[~filtered['industry'].isin(['Other', 'Unknown', ''])]
            if len(ind_df):
                ic = ind_df['industry'].value_counts().head(8).reset_index()
                ic.columns = ['Industry', 'Count']
                fig = px.bar(ic.sort_values('Count'), x='Count', y='Industry',
                             orientation='h', color='Count',
                             color_continuous_scale='Oranges', template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                                  coloraxis_showscale=False, height=270)
                st.plotly_chart(fig, use_container_width=True, key="an_ind")

    # Row 2: Malware + ASD E8 + State
    col3, col4, col5 = st.columns(3)

    with col3:
        st.subheader("Malware Classification")
        if 'malware_type' in filtered.columns and len(filtered):
            mt = filtered[~filtered['malware_type'].isin(['Unknown', ''])]['malware_type'].value_counts()
            if len(mt):
                fig = px.pie(values=mt.values, names=mt.index, hole=0.45,
                             color_discrete_sequence=PAL, template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, height=240)
                fig.update_traces(textposition='inside', textinfo='percent+label',
                                  textfont_size=10)
                st.plotly_chart(fig, use_container_width=True, key="an_maltype")

    with col4:
        st.subheader("ASD Essential Eight")
        if 'asd_e8' in filtered.columns and len(filtered):
            asd = (filtered[~filtered['asd_e8'].isin(['Unknown', ''])]
                   ['asd_e8'].value_counts().head(6).reset_index())
            asd.columns = ['Control', 'Count']
            fig = px.bar(asd.sort_values('Count'), x='Count', y='Control',
                         orientation='h', color='Count',
                         color_continuous_scale='Greens', template='plotly_dark')
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                              coloraxis_showscale=False, height=240)
            st.plotly_chart(fig, use_container_width=True, key="an_asd")

    with col5:
        st.subheader("AU State Distribution")
        CITY_STATE = {
            'Sydney': 'NSW', 'Newcastle': 'NSW', 'Melbourne': 'VIC',
            'Brisbane': 'QLD', 'Gold Coast': 'QLD', 'Perth': 'WA',
            'Adelaide': 'SA', 'Hobart': 'TAS', 'Canberra': 'ACT', 'Darwin': 'NT',
        }
        if 'city' in filtered.columns and len(filtered):
            s_df = filtered.copy()
            s_df['state'] = s_df['city'].map(CITY_STATE)
            sc_df = s_df.dropna(subset=['state'])['state'].value_counts().reset_index()
            sc_df.columns = ['State', 'Count']
            fig = px.bar(sc_df.sort_values('Count', ascending=False),
                         x='State', y='Count', color='Count',
                         color_continuous_scale='Blues', template='plotly_dark')
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                              coloraxis_showscale=False, height=240)
            st.plotly_chart(fig, use_container_width=True, key="an_states")

    # Row 3: IOC Types + Malware Families
    col6, col7 = st.columns(2)

    with col6:
        st.subheader("IOC Type Breakdown")
        if 'type' in filtered.columns and len(filtered):
            it = filtered[~filtered['type'].isin(['Unknown', ''])]['type'].value_counts()
            if len(it):
                fig = px.pie(values=it.values, names=it.index, hole=0.45,
                             color_discrete_sequence=PAL, template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, height=240)
                fig.update_traces(textposition='inside', textinfo='percent+label',
                                  textfont_size=10)
                st.plotly_chart(fig, use_container_width=True, key="an_ioctype")

    with col7:
        st.subheader("Top Malware Families")
        if 'malware_family' in filtered.columns and len(filtered):
            fam = (filtered[
                (filtered['malware_family'].notna()) &
                (~filtered['malware_family'].isin(['', 'Unknown'])) &
                (filtered['malware_family'].str.len() < 30)
            ]['malware_family'].value_counts().head(9))
            if len(fam):
                fam_df = fam.reset_index()
                fam_df.columns = ['Family', 'Count']
                fig = px.bar(fam_df.sort_values('Count'), x='Count', y='Family',
                             orientation='h', color='Count',
                             color_continuous_scale='Reds', template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                                  coloraxis_showscale=False, height=260)
                st.plotly_chart(fig, use_container_width=True, key="an_malfam")


# ══════════════════════════════════════════════════════════════
#  TAB 4 — RISK & CVSS
# ══════════════════════════════════════════════════════════════
with tab4:
    filtered = date_filtered

    avg_cvss  = filtered['cvss_score'].mean()         if 'cvss_score' in filtered.columns and len(filtered) else 0
    max_cvss  = filtered['cvss_score'].max()           if 'cvss_score' in filtered.columns and len(filtered) else 0
    crit_n    = len(filtered[filtered['cvss_score'] >= 9]) if 'cvss_score' in filtered.columns and len(filtered) else 0
    crithigh  = len(filtered[filtered['severity'].isin(['Critical','High'])]) if 'severity' in filtered.columns and len(filtered) else 0

    # KPI Row
    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Average CVSS",    f"{avg_cvss:.1f}", "/ 10.0 risk score")
    r2.metric("Critical (9+)",   f"{crit_n:,}",    "immediate action")
    r3.metric("Highest CVSS",    f"{max_cvss:.1f}", "maximum observed")
    r4.metric("Critical + High", f"{crithigh:,}",  "high priority threats")

    st.divider()

    # Row 1: Risk Assessment Matrix (hero) + Risk Register
    st.subheader("Risk Assessment Matrix")
    st.caption("ISO/IEC 27005:2022 · Likelihood × Impact · Bubble size = live threat volume")

    # Build risk matrix as scatter plot
    cat_counts_live = filtered['category'].value_counts().to_dict() if 'category' in filtered.columns else {}
    max_count = max(cat_counts_live.values(), default=1)

    RISKS = [
        dict(label='Phishing',      catKey='Phishing',             l=4, i=3, col='#ff9800', r='R1', score=20, rating='Critical'),
        dict(label='C2 Server',     catKey='C2 Server',            l=3, i=4, col='#ff3d5a', r='R2', score=20, rating='Critical'),
        dict(label='Malware',       catKey='Malware Distribution', l=4, i=2, col='#ff9800', r='R3', score=15, rating='High'),
        dict(label='Brute Force',   catKey='Brute Force',          l=4, i=4, col='#ff9800', r='R4', score=16, rating='High'),
        dict(label='Ransomware',    catKey='Ransomware',           l=2, i=4, col='#ff3d5a', r='R5', score=15, rating='High'),
        dict(label='DDoS',          catKey='DDoS Attack',          l=2, i=3, col='#ffd740', r='R7', score=12, rating='High'),
        dict(label='SQL Inject',    catKey='SQL Injection',        l=2, i=3, col='#ffd740', r='R6', score=12, rating='High'),
        dict(label='Port Scan',     catKey='Port Scan',            l=4, i=1, col='#00e5a0', r='R8', score=10, rating='Medium'),
    ]

    matrix_col, reg_col = st.columns([3, 1])

    with matrix_col:
        # Build scatter on a 5x5 grid
        risk_df = pd.DataFrame([{
            'Threat':     r['label'],
            'Likelihood': r['l'],
            'Impact':     r['i'],
            'Count':      cat_counts_live.get(r['catKey'], 1),
            'Color':      r['col'],
            'Rating':     r['rating'],
            'Score':      r['score'],
        } for r in RISKS])

        fig = go.Figure()

        # Draw coloured background cells
        CELL_COLORS = [
            # (l_min, l_max, i_min, i_max, colour)
            (0.5,5.5,0.5,2.5,'rgba(0,229,160,0.25)'),   # Low zone
            (0.5,3.5,2.5,5.5,'rgba(255,215,64,0.2)'),   # Medium zone
            (2.5,4.5,3.5,5.5,'rgba(255,152,0,0.2)'),    # High zone
            (3.5,5.5,3.5,5.5,'rgba(255,61,90,0.2)'),    # Critical zone
        ]
        for x0, x1, y0, y1, col in CELL_COLORS:
            fig.add_shape(type='rect', x0=x0, x1=x1, y0=y0, y1=y1,
                          fillcolor=col, line=dict(width=0), layer='below')

        # Grid lines
        for i in range(1, 6):
            fig.add_shape(type='line', x0=i+0.5, x1=i+0.5, y0=0.5, y1=5.5,
                          line=dict(color='#1a2d5a', width=1))
            fig.add_shape(type='line', x0=0.5, x1=5.5, y0=i+0.5, y1=i+0.5,
                          line=dict(color='#1a2d5a', width=1))

        # Threat bubbles — size by live count
        fig.add_trace(go.Scatter(
            x=risk_df['Likelihood'], y=risk_df['Impact'],
            mode='markers+text',
            marker=dict(
                size=[10 + (c / max_count) * 30 for c in risk_df['Count']],
                color=risk_df['Color'],
                opacity=0.75,
                line=dict(color=risk_df['Color'], width=2),
            ),
            text=risk_df['Threat'],
            textposition='top center',
            textfont=dict(size=9, color='#cde0ff'),
            customdata=list(zip(risk_df['Rating'], risk_df['Score'], risk_df['Count'])),
            hovertemplate=(
                '<b>%{text}</b><br>'
                'Likelihood: %{x} · Impact: %{y}<br>'
                'Rating: %{customdata[0]} · Score: %{customdata[1]}<br>'
                'Live count: %{customdata[2]:,}<extra></extra>'
            ),
        ))

        likelihood_labels = ['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost\nCertain']
        impact_labels     = ['', 'Negligible', 'Minor', 'Moderate', 'Major', 'Catastrophic']

        fig.update_layout(
            **PLOTLY_LAYOUT, height=340, showlegend=False,
            xaxis=dict(range=[0.5,5.5], tickvals=list(range(1,6)),
                       ticktext=likelihood_labels[1:],
                       title=dict(text='LIKELIHOOD →', font=dict(color='#00e5a0', size=11)),
                       showgrid=False),
            yaxis=dict(range=[0.5,5.5], tickvals=list(range(1,6)),
                       ticktext=impact_labels[1:],
                       title=dict(text='IMPACT →', font=dict(color='#00e5a0', size=11)),
                       showgrid=False),
        )
        st.plotly_chart(fig, use_container_width=True, key="risk_matrix")

    with reg_col:
        st.markdown("**Risk Register — ISO 27005**")
        rating_col = {'Critical': '#ff3d5a', 'High': '#ff9800', 'Medium': '#ffd740', 'Low': '#00e5a0'}
        for r in RISKS:
            col = rating_col.get(r['rating'], '#7a9cc8')
            count = cat_counts_live.get(r['catKey'], 0)
            st.markdown(
                f"<div class='risk-row'>"
                f"<span style='color:#3a5878;font-size:9px;min-width:22px'>{r['r']}</span>"
                f"<span style='flex:1;font-size:11px;color:#cde0ff'>{r['label']}</span>"
                f"<span style='font-weight:800;color:{col};min-width:20px;text-align:center'>{r['score']}</span>"
                f"<span style='font-size:9px;color:{col};min-width:50px;text-align:right'>{r['rating']}</span>"
                f"</div>",
                unsafe_allow_html=True
            )
        st.markdown("""
        <div style='margin-top:10px;font-size:9px;color:#3a5878'>
        <span style='color:#ff3d5a'>■</span> Critical 20-25 &nbsp;
        <span style='color:#ff9800'>■</span> High 12-19<br>
        <span style='color:#ffd740'>■</span> Medium 6-11 &nbsp;
        <span style='color:#00e5a0'>■</span> Low 1-5
        </div>""", unsafe_allow_html=True)

    st.divider()

    # Row 2: CVSS Distribution + MITRE weighted
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("CVSS Score Distribution")
        if 'cvss_score' in filtered.columns and len(filtered):
            bins   = ['Critical 9-10', 'High 7-8.9', 'Medium 4-6.9', 'Low 0-3.9']
            counts = [
                len(filtered[filtered['cvss_score'] >= 9]),
                len(filtered[(filtered['cvss_score'] >= 7) & (filtered['cvss_score'] < 9)]),
                len(filtered[(filtered['cvss_score'] >= 4) & (filtered['cvss_score'] < 7)]),
                len(filtered[filtered['cvss_score'] < 4]),
            ]
            fig = px.bar(x=bins, y=counts, color=bins,
                         color_discrete_map={
                             'Critical 9-10': '#ff3d5a', 'High 7-8.9': '#ff9800',
                             'Medium 4-6.9': '#ffd740', 'Low 0-3.9': '#00e5a0',
                         }, template='plotly_dark', labels={'x': '', 'y': 'Threats'})
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, height=260)
            for i, (b, c) in enumerate(zip(bins, counts)):
                pct = f"{c/len(filtered)*100:.0f}%"
                fig.add_annotation(x=b, y=c, text=f"{c:,} ({pct})",
                                   showarrow=False, yshift=8,
                                   font=dict(size=10, color='#cde0ff'))
            st.plotly_chart(fig, use_container_width=True, key="risk_cvss_dist")

    with col_b:
        st.subheader("MITRE ATT&CK — Weighted by CVSS")
        st.caption("Bar length = cumulative CVSS score, not just count")
        if 'mitre_technique' in filtered.columns and 'cvss_score' in filtered.columns and len(filtered):
            mitre = (filtered.groupby(
                ['mitre_technique', 'mitre_name'] if 'mitre_name' in filtered.columns
                else ['mitre_technique']
            ).agg(
                Count=('cvss_score', 'count'),
                CvssTotal=('cvss_score', 'sum')
            ).reset_index().sort_values('CvssTotal', ascending=True).tail(8))

            if 'mitre_name' in mitre.columns:
                mitre['Label'] = mitre['mitre_technique'] + ' — ' + mitre['mitre_name'].fillna('')
            else:
                mitre['Label'] = mitre['mitre_technique']

            fig = px.bar(mitre, x='CvssTotal', y='Label', orientation='h',
                         color='CvssTotal', color_continuous_scale='Reds',
                         template='plotly_dark',
                         labels={'CvssTotal': 'Total CVSS Weight', 'Label': ''},
                         hover_data=['Count'])
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                              coloraxis_showscale=False, height=260)
            st.plotly_chart(fig, use_container_width=True, key="risk_mitre")

    st.divider()

    # CVSS Methodology
    st.subheader("CVSS Calculation Methodology")
    mc1, mc2, mc3, mc4 = st.columns(4)
    with mc1:
        st.markdown("""**Step 1 — Base Score**
- Critical = 9.0
- High = 7.5
- Medium = 5.0
- Low = 2.5""")
    with mc2:
        st.markdown("""**Step 2 — Confidence**
- AbuseIPDB 0–100%
- (c÷100)×2−1
- Range: −1.0 to +1.0
- Example: 85% = +0.7""")
    with mc3:
        st.markdown("""**Step 3 — Category Boost**
- C2 / Ransomware = +0.5
- DDoS / SQL = +0.3
- Phishing = +0.1""")
    with mc4:
        st.markdown("""**Frameworks Applied**
- MITRE ATT&CK
- NIST CSF
- ASD Essential 8
- ISO 27001""")


# ══════════════════════════════════════════════════════════════
#  TAB 5 — IR & MITIGATION
# ══════════════════════════════════════════════════════════════
with tab5:

    # Response time info bar
    ir1, ir2, ir3, ir4 = st.columns(4)
    ir1.metric("Critical Response", "1 hour",   "Ransomware · C2 · DDoS")
    ir2.metric("High Response",     "4 hours",  "Phishing · Brute Force · Malware")
    ir3.metric("Medium Response",   "24 hours", "Port Scan · Recon")
    ir4.metric("IR Playbooks",      "8",        "NIST SP 800-61r2 aligned")

    st.divider()

    playbooks = ir_data.get('playbooks', {}) if ir_data else {}
    summary   = ir_data.get('summary',   []) if ir_data else []

    if not summary:
        st.warning("IR data not found. Run `python main.py` first.")
        st.stop()

    # Summary table with colour-coded severity
    st.subheader("Incident Response Playbooks")
    st.caption("Click ▶ on any row to expand the full playbook")

    sum_df = pd.DataFrame(summary)
    if not sum_df.empty:
        disp_cols = [c for c in ['category','severity','mitre','nist','asd_e8','response_time']
                     if c in sum_df.columns]
        st.dataframe(
            sum_df[disp_cols].rename(columns={
                'category': 'Category', 'severity': 'Severity', 'mitre': 'MITRE',
                'nist': 'NIST', 'asd_e8': 'ASD E8', 'response_time': 'Response Time',
            }),
            use_container_width=True, hide_index=True, height=300,
        )

    st.divider()

    # Inline expanders — one per playbook (compact, no giant panel)
    st.subheader("Playbook Details")
    st.caption("Expand any playbook below")

    for pb_name, p in playbooks.items():
        sev   = p.get('severity', '—')
        mitre = p.get('mitre', '—').split('—')[0].strip()
        resp  = p.get('response_time', '—')
        sev_icon = {'Critical':'🔴','High':'🟠','Medium':'🟡','Low':'🟢'}.get(sev, '⚪')

        with st.expander(f"{sev_icon} **{pb_name}** — {sev} · {mitre} · {resp}"):

            # Meta row
            m1, m2, m3, m4, m5 = st.columns(5)
            m1.markdown(f"**Severity**  \n{sev}")
            m2.markdown(f"**MITRE**  \n{p.get('mitre','—')}")
            m3.markdown(f"**NIST**  \n{p.get('nist','—')}")
            m4.markdown(f"**ASD E8**  \n{p.get('asd_e8','—')}")
            m5.markdown(f"**Response**  \n{resp}")

            st.markdown("---")

            # NIST 800-61r2 phases — 3 per row
            st.markdown("**IR Lifecycle — NIST SP 800-61r2**")
            phases = list(p.get('phases', {}).items())
            for row_start in range(0, len(phases), 3):
                cols = st.columns(3)
                for j, (phase, actions) in enumerate(phases[row_start:row_start + 3]):
                    with cols[j]:
                        st.markdown(
                            f"<div class='phase-card'>"
                            f"<div class='phase-title'>{row_start+j+1}. {phase}</div>"
                            + ''.join(f"<div class='phase-item'>{a}</div>"
                                      for a in (actions or [])[:3])
                            + "</div>",
                            unsafe_allow_html=True
                        )

            st.markdown("---")

            # Short + Long + Fixes + AU Contacts
            mit = p.get('mitigation', {})
            mc1, mc2, mc3, mc4 = st.columns(4)

            with mc1:
                st.markdown("**Short-Term Actions**")
                for i, item in enumerate(mit.get('short_term', [])[:4], 1):
                    st.markdown(f"{i}. {item}")

            with mc2:
                st.markdown("**Long-Term Actions**")
                for i, item in enumerate(mit.get('long_term', [])[:4], 1):
                    st.markdown(f"{i}. {item}")

            with mc3:
                st.markdown("**Vulnerability Fixes**")
                for fix in p.get('vulnerability_fixes', [])[:4]:
                    st.markdown(f"+ {fix}")

            with mc4:
                st.markdown("**AU Reporting Contacts**")
                for contact in p.get('au_contacts', [])[:3]:
                    st.markdown(f"- {contact}")
                st.error(
                    "**Mandatory Obligations**\n\n"
                    "Privacy Act 1988 — OAIC 30 days\n\n"
                    "SOCI Act 2018 — ASD 12 hours\n\n"
                    "Ransomware — ACSC 1300 CYBER1"
                )


# ── FOOTER ────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<div style='text-align:center;color:#3a5878;font-size:11px;padding:4px 0'>"
    "<span style='color:#6ba3ff;font-weight:700'>AAHE</span> &nbsp;·&nbsp; "
    "<span style='color:#ffd740;font-weight:600'>Group 14</span> &nbsp;·&nbsp; "
    "CYB815 Cybersecurity Capstone &nbsp;·&nbsp; "
    "OTX · AbuseIPDB · URLhaus · Feodo Tracker &nbsp;·&nbsp; "
    "MITRE ATT&CK · NIST CSF · CVSS v3.1 · ASD Essential 8 · ISO 27001 &nbsp;·&nbsp; "
    "For Educational and Research Use Only"
    "</div>",
    unsafe_allow_html=True
)
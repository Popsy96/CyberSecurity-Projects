"""
streamlit_app.py — AU CTI Dashboard v3
=======================================
CYB815 Cybersecurity Capstone — Group 14
AAHE · Australasian Academy of Higher Education

Changes from v2 (matching HTML dashboard v16):
  - Overview: removed Top Cities, timeline taller + proper line, attack cats full-width
  - Overview: removed Severity Breakdown panel
  - Timeline: gradient fill line chart, no log scale, coloured spike points
  - Attack Categories: full width, taller, shorter labels
  - Risk tab: Risk Register removed, fits one page (Matrix + CVSS side by side,
              MITRE + Top 5 threats side by side, compact methodology strip)
  - IR tab: ACSC always-visible bar at top, live threat counts per playbook,
            response time urgency visual, MITRE filter added to Feed tab
  - NIST % labels in Analytics
  - Map: city bubbles only (no 1500 cap), locked to AU bounds

Run:
    streamlit run dashboard/streamlit_app.py
"""

import json, os
from datetime import datetime, date, timedelta

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ── PAGE CONFIG ───────────────────────────────────────────────
st.set_page_config(
    page_title="AU CTI Dashboard — Group 14",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────
st.markdown("""
<style>
  .stApp { background:#060b18; color:#cde0ff; }
  [data-testid="stSidebar"] { background:#0a1020; border-right:1px solid #1a2d5a; }
  [data-testid="stMetric"] {
    background:#0b1225; border:1px solid #1a2d5a; border-radius:10px; padding:14px; }
  [data-testid="stMetricLabel"]  { color:#3a5878 !important; font-size:10px !important;
    text-transform:uppercase; letter-spacing:1px; }
  [data-testid="stMetricValue"]  { color:#fff !important; font-size:24px !important; font-weight:800 !important; }
  [data-testid="stMetricDelta"]  { color:#00e5a0 !important; font-size:10px !important; }
  div[data-testid="stTabs"] button { color:#7a9cc8 !important; font-weight:500; }
  div[data-testid="stTabs"] button[aria-selected="true"] {
    color:#fff !important; border-bottom:2px solid #2979ff !important; font-weight:700; }
  .stDataFrame { border:1px solid #1a2d5a; border-radius:8px; }
  h1,h2,h3 { color:#cde0ff !important; }
  hr { border-color:#1a2d5a; }

  /* Pills */
  .pill { display:inline-block;font-size:10px;padding:2px 9px;border-radius:20px;
    font-weight:600;margin-right:4px;border:1px solid; }
  .pill-red    { color:#ff7a90;background:rgba(255,61,90,.1);  border-color:rgba(255,61,90,.3); }
  .pill-blue   { color:#6ba3ff;background:rgba(41,121,255,.1);border-color:rgba(41,121,255,.3); }
  .pill-orange { color:#ffb74d;background:rgba(255,152,0,.1); border-color:rgba(255,152,0,.3); }
  .pill-green  { color:#00e5a0;background:rgba(0,229,160,.1); border-color:rgba(0,229,160,.3); }
  .pill-purple { color:#b388ff;background:rgba(156,107,255,.1);border-color:rgba(156,107,255,.3);}

  /* Phase cards */
  .phase-card { background:#0b1225;border:1px solid #1a2d5a;border-radius:8px;
    padding:10px 12px;margin-bottom:6px; }
  .phase-title { color:#2979ff;font-weight:700;font-size:11px;
    text-transform:uppercase;letter-spacing:1px;margin-bottom:6px; }
  .phase-item { color:#7a9cc8;font-size:10.5px;padding:2px 0; }
  .phase-item::before { content:"› ";color:#2979ff; }

  /* ACSC bar */
  .acsc-bar { background:rgba(255,61,90,.06);border:1px solid rgba(255,61,90,.25);
    border-radius:8px;padding:10px 16px;margin-bottom:12px; }

  /* Methodology strip */
  .meth-strip { display:flex;gap:10px;align-items:stretch;flex-wrap:wrap;padding:8px 0; }
  .meth-step { background:#0b1225;border:1px solid #1a2d5a;border-radius:6px;
    padding:8px 12px;flex:1;min-width:140px; }
  .meth-title { color:#2979ff;font-size:9px;font-weight:700;text-transform:uppercase;
    letter-spacing:.8px;margin-bottom:4px; }
  .meth-body { color:#7a9cc8;font-size:10px;line-height:1.5; }
</style>
""", unsafe_allow_html=True)

# ── CONSTANTS ─────────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    plot_bgcolor='#0b1225', paper_bgcolor='#060b18',
    font=dict(color='#7a9cc8', size=11),
    margin=dict(l=10, r=10, t=30, b=10),
)
PAL     = ['#2979ff','#ff3d5a','#ff9800','#ffd740','#00e5a0','#9c6bff','#00d4ff','#fd7e14']
SEV_COL = {'Critical':'#ff3d5a','High':'#ff9800','Medium':'#ffd740','Low':'#00e5a0'}
PROJECT_START = date(2026, 4, 13)

CITY_COORDS = {
    'Perth':(-31.9505,115.8605),'Darwin':(-12.4634,130.8456),'Adelaide':(-34.9285,138.6007),
    'Brisbane':(-27.4698,153.0251),'Sydney':(-33.8688,151.2093),'Melbourne':(-37.8136,144.9631),
    'Hobart':(-42.8821,147.3272),'Canberra':(-35.2809,149.1300),
    'Gold Coast':(-28.0167,153.4000),'Newcastle':(-32.9267,151.7789),
}
CITY_STATE = {
    'Sydney':'NSW','Newcastle':'NSW','Melbourne':'VIC','Brisbane':'QLD',
    'Gold Coast':'QLD','Perth':'WA','Adelaide':'SA','Hobart':'TAS',
    'Canberra':'ACT','Darwin':'NT',
}

# ── LOAD DATA ─────────────────────────────────────────────────
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

cat_counts  = stats.get('category_counts', {})
phishing_n  = cat_counts.get('Phishing', 0)
malware_n   = cat_counts.get('Malware Distribution', 0)
susp_n      = (cat_counts.get('Brute Force',0) +
               cat_counts.get('SSH Brute Force',0) +
               cat_counts.get('Suspicious Activity',0))

# ── HEADER ────────────────────────────────────────────────────
st.markdown(f"""
<div style="background:linear-gradient(135deg,#071035,#0d1e4a,#071035);
  border:1px solid #1a2d5a;border-radius:10px;padding:12px 18px;margin-bottom:14px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px">
    <div>
      <span style="color:#6ba3ff;font-weight:700;font-size:13px;margin-right:10px">AAHE</span>
      <span style="color:#fff;font-weight:700;font-size:17px">Australia Cyber Threat Intelligence Dashboard</span>
      <span style="color:#3a5878;font-size:11px;margin-left:8px">CYB815 &nbsp;·&nbsp;
        <span style="color:#ffd740;font-weight:700">Group 14</span></span><br/>
      <div style="margin-top:7px;display:flex;flex-wrap:wrap;gap:4px;align-items:center">
        <span class="pill pill-red">MITRE ATT&amp;CK</span>
        <span class="pill pill-blue">NIST CSF</span>
        <span class="pill pill-orange">CVSS v3.1</span>
        <span class="pill pill-green">ASD Essential 8</span>
        <span class="pill pill-purple">ISO 27001</span>
        &nbsp;
        <span style="font-size:10px;color:#ff9800;font-weight:600">✓ Malware: {malware_n:,}</span>
        &nbsp;
        <span style="font-size:10px;color:#ff3d5a;font-weight:600">✓ Phishing: {phishing_n:,}</span>
        &nbsp;
        <span style="font-size:10px;color:#ffd740;font-weight:600">✓ Suspicious: {susp_n:,}</span>
      </div>
    </div>
    <div style="text-align:right;color:#3a5878;font-size:10px">
      Last updated<br/>
      <span style="color:#00d4ff;font-size:11px">{stats.get('last_updated','—')}</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# ── SIDEBAR ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("**📅 Date Range**")
    st.caption("Preset applies immediately · Custom needs Apply")

    preset = st.radio("Preset", [
        "All Time","Last 7 Days","Last 30 Days",
        "Project Period (Apr 13→)","Custom Range",
    ], index=0, label_visibility="collapsed")

    from_date = to_date = None
    if preset == "Custom Range":
        c1, c2 = st.columns(2)
        from_date = c1.date_input("From", value=PROJECT_START, key="from_d")
        to_date   = c2.date_input("To",   value=date.today(),  key="to_d")

    apply_date = st.button("▶ Apply", use_container_width=True, type="primary")
    if st.button("✕ Clear", use_container_width=True):
        st.session_state['date_applied'] = 'All Time'
        st.rerun()

    if apply_date:
        st.session_state['date_applied'] = preset
        if preset == "Custom Range":
            st.session_state['from_date'] = from_date
            st.session_state['to_date']   = to_date

    active_preset = st.session_state.get('date_applied', 'All Time')
    st.caption(f"Active: **{active_preset}**")
    st.divider()

    # IOC Filters
    st.markdown("**🔍 Threat Intel Filters**")
    sev_opts  = ['All'] + sorted(df['severity'].dropna().unique().tolist())   if 'severity'      in df.columns else ['All']
    cat_opts  = ['All'] + sorted(df['category'].dropna().unique().tolist())   if 'category'      in df.columns else ['All']
    city_opts = ['All'] + sorted([c for c in df['city'].dropna().unique()
                                   if c not in ('AU','Unknown','')]) if 'city' in df.columns else ['All']
    type_opts = ['All'] + sorted(df['type'].dropna().unique().tolist())       if 'type'          in df.columns else ['All']
    nist_opts = ['All','Identify','Protect','Detect','Respond','Recover']
    src_opts  = ['All'] + sorted(df['source'].dropna().unique().tolist())     if 'source'        in df.columns else ['All']
    mal_opts  = ['All'] + sorted([m for m in df['malware_type'].dropna().unique()
                                   if m not in ('Unknown','')]) if 'malware_type' in df.columns else ['All']
    mitre_opts= ['All'] + sorted(df['mitre_technique'].dropna().unique().tolist()) if 'mitre_technique' in df.columns else ['All']

    sel_sev   = st.selectbox("Severity",      sev_opts,   key="sev_f")
    sel_cat   = st.selectbox("Category",      cat_opts,   key="cat_f")
    sel_city  = st.selectbox("City",          city_opts,  key="city_f")
    sel_type  = st.selectbox("IOC Type",      type_opts,  key="type_f")
    sel_nist  = st.selectbox("NIST Function", nist_opts,  key="nist_f")
    sel_src   = st.selectbox("Source Feed",   src_opts,   key="src_f")
    sel_mal   = st.selectbox("Malware Type",  mal_opts,   key="mal_f")
    sel_mitre = st.selectbox("MITRE Technique", mitre_opts, key="mitre_f")

    apply_ioc = st.button("▶ Apply Filters",  use_container_width=True, type="primary")
    if st.button("✕ Reset Filters", use_container_width=True):
        for k in ['sev_f','cat_f','city_f','type_f','nist_f','src_f','mal_f','mitre_f']:
            st.session_state[k] = 'All'
        st.rerun()

    st.divider()
    st.markdown("**📡 Feed Status**")
    sc = stats.get('source_counts', {})
    for feed, col in [('AlienVault OTX','#2979ff'),('AbuseIPDB','#ff3d5a'),
                      ('URLhaus','#ff9800'),('Feodo Tracker','#9c6bff')]:
        c_ = sc.get(feed, 0)
        st.markdown(f"{'🟢' if c_>0 else '⚫'} **{feed}** — `{c_:,}`")

# ── DATE FILTER ───────────────────────────────────────────────
def apply_date_filter(data: pd.DataFrame) -> pd.DataFrame:
    d = data.copy()
    if '_dt' not in d.columns:
        return d
    active   = st.session_state.get('date_applied', 'All Time')
    now_ts   = pd.Timestamp.now(tz='UTC').normalize()
    proj_ts  = pd.Timestamp(PROJECT_START, tz='UTC')
    if active == "Last 7 Days":
        d = d[d['_dt'] >= now_ts - pd.Timedelta(days=6)]
    elif active == "Last 30 Days":
        d = d[d['_dt'] >= now_ts - pd.Timedelta(days=29)]
    elif active == "Project Period (Apr 13→)":
        d = d[d['_dt'] >= proj_ts]
    elif active == "Custom Range":
        fd = st.session_state.get('from_date')
        td = st.session_state.get('to_date')
        if fd: d = d[d['_dt'] >= pd.Timestamp(fd, tz='UTC')]
        if td: d = d[d['_dt'] <= pd.Timestamp(td, tz='UTC') + pd.Timedelta(days=1)]
    return d

def apply_ioc_filters(data: pd.DataFrame) -> pd.DataFrame:
    d = data.copy()
    if sel_sev   != 'All' and 'severity'       in d.columns: d = d[d['severity']       == sel_sev]
    if sel_cat   != 'All' and 'category'       in d.columns: d = d[d['category']       == sel_cat]
    if sel_city  != 'All' and 'city'           in d.columns: d = d[d['city']           == sel_city]
    if sel_type  != 'All' and 'type'           in d.columns: d = d[d['type']           == sel_type]
    if sel_nist  != 'All' and 'nist_function'  in d.columns: d = d[d['nist_function']  == sel_nist]
    if sel_src   != 'All' and 'source'         in d.columns: d = d[d['source']         == sel_src]
    if sel_mal   != 'All' and 'malware_type'   in d.columns: d = d[d['malware_type']   == sel_mal]
    if sel_mitre != 'All' and 'mitre_technique' in d.columns: d = d[d['mitre_technique']== sel_mitre]
    return d

date_filtered = apply_date_filter(df)
ioc_filtered  = apply_ioc_filters(date_filtered) if apply_ioc else date_filtered
total_n       = len(df)
st.sidebar.info(f"**{len(date_filtered):,}** of **{total_n:,}** threats shown")

# ── TABS ──────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏠 Overview", "🔎 Threat Intel Feed",
    "📊 Analytics", "⚠️ Risk & CVSS", "🛡 IR & Mitigation",
])

# ══════════════════════════════════════════════════════════════
#  TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════
with tab1:
    filtered = date_filtered

    # ── KPI Row ──────────────────────────────────────────────
    c1,c2,c3,c4,c5,c6 = st.columns(6)
    c1.metric("Total IOCs",    f"{len(filtered):,}",        f"of {total_n:,} total")
    c2.metric("Critical",      f"{len(filtered[filtered['severity']=='Critical']):,}" if 'severity' in filtered.columns else "—", "act immediately")
    c3.metric("High",          f"{len(filtered[filtered['severity']=='High']):,}"     if 'severity' in filtered.columns else "—", "investigate now")
    c4.metric("Avg CVSS",      f"{filtered['cvss_score'].mean():.1f}" if 'cvss_score' in filtered.columns and len(filtered) else "—", "/ 10.0")
    c5.metric("Phishing",      f"{len(filtered[filtered['category']=='Phishing']):,}" if 'category' in filtered.columns else "—", "campaigns")
    c6.metric("Suspicious",    f"{len(filtered[filtered['category'].isin(['Brute Force','SSH Brute Force','Suspicious Activity'])]):,}" if 'category' in filtered.columns else "—", "network threats")

    # ── IOC Timeline — gradient line, no log scale ───────────
    tl = stats.get('timeline', [])
    if tl:
        tl_df = pd.DataFrame(tl)
        tl_df = tl_df[tl_df['date'] >= '2026-04-13'].copy()
        tl_df['date'] = tl_df['date'].str[5:]  # MM-DD only
        if len(tl_df):
            max_v  = tl_df['count'].max() or 1
            colors = tl_df['count'].apply(
                lambda v: '#ff3d5a' if v > max_v*0.6 else '#ff9800' if v > max_v*0.25 else '#2979ff'
            )
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=tl_df['date'], y=tl_df['count'],
                mode='lines+markers',
                line=dict(color='#2979ff', width=2.5),
                fill='tozeroy',
                fillcolor='rgba(41,121,255,0.15)',
                marker=dict(
                    size=[6 if v > max_v*0.25 else 3 for v in tl_df['count']],
                    color=list(colors),
                    line=dict(color='#fff', width=1),
                ),
                hovertemplate='2026-%{x}<br>%{y:,} threats<extra></extra>',
            ))
            fig.update_layout(**PLOTLY_LAYOUT, height=200,
                              xaxis=dict(showgrid=False, tickfont=dict(size=9)),
                              yaxis=dict(gridcolor='#0a1628', tickfont=dict(size=9),
                                         tickformat='~s'))
            st.markdown("**IOC Detections Over Time**")
            st.plotly_chart(fig, use_container_width=True, key="ov_timeline")

    # ── Map + Attack Categories side by side ─────────────────
    col_map, col_right = st.columns([2, 1])

    with col_map:
        st.markdown("**🗺 Australia Threat Map**")
        if 'city' in filtered.columns and len(filtered):
            city_g = filtered.groupby('city').agg(
                count=('cvss_score','count'),
                max_cvss=('cvss_score','max'),
                crit=('severity', lambda x: (x=='Critical').sum())
            ).reset_index()
            city_g = city_g[city_g['city'].isin(CITY_COORDS)]
            if len(city_g):
                city_g['lat']   = city_g['city'].map(lambda c: CITY_COORDS[c][0])
                city_g['lon']   = city_g['city'].map(lambda c: CITY_COORDS[c][1])
                city_g['color'] = city_g.apply(lambda r:
                    '#ff3d5a' if r['crit']/max(r['count'],1) > 0.5
                    else '#ff9800' if r['max_cvss'] >= 7 else '#2979ff', axis=1)
                # Small bubbles — 8 to 22px range (was 10-45, way too big)
                max_c = city_g['count'].max() or 1
                city_g['size'] = (8 + (city_g['count'] / max_c) * 14).round(1)
                # Show city + count directly as text on map
                city_g['txt']   = city_g['city'] + '<br>' + city_g['count'].apply(lambda v: f"{v:,}")
                city_g['hover'] = city_g.apply(
                    lambda r: f"<b>{r['city']}</b><br>"
                              f"Total: {r['count']:,}<br>"
                              f"Critical: {r['crit']:,}<br>"
                              f"Max CVSS: {r['max_cvss']:.1f}", axis=1)

                fig = go.Figure()
                for col_hex, name in [('#ff3d5a','Critical hotspot'),
                                       ('#ff9800','High risk'),
                                       ('#2979ff','Active')]:
                    sub = city_g[city_g['color'] == col_hex]
                    if len(sub):
                        fig.add_trace(go.Scattermapbox(
                            lat=sub['lat'], lon=sub['lon'],
                            mode='markers+text',
                            marker=dict(
                                size=list(sub['size']),
                                color=col_hex,
                                opacity=0.80,
                            ),
                            text=list(sub['txt']),
                            textfont=dict(size=8, color='#ffffff'),
                            textposition='top center',
                            hovertext=list(sub['hover']),
                            hoverinfo='text',
                            name=name,
                        ))

                fig.update_layout(
                    mapbox=dict(
                        # open-street-map shows state borders clearly
                        style='open-street-map',
                        center=dict(lat=-26.0, lon=134.0),
                        zoom=3.4,   # slightly zoomed out so Darwin+Hobart visible
                    ),
                    margin={'r':0,'t':0,'l':0,'b':0},
                    height=370,
                    paper_bgcolor='#060b18',
                    legend=dict(
                        orientation='h', y=1.02, x=0,
                        bgcolor='rgba(6,11,24,.85)',
                        font=dict(size=9, color='#cde0ff'),
                        bordercolor='#1a2d5a', borderwidth=1,
                    ),
                )
                # Dark overlay via CSS is not possible in plotly mapbox,
                # but open-street-map is readable at low opacity naturally
                st.plotly_chart(fig, use_container_width=True, key="ov_map")

                # City count table below map
                top_cities = city_g.sort_values('count', ascending=False).head(5)
                medals = ['🥇','🥈','🥉','④','⑤']
                cols_ct = st.columns(len(top_cities))
                for i, (_, row) in enumerate(top_cities.iterrows()):
                    col_ct = cols_ct[i]
                    col_ct.metric(
                        f"{medals[i]} {row['city']}",
                        f"{row['count']:,}",
                        f"🔴 {row['crit']:,} critical"
                    )
        else:
            st.info("Map requires city field in data.json")

    with col_right:
        # Attack Categories — full width in this column, taller
        st.markdown("**Attack Categories**")
        if 'category' in filtered.columns and len(filtered):
            cats = (filtered[~filtered['category'].isin(['Suspicious Activity','Unknown',''])]
                    ['category'].value_counts().head(8).reset_index())
            cats.columns = ['Category', 'Count']
            # Shorten labels
            cats['Category'] = cats['Category'].str.replace(' Distribution','').str.replace(' Attack','')
            cats = cats.sort_values('Count')
            fig = px.bar(cats, x='Count', y='Category', orientation='h',
                         color='Count', color_continuous_scale='Blues',
                         template='plotly_dark')
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                              coloraxis_showscale=False, height=170)
            fig.update_traces(marker_line_width=0)
            fig.update_xaxes(showgrid=False, tickfont=dict(size=9))
            fig.update_yaxes(tickfont=dict(size=9.5))
            st.plotly_chart(fig, use_container_width=True, key="ov_cats")

        # Recent Collection Runs
        st.markdown("**Recent Collection Runs**")
        runs = stats.get('fetch_runs', [])
        if runs:
            for r in runs[:3]:
                st.markdown(
                    f"**{r.get('run_time_au','—')}**  \n"
                    f"🔴 `{r.get('critical',0):,}` &nbsp;"
                    f"🟠 `{r.get('high',0):,}` &nbsp;"
                    f"✅ `+{r.get('new_threats',0):,}` new"
                )
        else:
            st.caption("No run history yet.")


# ══════════════════════════════════════════════════════════════
#  TAB 2 — THREAT INTEL FEED
# ══════════════════════════════════════════════════════════════
with tab2:
    active_f = [f for f,v in [
        ('Severity',sel_sev),('Category',sel_cat),('City',sel_city),('Type',sel_type),
        ('NIST',sel_nist),('Source',sel_src),('Malware',sel_mal),('MITRE',sel_mitre),
    ] if v != 'All']

    if active_f:
        st.info(f"🔍 Active filters: {' · '.join(active_f)} — **{len(ioc_filtered):,}** of **{len(date_filtered):,}** threats")
    else:
        st.caption(f"Showing all **{len(ioc_filtered):,}** threats — use sidebar filters to narrow down")

    if len(ioc_filtered):
        show_cols = ['severity','cvss_score','type','ioc','category','mitre_technique',
                     'nist_function','asd_e8','industry','source','city','timestamp_au']
        cols_e = [c for c in show_cols if c in ioc_filtered.columns]
        disp   = (ioc_filtered[cols_e]
                  .sort_values('cvss_score', ascending=False)
                  .rename(columns={
                      'cvss_score':'CVSS','mitre_technique':'MITRE','nist_function':'NIST',
                      'asd_e8':'ASD E8','timestamp_au':'Timestamp','severity':'Severity',
                      'type':'Type','ioc':'Indicator','category':'Category',
                      'industry':'Industry','source':'Source','city':'City',
                  }))
        st.dataframe(disp, use_container_width=True, height=480,
                     column_config={'CVSS': st.column_config.NumberColumn(format="%.1f"),
                                    'Indicator': st.column_config.TextColumn(width='medium')})
        csv = ioc_filtered[cols_e].to_csv(index=False)
        st.download_button(
            label=f"⬇ Export {len(ioc_filtered):,} threats (CSV)",
            data=csv,
            file_name=f"au-cti-group14-{datetime.now().strftime('%Y-%m-%d')}.csv",
            mime="text/csv",
        )
    else:
        st.warning("No threats match the current filters.")


# ══════════════════════════════════════════════════════════════
#  TAB 3 — ANALYTICS
# ══════════════════════════════════════════════════════════════
with tab3:
    filtered = date_filtered

    # NIST CSF with % labels
    nd       = stats.get('nist_dist', {})
    nd_total = sum(nd.values()) or 1
    n1,n2,n3,n4,n5 = st.columns(5)
    for col, key, label in [
        (n1,'Identify','IDENTIFY'),(n2,'Protect','PROTECT'),(n3,'Detect','DETECT'),
        (n4,'Respond','RESPOND'),(n5,'Recover','RECOVER'),
    ]:
        v   = nd.get(key, 0)
        pct = round(v/nd_total*100)
        col.metric(label, f"{v:,}", f"{pct}% of threats")

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Threats by Australian City")
        if 'city' in filtered.columns and len(filtered):
            city_df = filtered[~filtered['city'].isin(['AU','Unknown',''])]
            if len(city_df):
                cc = city_df['city'].value_counts().head(8).reset_index()
                cc.columns = ['City','Count']
                fig = px.bar(cc.sort_values('Count'), x='Count', y='City',
                             orientation='h', color='Count',
                             color_continuous_scale='Blues', template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                                  coloraxis_showscale=False, height=270)
                st.plotly_chart(fig, use_container_width=True, key="an_cities")

    with col2:
        st.subheader("Affected Industries")
        if 'industry' in filtered.columns and len(filtered):
            ind_df = filtered[~filtered['industry'].isin(['Other','Unknown',''])]
            if len(ind_df):
                ic = ind_df['industry'].value_counts().head(8).reset_index()
                ic.columns = ['Industry','Count']
                fig = px.bar(ic.sort_values('Count'), x='Count', y='Industry',
                             orientation='h', color='Count',
                             color_continuous_scale='Oranges', template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                                  coloraxis_showscale=False, height=270)
                st.plotly_chart(fig, use_container_width=True, key="an_ind")

    col3, col4, col5 = st.columns(3)
    with col3:
        st.subheader("Malware Classification")
        if 'malware_type' in filtered.columns and len(filtered):
            mt = filtered[~filtered['malware_type'].isin(['Unknown',''])]['malware_type'].value_counts()
            if len(mt):
                fig = px.pie(values=mt.values, names=mt.index, hole=0.45,
                             color_discrete_sequence=PAL, template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, height=240)
                fig.update_traces(textposition='inside', textinfo='percent+label', textfont_size=10)
                st.plotly_chart(fig, use_container_width=True, key="an_maltype")

    with col4:
        st.subheader("ASD Essential Eight")
        if 'asd_e8' in filtered.columns and len(filtered):
            asd = (filtered[~filtered['asd_e8'].isin(['Unknown',''])]
                   ['asd_e8'].value_counts().head(6).reset_index())
            asd.columns = ['Control','Count']
            fig = px.bar(asd.sort_values('Count'), x='Count', y='Control',
                         orientation='h', color='Count',
                         color_continuous_scale='Greens', template='plotly_dark')
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                              coloraxis_showscale=False, height=240)
            st.plotly_chart(fig, use_container_width=True, key="an_asd")

    with col5:
        st.subheader("AU State Distribution")
        if 'city' in filtered.columns and len(filtered):
            s_df = filtered.copy()
            s_df['state'] = s_df['city'].map(CITY_STATE)
            sc_df = s_df.dropna(subset=['state'])['state'].value_counts().reset_index()
            sc_df.columns = ['State','Count']
            fig = px.bar(sc_df.sort_values('Count', ascending=False),
                         x='State', y='Count', color='Count',
                         color_continuous_scale='Blues', template='plotly_dark')
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                              coloraxis_showscale=False, height=240)
            st.plotly_chart(fig, use_container_width=True, key="an_states")

    col6, col7 = st.columns(2)
    with col6:
        st.subheader("IOC Type Breakdown")
        if 'type' in filtered.columns and len(filtered):
            it = filtered[~filtered['type'].isin(['Unknown',''])]['type'].value_counts()
            if len(it):
                fig = px.pie(values=it.values, names=it.index, hole=0.45,
                             color_discrete_sequence=PAL, template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, height=240)
                fig.update_traces(textposition='inside', textinfo='percent+label', textfont_size=10)
                st.plotly_chart(fig, use_container_width=True, key="an_ioctype")

    with col7:
        st.subheader("Top Malware Families")
        if 'malware_family' in filtered.columns and len(filtered):
            fam = (filtered[
                (filtered['malware_family'].notna()) &
                (~filtered['malware_family'].isin(['','Unknown'])) &
                (filtered['malware_family'].str.len() < 30)
            ]['malware_family'].value_counts().head(9))
            if len(fam):
                fam_df = fam.reset_index()
                fam_df.columns = ['Family','Count']
                fig = px.bar(fam_df.sort_values('Count'), x='Count', y='Family',
                             orientation='h', color='Count',
                             color_continuous_scale='Reds', template='plotly_dark')
                fig.update_layout(**PLOTLY_LAYOUT, showlegend=False,
                                  coloraxis_showscale=False, height=260)
                st.plotly_chart(fig, use_container_width=True, key="an_malfam")


# ══════════════════════════════════════════════════════════════
#  TAB 4 — RISK & CVSS  (one page, no Risk Register)
# ══════════════════════════════════════════════════════════════
with tab4:
    filtered    = date_filtered
    avg_cvss    = filtered['cvss_score'].mean()  if 'cvss_score' in filtered.columns and len(filtered) else 0
    max_cvss    = filtered['cvss_score'].max()   if 'cvss_score' in filtered.columns and len(filtered) else 0
    crit_n      = len(filtered[filtered['cvss_score']>=9]) if 'cvss_score' in filtered.columns and len(filtered) else 0
    crithigh    = len(filtered[filtered['severity'].isin(['Critical','High'])]) if 'severity' in filtered.columns and len(filtered) else 0

    # Row 1: 4 KPIs
    r1,r2,r3,r4 = st.columns(4)
    r1.metric("Average CVSS",    f"{avg_cvss:.1f}", "/ 10.0")
    r2.metric("Critical (9+)",   f"{crit_n:,}",    "immediate action")
    r3.metric("Highest CVSS",    f"{max_cvss:.1f}", "maximum observed")
    r4.metric("Critical + High", f"{crithigh:,}",  "high priority")

    # Row 2: Risk Matrix (left) + CVSS Distribution (right)
    col_mat, col_cvss = st.columns(2)

    RISKS = [
        dict(label='Phishing',   catKey='Phishing',            l=4,i=3,col='#ff9800',score=20,rating='Critical'),
        dict(label='C2 Server',  catKey='C2 Server',           l=3,i=4,col='#ff3d5a',score=20,rating='Critical'),
        dict(label='Malware',    catKey='Malware Distribution',l=4,i=2,col='#ff9800',score=15,rating='High'),
        dict(label='Brute Force',catKey='Brute Force',         l=4,i=4,col='#ff9800',score=16,rating='High'),
        dict(label='Ransomware', catKey='Ransomware',          l=2,i=4,col='#ff3d5a',score=15,rating='High'),
        dict(label='DDoS',       catKey='DDoS Attack',         l=2,i=3,col='#ffd740',score=12,rating='High'),
        dict(label='SQL Inject', catKey='SQL Injection',       l=2,i=3,col='#ffd740',score=12,rating='High'),
        dict(label='Port Scan',  catKey='Port Scan',           l=4,i=1,col='#00e5a0',score=10,rating='Medium'),
    ]
    cat_live  = filtered['category'].value_counts().to_dict() if 'category' in filtered.columns else {}
    max_count = max(cat_live.values(), default=1)
    risk_df   = pd.DataFrame([{
        'Threat':r['label'],'Likelihood':r['l'],'Impact':r['i'],
        'Count':cat_live.get(r['catKey'],1),'Color':r['col'],
        'Rating':r['rating'],'Score':r['score'],
    } for r in RISKS])

    with col_mat:
        st.markdown("**Risk Assessment Matrix**")
        st.caption("ISO/IEC 27005:2022 · Bubble size = live threat volume")
        fig = go.Figure()
        for x0,x1,y0,y1,c in [
            (0.5,5.5,0.5,2.5,'rgba(0,229,160,0.2)'),
            (0.5,3.5,2.5,5.5,'rgba(255,215,64,0.15)'),
            (2.5,4.5,3.5,5.5,'rgba(255,152,0,0.15)'),
            (3.5,5.5,3.5,5.5,'rgba(255,61,90,0.18)'),
        ]:
            fig.add_shape(type='rect',x0=x0,x1=x1,y0=y0,y1=y1,
                          fillcolor=c,line=dict(width=0),layer='below')
        for i in range(1,6):
            fig.add_shape(type='line',x0=i+.5,x1=i+.5,y0=.5,y1=5.5,line=dict(color='#1a2d5a',width=1))
            fig.add_shape(type='line',x0=.5,x1=5.5,y0=i+.5,y1=i+.5,line=dict(color='#1a2d5a',width=1))
        fig.add_trace(go.Scatter(
            x=risk_df['Likelihood'], y=risk_df['Impact'],
            mode='markers+text',
            marker=dict(size=[10+(c/max_count)*28 for c in risk_df['Count']],
                        color=risk_df['Color'], opacity=0.78,
                        line=dict(color=risk_df['Color'],width=1.5)),
            text=risk_df['Threat'],
            textposition='top center',
            textfont=dict(size=9,color='#cde0ff'),
            customdata=list(zip(risk_df['Rating'],risk_df['Score'],risk_df['Count'])),
            hovertemplate='<b>%{text}</b><br>L=%{x} · I=%{y}<br>Rating: %{customdata[0]} · Score: %{customdata[1]}<br>Live: %{customdata[2]:,}<extra></extra>',
        ))
        fig.update_layout(
            **PLOTLY_LAYOUT, height=280, showlegend=False,
            xaxis=dict(range=[0.5,5.5],tickvals=list(range(1,6)),
                       ticktext=['Rare','Unlikely','Possible','Likely','Almost\nCertain'],
                       title=dict(text='LIKELIHOOD →',font=dict(color='#00e5a0',size=10)),
                       showgrid=False),
            yaxis=dict(range=[0.5,5.5],tickvals=list(range(1,6)),
                       ticktext=['Negligible','Minor','Moderate','Major','Catastrophic'],
                       title=dict(text='IMPACT →',font=dict(color='#00e5a0',size=10)),
                       showgrid=False),
        )
        st.plotly_chart(fig, use_container_width=True, key="risk_matrix")

    with col_cvss:
        st.markdown("**CVSS Score Distribution**")
        if 'cvss_score' in filtered.columns and len(filtered):
            bins   = ['Critical 9-10','High 7-8.9','Medium 4-6.9','Low 0-3.9']
            counts = [
                len(filtered[filtered['cvss_score']>=9]),
                len(filtered[(filtered['cvss_score']>=7)&(filtered['cvss_score']<9)]),
                len(filtered[(filtered['cvss_score']>=4)&(filtered['cvss_score']<7)]),
                len(filtered[filtered['cvss_score']<4]),
            ]
            fig = px.bar(x=bins, y=counts, color=bins, template='plotly_dark',
                         color_discrete_map={'Critical 9-10':'#ff3d5a','High 7-8.9':'#ff9800',
                                             'Medium 4-6.9':'#ffd740','Low 0-3.9':'#00e5a0'})
            fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, height=160)
            fig.update_traces(marker_line_width=0)
            for b,cv in zip(bins,counts):
                pct = f"{cv/len(filtered)*100:.0f}%" if len(filtered) else ''
                fig.add_annotation(x=b,y=cv,text=f"{cv:,} ({pct})",
                                   showarrow=False,yshift=8,font=dict(size=9,color='#cde0ff'))
            st.plotly_chart(fig, use_container_width=True, key="risk_cvss_dist")

        # Top 5 Highest CVSS Threats (city + category, no IOC)
        st.markdown("**Top 5 Highest Risk Threats** — city & category only")
        if 'cvss_score' in filtered.columns and len(filtered):
            top5 = (filtered[filtered['cvss_score']>0]
                    .sort_values('cvss_score',ascending=False)
                    .head(5))
            show = [c for c in ['cvss_score','severity','category','mitre_technique','city','source']
                    if c in top5.columns]
            st.dataframe(
                top5[show].rename(columns={'cvss_score':'CVSS','mitre_technique':'MITRE',
                                           'severity':'Sev','category':'Category',
                                           'city':'City','source':'Source'}),
                use_container_width=True, hide_index=True, height=200,
                column_config={'CVSS': st.column_config.NumberColumn(format="%.1f")},
            )

    # Row 3: MITRE weighted
    st.markdown("**MITRE ATT&CK Technique Frequency** — weighted by CVSS score")
    if 'mitre_technique' in filtered.columns and 'cvss_score' in filtered.columns and len(filtered):
        grp_cols = ['mitre_technique','mitre_name'] if 'mitre_name' in filtered.columns else ['mitre_technique']
        mitre = (filtered.groupby(grp_cols)
                 .agg(Count=('cvss_score','count'), CvssTotal=('cvss_score','sum'))
                 .reset_index().sort_values('CvssTotal',ascending=True).tail(8))
        mitre['Label'] = (mitre['mitre_technique'] + ' — ' + mitre['mitre_name'].fillna('')
                          if 'mitre_name' in mitre.columns else mitre['mitre_technique'])
        fig = px.bar(mitre, x='CvssTotal', y='Label', orientation='h',
                     color='CvssTotal', color_continuous_scale='Reds',
                     template='plotly_dark',
                     labels={'CvssTotal':'Total CVSS Weight','Label':''})
        fig.update_layout(**PLOTLY_LAYOUT, showlegend=False, coloraxis_showscale=False, height=240)
        st.plotly_chart(fig, use_container_width=True, key="risk_mitre")

    # Row 4: Methodology compact strip
    st.markdown("""
    <div class="meth-strip">
      <div class="meth-step">
        <div class="meth-title">Step 1 — Base Score</div>
        <div class="meth-body">Critical=9.0 · High=7.5 · Medium=5.0 · Low=2.5</div>
      </div>
      <div style="color:#3a5878;font-size:18px;align-self:center">→</div>
      <div class="meth-step">
        <div class="meth-title">Step 2 — Confidence</div>
        <div class="meth-body">AbuseIPDB 0–100% · (c÷100)×2−1 · Range −1 to +1</div>
      </div>
      <div style="color:#3a5878;font-size:18px;align-self:center">→</div>
      <div class="meth-step">
        <div class="meth-title">Step 3 — Category Boost</div>
        <div class="meth-body">C2/Ransomware +0.5 · DDoS +0.3 · Phishing +0.1</div>
      </div>
      <div style="color:#3a5878;font-size:18px;align-self:center">+</div>
      <div class="meth-step" style="min-width:120px">
        <div class="meth-title">Frameworks</div>
        <div class="meth-body" style="color:#ff8888">MITRE ATT&CK</div>
        <div class="meth-body" style="color:#80aaff">NIST CSF</div>
        <div class="meth-body" style="color:#00d68f">ASD Essential 8</div>
        <div class="meth-body" style="color:#bb88ff">ISO 27001</div>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
#  TAB 5 — IR & MITIGATION
# ══════════════════════════════════════════════════════════════
with tab5:

    # ACSC always-visible bar
    st.markdown("""
    <div class="acsc-bar">
      <span style="color:#ff4545;font-weight:700;font-size:12px">🇦🇺 Australian Reporting Obligations</span>
      &nbsp;&nbsp;
      <a href="https://www.cyber.gov.au/report" target="_blank"
         style="background:rgba(255,61,90,.15);border:1px solid rgba(255,61,90,.3);
                color:#ff7a90;border-radius:5px;padding:3px 10px;font-size:10px;
                font-weight:600;text-decoration:none">🔗 Report to ACSC</a>
      &nbsp;
      <span style="color:#3a5878;font-size:10px">
        Privacy Act 1988 — OAIC within 30 days &nbsp;·&nbsp;
        SOCI Act 2018 — ASD within 12 hours &nbsp;·&nbsp;
        Ransomware — 1300 CYBER1
      </span>
    </div>
    """, unsafe_allow_html=True)

    # Response time info
    ir1,ir2,ir3,ir4 = st.columns(4)
    ir1.metric("Critical Response","1 hour",   "Ransomware · C2 · DDoS")
    ir2.metric("High Response",    "4 hours",  "Phishing · Brute Force · Malware")
    ir3.metric("Medium Response",  "24 hours", "Port Scan · Recon")
    ir4.metric("IR Playbooks",     "8",        "NIST SP 800-61r2 aligned")

    playbooks = ir_data.get('playbooks', {}) if ir_data else {}
    summary   = ir_data.get('summary',   []) if ir_data else []

    if not summary:
        st.warning("IR data not found. Run `python main.py` first.")
        st.stop()

    # Summary table with live counts + urgency
    st.subheader("Incident Response Playbooks")
    cat_counts_live = df['category'].value_counts().to_dict() if 'category' in df.columns else {}

    sum_df = pd.DataFrame(summary)
    if not sum_df.empty and 'category' in sum_df.columns:
        sum_df['Active Threats'] = sum_df['category'].map(
            lambda c: cat_counts_live.get(c, 0))
        sum_df['Urgency'] = sum_df['severity'].map(
            {'Critical':'🔴 1 hour','High':'🟠 4 hours','Medium':'🟡 24 hours'}).fillna('—')
        disp_cols = [c for c in ['category','severity','mitre','nist','asd_e8','Urgency','Active Threats']
                     if c in sum_df.columns]
        st.dataframe(
            sum_df[disp_cols].rename(columns={
                'category':'Category','severity':'Severity','mitre':'MITRE',
                'nist':'NIST','asd_e8':'ASD E8',
            }),
            use_container_width=True, hide_index=True, height=280,
        )

    st.divider()
    st.subheader("Playbook Details")
    st.caption("Expand any playbook — includes phases, mitigations, AU contacts")

    for pb_name, p in playbooks.items():
        sev      = p.get('severity','—')
        mitre    = p.get('mitre','—').split('—')[0].strip()
        resp     = p.get('response_time','—')
        live_ct  = cat_counts_live.get(pb_name, 0)
        sev_icon = {'Critical':'🔴','High':'🟠','Medium':'🟡','Low':'🟢'}.get(sev,'⚪')
        live_str = f" · {live_ct:,} active" if live_ct > 0 else ""

        with st.expander(f"{sev_icon} **{pb_name}** — {sev} · {mitre} · {resp}{live_str}"):
            m1,m2,m3,m4,m5 = st.columns(5)
            m1.markdown(f"**Severity**\n\n{sev}")
            m2.markdown(f"**MITRE**\n\n{p.get('mitre','—')}")
            m3.markdown(f"**NIST**\n\n{p.get('nist','—')}")
            m4.markdown(f"**ASD E8**\n\n{p.get('asd_e8','—')}")
            m5.markdown(f"**Response**\n\n{resp}")

            st.markdown("---")
            st.markdown("**IR Lifecycle — NIST SP 800-61r2**")
            phases = list(p.get('phases', {}).items())
            for row_s in range(0, len(phases), 3):
                cols = st.columns(3)
                for j, (phase, actions) in enumerate(phases[row_s:row_s+3]):
                    with cols[j]:
                        st.markdown(
                            f"<div class='phase-card'>"
                            f"<div class='phase-title'>{row_s+j+1}. {phase}</div>"
                            + ''.join(f"<div class='phase-item'>{a}</div>"
                                      for a in (actions or [])[:3])
                            + "</div>", unsafe_allow_html=True)

            st.markdown("---")
            mit = p.get('mitigation', {})
            mc1,mc2,mc3,mc4 = st.columns(4)
            with mc1:
                st.markdown("**Short-Term**")
                for i,item in enumerate(mit.get('short_term',[])[:4],1):
                    st.markdown(f"{i}. {item}")
            with mc2:
                st.markdown("**Long-Term**")
                for i,item in enumerate(mit.get('long_term',[])[:4],1):
                    st.markdown(f"{i}. {item}")
            with mc3:
                st.markdown("**Vulnerability Fixes**")
                for fix in p.get('vulnerability_fixes',[])[:4]:
                    st.markdown(f"+ {fix}")
            with mc4:
                st.markdown("**AU Contacts**")
                for contact in p.get('au_contacts',[])[:3]:
                    st.markdown(f"- {contact}")
                st.error("**Mandatory**\n\nPrivacy Act — OAIC 30 days\n\nSOCI Act — ASD 12 hrs\n\nRansomware — 1300 CYBER1")


# ── FOOTER ────────────────────────────────────────────────────
st.divider()
st.markdown(
    "<div style='text-align:center;color:#3a5878;font-size:10px;padding:4px 0'>"
    "<span style='color:#6ba3ff;font-weight:700'>AAHE</span> &nbsp;·&nbsp; "
    "<span style='color:#ffd740;font-weight:600'>Group 14</span> &nbsp;·&nbsp; "
    "CYB815 Cybersecurity Capstone &nbsp;·&nbsp; "
    "OTX · AbuseIPDB · URLhaus · Feodo Tracker &nbsp;·&nbsp; "
    "MITRE ATT&CK · NIST CSF · CVSS v3.1 · ASD Essential 8 · ISO 27001 &nbsp;·&nbsp; "
    "For Educational and Research Use Only"
    "</div>", unsafe_allow_html=True)
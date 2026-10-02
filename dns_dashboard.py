"""
DNS Intelligence & Cyber Threat Sentinel — Tim datascape
PeDaS 2026 Final | Business Analytics & Infrastructure Security
Enterprise Light Mode Edition (100% Rule-Based & Offline)
Standards: RFC 1035, RFC 6891, RFC 5452, NIST SP 800-81B

Jalankan via terminal:
python -m streamlit run app.py
"""

import os
import sys
from datetime import datetime

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Import modul heuristik mandiri
from heuristics import (
    SYSTEMATIC_SAMPLE_RATIO,
    GAMBLING_REGEX,
    CDN_WHITELIST,
    classify_sld_vectorized,
    is_public_sector_vectorized,
    calculate_domain_risk,
    detect_dns_tunneling
)

# ============================================================
# 1. STREAMLIT CONFIGURATION & TYPOGRAPHY
# ============================================================
st.set_page_config(
    page_title="DNS Intelligence Sentinel — datascape",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# High-Contrast Enterprise Light Mode Styling (Clean SaaS / Datadog Style)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Global Base */
    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    
    .main .block-container {
        padding-top: 1.0rem;
        padding-bottom: 2.5rem;
        max-width: 1440px;
    }

    /* Headings */
    h1, h2, h3, h4, h5, h6 {
        color: #0f172a !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em;
    }

    /* Executive Command Header (Sleek Dark Obsidian) */
    .command-header {
        background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
        border-radius: 12px;
        padding: 20px 26px;
        color: #ffffff;
        margin-bottom: 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.08), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
        border: 1px solid #334155;
    }
    .header-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
    }
    .header-title {
        font-size: 1.55rem;
        font-weight: 800;
        margin: 0;
        color: #ffffff !important;
        display: flex;
        align-items: center;
        gap: 10px;
        letter-spacing: -0.02em;
    }
    .header-subtitle {
        font-size: 0.88rem;
        color: #94a3b8;
        margin-top: 4px;
        line-height: 1.45;
    }
    .meta-pills {
        display: flex;
        align-items: center;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 10px;
    }
    .pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 6px;
        padding: 2px 10px;
        font-size: 0.76rem;
        font-weight: 600;
        color: #e2e8f0;
    }
    .pill-green {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.35);
        color: #34d399;
    }
    .live-dot {
        width: 7px;
        height: 7px;
        background-color: #10b981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 8px #10b981;
    }

    /* KPI Cards (Clean SaaS Border Style) */
    .kpi-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 16px 18px;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.03);
        margin-bottom: 12px;
        transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .kpi-card:hover {
        border-color: #cbd5e1;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
    }
    .kpi-eyebrow {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #64748b;
        margin-bottom: 4px;
    }
    .kpi-value {
        font-size: 1.75rem;
        font-weight: 800;
        color: #0f172a;
        line-height: 1.15;
        letter-spacing: -0.02em;
    }
    .kpi-footer {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 6px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .kpi-badge {
        padding: 1px 7px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.70rem;
    }
    .badge-success { background: #ecfdf5; color: #059669; }
    .badge-warning { background: #fffbeb; color: #d97706; }
    .badge-neutral { background: #f1f5f9; color: #475569; }

    /* Clean Content Containers */
    .content-box {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.02);
    }

    /* Callout Strips */
    .callout-strip {
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 14px;
        font-size: 0.85rem;
        line-height: 1.5;
        border: 1px solid transparent;
    }
    .callout-green { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
    .callout-amber { background: #fffbeb; border-color: #fde68a; color: #854d0e; }
    .callout-rose  { background: #fff1f2; border-color: #fecdd3; color: #9f1239; }

    /* Tab Customization */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border-radius: 6px 6px 0px 0px;
        padding: 8px 16px;
        color: #64748b;
        font-weight: 600;
        font-size: 0.88rem;
        border: 1px solid transparent;
    }
    .stTabs [aria-selected="true"] {
        background-color: #ffffff !important;
        color: #0f172a !important;
        font-weight: 700 !important;
        border: 1px solid #e2e8f0 !important;
        border-bottom: 2px solid #2563eb !important;
    }

    /* Sidebar Background & Elements */
    section[data-testid="stSidebar"] {
        background-color: #ffffff;
        border-right: 1px solid #e2e8f0;
    }

    /* BaseWeb Dropdowns & Select Popovers contrast protection */
    [data-baseweb="popover"], [data-baseweb="menu"] {
        background-color: #ffffff !important;
    }
    [data-baseweb="popover"] * {
        color: #0f172a !important;
    }

    /* Code styling */
    code {
        font-family: 'JetBrains Mono', monospace !important;
        background: #f1f5f9 !important;
        color: #0f172a !important;
        padding: 2px 5px;
        border-radius: 4px;
        font-size: 0.85em;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================
# 2. DATA LOADING PIPELINE (PARQUET STREAM-LINED & MEMORY OPTIMIZED)
# ============================================================
@st.cache_data(show_spinner=False)
def load_dns_dataset(path: str, n_rows: int = 250_000):
    """
    Memuat dataset DNS IDADX secara optimal dengan pemetaan tipe data hemat memori
    dan feature engineering terintegrasi untuk CSV maupun Parquet.
    """
    if not os.path.exists(path):
        return None, f"File tidak ditemukan di path: {path}"
    
    try:
        if path.endswith('.parquet'):
            df = pd.read_parquet(path)
            if 'ts_iso' in df.columns and 'ts_dt' not in df.columns:
                df['ts_dt'] = pd.to_datetime(df['ts_iso'], errors='coerce', utc=True)
            elif 'ts_dt' in df.columns:
                df['ts_dt'] = pd.to_datetime(df['ts_dt'], errors='coerce', utc=True)
        else:
            # Fallback membaca CSV secara chunking
            chunks = []
            total = 0
            chunk_size = 100_000
            cols_needed = ['ts_iso', 'ip_ver', 'frame_len', 'dns_len', 'qr', 'aa', 'tc', 
                           'rd', 'ra', 'ad', 'do', 'rcode', 'ancount', 'qname', 'qtype', 'qtype_name', 'edns']
            
            for chunk in pd.read_csv(path, chunksize=chunk_size, usecols=lambda c: c in cols_needed, dtype=str, low_memory=False):
                chunks.append(chunk)
                total += len(chunk)
                if total >= n_rows:
                    break
            df = pd.concat(chunks, ignore_index=True).iloc[:n_rows]
            
            for col in ['qr', 'rcode', 'ancount', 'tc', 'aa', 'rd', 'ra', 'ad', 'do', 
                        'edns', 'qtype', 'ip_ver', 'dns_len', 'frame_len']:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
            
            if 'ts_iso' in df.columns:
                df['ts_dt'] = pd.to_datetime(df['ts_iso'], errors='coerce', utc=True)

        # ------------------------------------------------------------
        # Unified Feature Engineering (Vectorized & Resilient)
        # ------------------------------------------------------------
        if 'qname_raw' not in df.columns:
            df['qname_raw'] = df['qname'].fillna('').astype(str)
            
        if 'qname_lower' not in df.columns:
            df['qname_lower'] = df['qname_raw'].str.lower().str.rstrip('.')
            
        if 'sector' not in df.columns:
            df['sector'] = classify_sld_vectorized(df['qname_lower'])
            
        if 'is_mixed' not in df.columns:
            df['is_mixed'] = df['qname_raw'].str.contains(r'[A-Z]', regex=True, na=False) & \
                             df['qname_raw'].str.contains(r'[a-z]', regex=True, na=False)
                             
        if 'is_gambling' not in df.columns:
            df['is_gambling'] = df['qname_lower'].str.contains(GAMBLING_REGEX, regex=True, na=False)
            
        if 'is_public' not in df.columns:
            df['is_public'] = is_public_sector_vectorized(df['qname_lower'])

        # ------------------------------------------------------------
        # Memory Optimization (Downcasting types)
        # ------------------------------------------------------------
        for col in ['qr', 'aa', 'tc', 'rd', 'ra', 'ad', 'do', 'edns']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype('int8')

        for col in ['rcode', 'ancount']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype('int16')

        for col in ['frame_len', 'dns_len']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype('uint16')

        for col in ['sector', 'qtype_name', 'ip_ver']:
            if col in df.columns:
                df[col] = df[col].astype('category')

        return df, None
    except Exception as e:
        return None, str(e)

# ============================================================
# 3. SIDEBAR CONFIGURATION & INTERACTIVE FILTERS
# ============================================================
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=52)
    st.markdown("### DNS Intelligence Sentinel")
    st.markdown("<span style='font-size:0.80rem; color:#64748b;'>Tim <b>datascape</b> | PeDaS 2026</span>", unsafe_allow_html=True)
    st.markdown("---")
    
    st.markdown("#### 📁 Sumber Data")
    candidate_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_sample.parquet") if "__file__" in dir() else "",
        "dns_sample.parquet",
        os.path.join(os.getcwd(), "dns_sample.parquet"),
        os.path.join(os.getcwd(), "Pedas-Final", "dns_sample.parquet"),
        "sample-dns-30min.csv",
        os.path.join(os.getcwd(), "Pedas-Final", "sample-dns-30min.csv")
    ]
    default_path = next((p for p in candidate_paths if p and os.path.exists(p)), candidate_paths[0])
    dns_path = st.text_input("Path Dataset", value=default_path, help="Path ke berkas parquet (10.8 MB) atau raw CSV")
    
    is_parquet = dns_path.endswith('.parquet')
    if is_parquet:
        st.caption("⚡ **Parquet Engine**: 334k observasi terkompresi cepat (30 menit penuh).")
    else:
        sample_size = st.slider("Jumlah Baris Sampel CSV", 50_000, 500_000, 200_000, step=50_000)

with st.spinner("Memuat telemetri log DNS IDADX..."):
    df_raw, err = load_dns_dataset(dns_path)

if err or df_raw is None:
    st.error(f"❌ Terjadi kesalahan saat membaca dataset: {err}")
    st.info("Pastikan file `dns_sample.parquet` berada di direktori aplikasi.")
    st.stop()

# Interactive Filter Controls in Sidebar
with st.sidebar:
    st.markdown("---")
    st.markdown("#### 🔍 Filter Global")
    
    # 1. Filter Rentang Waktu (Time-Range Slider) — FIX 1A: Timezone Aware Handling
    has_time = ('ts_dt' in df_raw.columns) and (df_raw['ts_dt'].notna().sum() > 20)
    time_filtered = False
    time_filter_val = None
    
    if has_time:
        min_dt = df_raw['ts_dt'].min().to_pydatetime()
        max_dt = df_raw['ts_dt'].max().to_pydatetime()
        if min_dt < max_dt:
            time_filter_val = st.slider(
                "🕒 Jendela Waktu (UTC)",
                min_value=min_dt,
                max_value=max_dt,
                value=(min_dt, max_dt),
                format="HH:mm:ss",
                help="Persempit analisis ke jendela waktu lonjakan tertentu."
            )
            time_filtered = True

    # 2. Sektor SLD filter
    all_sectors = sorted([str(s) for s in df_raw['sector'].dropna().unique()])
    selected_sectors = st.multiselect("Sektor SLD", options=all_sectors, default=all_sectors)
    
    # 3. Protocol / IP Ver filter
    ip_options = ["Semua (IPv4 & IPv6)", "IPv4 Only", "IPv6 Only"]
    selected_ip = st.selectbox("Versi IP", options=ip_options)
    
    # 4. Query Type filter
    top_qtypes = ['A', 'AAAA', 'NS', 'DS', 'TXT', 'HTTPS', 'CNAME', 'SOA', 'PTR']
    avail_qtypes = [q for q in top_qtypes if q in df_raw['qtype_name'].dropna().unique()]
    selected_qtypes = st.multiselect("Tipe Kueri (QType)", options=avail_qtypes, default=avail_qtypes)
    
    # 5. Search Box
    search_term = st.text_input("Filter Domain Teks", placeholder="Cth: go.id, slot, kemkes...")
    
    st.markdown("---")
    st.markdown("""
    <div style='font-size:0.75rem; color:#64748b; line-height:1.5;'>
        <b>Standar Regulasi:</b> RFC 1035, RFC 6891<br>
        <b>Sampling Rate:</b> 1:35 (Scale Factor x35)<br>
        <b>Blind Review:</b> Tim: datascape
    </div>
    """, unsafe_allow_html=True)

# Apply global filters (FIX 1A: ensure UTC timezone matching)
df = df_raw.copy()

if time_filtered and time_filter_val:
    t_start = pd.to_datetime(time_filter_val[0], utc=True)
    t_end = pd.to_datetime(time_filter_val[1], utc=True)
    df = df[(df['ts_dt'] >= t_start) & (df['ts_dt'] <= t_end)]

if selected_sectors:
    df = df[df['sector'].astype(str).isin(selected_sectors)]
    
if selected_ip == "IPv4 Only":
    df = df[df['ip_ver'] == 4]
elif selected_ip == "IPv6 Only":
    df = df[df['ip_ver'] == 6]
    
if selected_qtypes and 'qtype_name' in df.columns:
    df = df[df['qtype_name'].isin(selected_qtypes) | df['qtype_name'].isna()]
    
if search_term:
    df = df[df['qname_lower'].str.contains(search_term.lower(), na=False)]

# Partition Queries vs Responses
queries = df[df['qr'] == 0].copy()
responses = df[df['qr'] == 1].copy()
total_records = len(df)
total_q = len(queries)
total_r = len(responses)

if total_records == 0:
    st.warning("⚠️ Tidak ada data yang cocok dengan kombinasi filter saat ini. Silakan sesuaikan filter di sidebar.")
    st.stop()

# ============================================================
# 4. EXECUTIVE COMMAND HEADER (CLEAN OBSIDIAN)
# ============================================================
servfail_cnt = int((responses['rcode'] == 2).sum()) if total_r > 0 else 0
reliability_pct = ((total_r - servfail_cnt) / total_r * 100.0) if total_r > 0 else 100.0
server_healthy = servfail_cnt <= 5
status_badge = "SISTEM NORMAL & RESILIEN" if server_healthy else "WASPADA INSIDEN"

st.markdown(f"""
<div class="command-header">
    <div class="header-top">
        <div>
            <div class="header-title">
                🛡️ DNS Intelligence & Cyber Threat Sentinel
            </div>
            <div class="header-subtitle">
                Pusat Komando Telemetri Otoritatif IDADX • Evaluasi Kualitas Layanan (QoS RFC 1035), Kapasitas Beban QPS & Mitigasi Ancaman Siber
            </div>
            <div class="meta-pills">
                <span class="pill pill-green"><span class="live-dot"></span> {status_badge}</span>
                <span class="pill">🏷️ Tim: datascape</span>
                <span class="pill">📊 {total_records:,} Paket ({total_q:,} Kueri | {total_r:,} Respons)</span>
                <span class="pill">⏱️ Rasio Skala: x{SYSTEMATIC_SAMPLE_RATIO:.0f}</span>
            </div>
        </div>
        <div style="background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12); padding:12px 18px; border-radius:8px; text-align:right;">
            <div style="font-size:0.70rem; text-transform:uppercase; color:#94a3b8; font-weight:700; letter-spacing:0.06em;">SLA Keandalan Server</div>
            <div style="font-size:1.45rem; font-weight:800; color:#38bdf8; letter-spacing:-0.02em;">
                {reliability_pct:.4f}%
            </div>
            <div style="font-size:0.72rem; color:#cbd5e1;">Hanya {servfail_cnt} SERVFAIL dari {total_r:,} respons</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# 5. TOP 4 EXECUTIVE KPI CARDS
# ============================================================
k1, k2, k3, k4 = st.columns(4)

with k1:
    qps_val = 2902.0
    if 'ts_dt' in queries.columns and queries['ts_dt'].notna().sum() > 10:
        span_sec = (queries['ts_dt'].max() - queries['ts_dt'].min()).total_seconds()
        if span_sec > 0:
            scale_fac = SYSTEMATIC_SAMPLE_RATIO if is_parquet else 1.0
            qps_val = (total_q * scale_fac) / span_sec
    st.markdown(f"""
    <div class="kpi-card" style="border-top:3px solid #2563eb;">
        <div class="kpi-eyebrow">Throughput Nasional (QPS)</div>
        <div class="kpi-value">{qps_val:,.0f}</div>
        <div class="kpi-footer">
            <span class="kpi-badge badge-success">Stabil</span> Puncak: 3.721 QPS (Elastisitas OK)
        </div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    noerror_cnt = int((responses['rcode'] == 0).sum()) if total_r > 0 else 0
    noerror_pct = (noerror_cnt / total_r * 100) if total_r > 0 else 0
    st.markdown(f"""
    <div class="kpi-card" style="border-top:3px solid #10b981;">
        <div class="kpi-eyebrow">Resolusi Sukses (NOERROR)</div>
        <div class="kpi-value">{noerror_pct:.2f}%</div>
        <div class="kpi-footer">
            <span class="kpi-badge badge-success">Optimal</span> {noerror_cnt:,} respons terlayani
        </div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    nx_cnt = int((responses['rcode'] == 3).sum()) if total_r > 0 else 0
    nx_pct = (nx_cnt / total_r * 100) if total_r > 0 else 0
    st.markdown(f"""
    <div class="kpi-card" style="border-top:3px solid #f59e0b;">
        <div class="kpi-eyebrow">Tingkat NXDOMAIN (RFC 1035)</div>
        <div class="kpi-value">{nx_pct:.2f}%</div>
        <div class="kpi-footer">
            <span class="kpi-badge badge-warning">Audit</span> {nx_cnt:,} domain tidak ditemukan
        </div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    mixed_cnt = int(df['is_mixed'].sum()) if total_records > 0 else 0
    mixed_pct = (mixed_cnt / total_records * 100) if total_records > 0 else 0
    st.markdown(f"""
    <div class="kpi-card" style="border-top:3px solid #8b5cf6;">
        <div class="kpi-eyebrow">Paparan DNS 0x20 Probing</div>
        <div class="kpi-value">{mixed_pct:.1f}%</div>
        <div class="kpi-footer">
            <span class="kpi-badge badge-neutral">Mitigasi</span> {mixed_cnt:,} kueri mixed-case
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='margin-bottom:6px;'></div>", unsafe_allow_html=True)

# ============================================================
# 6. WORKSPACE TABS (5 POWERFUL OPERATIONAL MODULES)
# ============================================================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Ringkasan QoS (RFC 1035)",
    "⏱️ Trafik Temporal & QPS",
    "🚨 Intelijen Ancaman Siber",
    "🌐 Komparasi Sektor SLD",
    "🛡️ Sandbox Risiko Domain"
])

# ------------------------------------------------------------
# TAB 1: RINGKASAN QOS & KUALITAS LAYANAN
# ------------------------------------------------------------
with tab1:
    st.markdown("### 📊 Evaluasi Kualitas Layanan & Kepatuhan Protokol RFC 1035")
    st.caption("Pemisahan ketat volume kueri (qr=0) vs respons (qr=1) dengan denominator tepat untuk akurasi audit telemetri.")
    
    col_t1a, col_t1b = st.columns([5, 4])
    
    with col_t1a:
        rcode_counts = responses['rcode'].value_counts()
        RCODE_LABELS = {0: 'NOERROR (Sukses)', 3: 'NXDOMAIN (Tidak Ditemukan)', 1: 'FORMERR (Format Salah)', 
                        4: 'NOTIMP (Belum Didukung)', 2: 'SERVFAIL (Kegagalan Server)', 5: 'REFUSED (Ditolak)'}
        
        plot_df = pd.DataFrame({
            'Status': [RCODE_LABELS.get(int(k), f'Rcode {k}') for k in rcode_counts.index],
            'Frekuensi': rcode_counts.values,
            'Persentase': [(v / total_r * 100) for v in rcode_counts.values]
        })
        
        # FIX 1C: Explicit color mapping based on status name (no frequency-order color flipping)
        COLOR_MAP = {
            'NOERROR (Sukses)': '#10b981',
            'NXDOMAIN (Tidak Ditemukan)': '#f59e0b',
            'FORMERR (Format Salah)': '#8b5cf6',
            'SERVFAIL (Kegagalan Server)': '#ef4444',
            'REFUSED (Ditolak)': '#64748b',
            'NOTIMP (Belum Didukung)': '#94a3b8'
        }
        donut_colors = [COLOR_MAP.get(lbl, '#cbd5e1') for lbl in plot_df['Status']]
        
        fig_donut = go.Figure(data=[go.Pie(
            labels=plot_df['Status'],
            values=plot_df['Frekuensi'],
            hole=0.60,
            marker_colors=donut_colors,
            textinfo='label+percent',
            textposition='outside',
            insidetextorientation='radial',
            hovertemplate="<b>%{label}</b><br>Frekuensi: %{value:,}<br>Porsi: %{percent}<extra></extra>"
        )])
        fig_donut.update_layout(
            title="<b>Komposisi Kode Respons (Rcode) Otoritatif IDADX</b>",
            font=dict(family="Plus Jakarta Sans", size=12),
            height=340,
            margin=dict(l=20, r=20, t=40, b=20),
            showlegend=False,
            annotations=[dict(text=f"<b>{noerror_pct:.1f}%</b><br><span style='font-size:11px;color:#64748b;'>NOERROR</span>", x=0.5, y=0.5, font_size=16, showarrow=False)]
        )
        st.plotly_chart(fig_donut, use_container_width=True)
        
    with col_t1b:
        st.markdown("#### 📋 Matriks Kepatuhan RFC 1035")
        st.dataframe(
            plot_df.style.format({'Frekuensi': '{:,}', 'Persentase': '{:.3f}%'}),
            use_container_width=True,
            hide_index=True
        )
        
        st.markdown("""
        <div class="callout-strip callout-green">
            <b>Temuan Kunci QoS:</b><br>
            • <b>Zero Packet Drop:</b> Rasio kueri vs respons bernilai 1.00 : 0.997, mengonfirmasi ketiadaan antrean tertunda (*queue starvation*).<br>
            • <b>Keandalan Kelas Enterprise:</b> SERVFAIL hanya 0.0003% (jauh melampaui batas toleransi SLA global &lt;0.10%).
        </div>
        """, unsafe_allow_html=True)

    # Secondary Protocol Row
    st.markdown("#### ⚡ Profil Transport & Perluasan Protokol")
    p1, p2, p3, p4 = st.columns(4)
    with p1:
        tcp_cnt = int((df['tc'] == 1).sum()) if 'tc' in df.columns else 0
        tcp_pct = (tcp_cnt / total_records * 100)
        st.metric("Truncation Rate (tc=1)", f"{tcp_pct:.2f}%", f"{tcp_cnt:,} fallback ke TCP")
    with p2:
        edns_cnt = int((df['edns'] == 1).sum()) if 'edns' in df.columns else 0
        edns_pct = (edns_cnt / total_records * 100)
        st.metric("Adopsi EDNS0 (RFC 6891)", f"{edns_pct:.1f}%", "Buffer diperluas")
    with p3:
        do_cnt = int((queries['do'] == 1).sum()) if 'do' in queries.columns else 0
        do_pct = (do_cnt / total_q * 100) if total_q > 0 else 0
        st.metric("DO-Bit DNSSEC Kueri", f"{do_pct:.1f}%", "Validasi kriptografi aktif")
    with p4:
        large_resp = int((responses['frame_len'] >= 1000).sum()) if 'frame_len' in responses.columns else 0
        large_pct = (large_resp / total_r * 100) if total_r > 0 else 0
        st.metric("Paket Jumbo (>=1000 B)", f"{large_pct:.2f}%", f"{large_resp:,} respons masif")

    with st.expander("📖 Metodologi & Dasar Regulasi Kepatuhan Protokol (RFC 1035 & RFC 6891)"):
        st.markdown("""
        **1. Standar RFC 1035 (Domain Names - Implementation and Specification):**
        * Kualitas Layanan (QoS) DNS diukur secara ketat hanya pada paket respons (`qr=1`). Menyertakan paket kueri (`qr=0`) sebagai denominator akan mendilusi persentase status secara keliru.
        * `NOERROR (RCODE 0)`: Kueri berhasil diselesaikan dengan rekaman resource records (RR) yang sah.
        * `NXDOMAIN (RCODE 3)`: Domain authoritative name tidak terdaftar dalam zona. Sering dimanfaatkan bot pemindai untuk enumerasi brute-force.
        * `SERVFAIL (RCODE 2)`: Server gagal merespons akibat kegagalan internal atau timeout zona. Standar toleransi SLA global adalah < 0.10%.

        **2. Standar RFC 6891 (Extension Mechanisms for DNS / EDNS0):**
        * Memungkinkan klien DNS mengumumkan ukuran buffer UDP yang lebih besar dari batas tradisional 512 byte (hingga 4.096 byte), menghindari overhead koneksi TCP tiga arah (*TCP 3-way handshake*).
        """)

# ------------------------------------------------------------
# TAB 2: DINAMIKA TRAFIK & BEBAN PUNCAK (QPS)
# ------------------------------------------------------------
with tab2:
    st.markdown("### ⏱️ Dinamika Trafik Temporal & Analisis Lonjakan Beban (QPS)")
    st.caption("Monitoring throughput kueri masuk (qr=0) per detik di sepanjang jendela waktu observasi telemetri.")
    
    # FIX 2A: Aggregate strictly on queries (qr == 0) to prevent double counting
    if 'ts_dt' in queries.columns and queries['ts_dt'].notna().sum() > 20:
        ts_df = queries.set_index('ts_dt').resample('5s').size().reset_index(name='sample_count')
        scale_fac = SYSTEMATIC_SAMPLE_RATIO if is_parquet else 1.0
        ts_df['qps'] = (ts_df['sample_count'] * scale_fac) / 5.0
        ts_df['rolling_qps'] = ts_df['qps'].rolling(window=6, min_periods=1).mean()
        
        mean_qps = ts_df['qps'].mean()
        peak_qps = ts_df['qps'].max()
        
        fig_qps = go.Figure()
        # Area fill for throughput
        fig_qps.add_trace(go.Scatter(
            x=ts_df['ts_dt'], y=ts_df['qps'],
            mode='lines', name='Throughput QPS Instan',
            line=dict(color='#60a5fa', width=1.2, shape='spline'),
            fill='tozeroy', fillcolor='rgba(96, 165, 250, 0.08)',
            hovertemplate="<b>%{x|%H:%M:%S} UTC</b><br>Instan: %{y:,.0f} QPS<extra></extra>"
        ))
        fig_qps.add_trace(go.Scatter(
            x=ts_df['ts_dt'], y=ts_df['rolling_qps'],
            mode='lines', name='Moving Average (30s)',
            line=dict(color='#1e3a8a', width=2.4, shape='spline'),
            hovertemplate="<b>%{x|%H:%M:%S} UTC</b><br>MA 30s: %{y:,.0f} QPS<extra></extra>"
        ))
        fig_qps.add_hline(y=mean_qps, line_dash="dash", line_color="#10b981", 
                          annotation_text=f"Rata-rata: {mean_qps:,.0f} QPS", annotation_position="top left")
        fig_qps.add_hline(y=peak_qps, line_dash="dot", line_color="#ef4444", 
                          annotation_text=f"Puncak: {peak_qps:,.0f} QPS", annotation_position="bottom left")
        
        fig_qps.update_layout(
            title="<b>Tren Throughput Kueri Masuk (QPS) IDADX</b>",
            xaxis_title="Waktu Transaksi (UTC)",
            yaxis_title="Kueri per Detik (QPS)",
            font=dict(family="Plus Jakarta Sans", size=12),
            height=370,
            margin=dict(l=20, r=20, t=50, b=20),
            hovermode="x unified",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_qps, use_container_width=True)
    else:
        st.info("Informasi timestamp tidak memadai untuk visualisasi deret waktu.")

    col_t2a, col_t2b = st.columns(2)
    with col_t2a:
        st.markdown("#### 📑 Distribusi Tipe Kueri (QType)")
        if 'qtype_name' in queries.columns:
            qtype_dist = queries['qtype_name'].value_counts().head(8).reset_index()
            qtype_dist.columns = ['QType', 'Frekuensi']
            qtype_dist['Persentase'] = qtype_dist['Frekuensi'] / total_q * 100
            
            fig_qtype = px.bar(
                qtype_dist, x='Persentase', y='QType', orientation='h',
                text='Persentase', color='Persentase',
                color_continuous_scale=['#bfdbfe', '#1e3a8a'],
                title="Top 8 Jenis Record DNS yang Diminta"
            )
            fig_qtype.update_traces(
                texttemplate='%{text:.1f}%', textposition='outside',
                hovertemplate="<b>QType: %{y}</b><br>Porsi: %{x:.2f}%<extra></extra>"
            )
            fig_qtype.update_layout(height=280, font=dict(family="Plus Jakarta Sans"), coloraxis_showscale=False, yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_qtype, use_container_width=True)
            
    with col_t2b:
        st.markdown("#### 📦 Distribusi Ukuran Paket (Frame Length)")
        if 'frame_len' in df.columns:
            fig_hist = px.histogram(
                df, x='frame_len', color='qr', barmode='overlay', nbins=50,
                color_discrete_map={0: '#3b82f6', 1: '#10b981'},
                labels={'qr': 'Tipe (0=Q, 1=R)', 'frame_len': 'Ukuran Paket (Byte)'},
                title="Distribusi Ukuran Frame (Kueri vs Respons)"
            )
            fig_hist.update_layout(height=280, font=dict(family="Plus Jakarta Sans"), legend=dict(orientation="h", y=1.1))
            st.plotly_chart(fig_hist, use_container_width=True)

# ------------------------------------------------------------
# TAB 3: INTELIJEN ANCAMAN SIBER & DETEKSI ANOMALI
# ------------------------------------------------------------
with tab3:
    st.markdown("### 🚨 Intelijen Keamanan Siber: Pemetaan Anomali, DNS Tunneling & Pembajakan Domain")
    st.caption("Deteksi proaktif terhadap probing mixed-case DNS 0x20, eksfiltrasi DNS Tunneling, dan infiltrasi subdomain instansi publik.")
    
    col_t3a, col_t3b = st.columns([1, 1])
    
    with col_t3a:
        st.markdown("#### 🔬 DNS 0x20 Bit Probing Tracker")
        st.markdown("""
        <div class="callout-strip callout-amber">
            <b>Mekanisme DNS 0x20 (RFC 5452):</b><br>
            Resolver modern mengacak huruf besar/kecil (misal <code>wWw.KeMkEs.gO.Id</code>) untuk menambahkan entropi acak (~12 bit) guna menggagalkan serangan <i>Kaminsky Cache Poisoning</i>.<br><br>
            • <b>Frekuensi Terpapar:</b> <b>46.4%</b> kueri mengadopsi mekanisme ini.<br>
            • <b>Dampak:</b> Resolver otoritatif wajib <i>case-insensitive</i> agar tidak memicu fragmentasi memori cache.
        </div>
        """, unsafe_allow_html=True)
        
        fig_0x20 = go.Figure(data=[go.Pie(
            labels=['Mixed-Case (DNS 0x20)', 'Standard Lowercase'],
            values=[mixed_cnt, total_records - mixed_cnt],
            hole=0.6,
            marker_colors=['#3b82f6', '#e2e8f0'],
            hovertemplate="<b>%{label}</b><br>Jumlah: %{value:,}<br>Persentase: %{percent}<extra></extra>"
        )])
        fig_0x20.update_layout(height=220, margin=dict(l=10, r=10, t=10, b=10), font=dict(family="Plus Jakarta Sans"))
        st.plotly_chart(fig_0x20, use_container_width=True)
        
    with col_t3b:
        st.markdown("#### 🎯 Sentinel Subdomain Publik Terinfiltrasi Judi Online")
        compromised = df[df['is_public'] & df['is_gambling']][['qname_raw', 'sector', 'rcode']].drop_duplicates()
        
        if len(compromised) > 0:
            st.markdown(f"""
            <div class="callout-strip callout-rose">
                <b>🚨 Peringatan Ancaman Kritis:</b> Ditemukan <b>{len(compromised)}</b> domain resmi instansi publik disusupi kata kunci judi ilegal (<i>SEO Poisoning</i>).
            </div>
            """, unsafe_allow_html=True)
            
            st.dataframe(
                compromised.rename(columns={'qname_raw': 'Domain Subdomain Terkompromi', 'sector': 'Sektor SLD', 'rcode': 'Kode Status'}),
                use_container_width=True,
                hide_index=True,
                height=180
            )
            
            # Actionable IoC CSV Download
            ioc_csv = compromised.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Unduh Daftar Insiden untuk CSIRT (IoC CSV)",
                data=ioc_csv,
                file_name="ioc_compromised_domains_pedas2026.csv",
                mime="text/csv",
                help="Ekspor daftar domain untuk langsung diserahkan kepada tim tanggap insiden siber."
            )
        else:
            st.success("Tidak ada domain publik yang terindikasi disusupi pada filter saat ini.")

    # Modul Deteksi DNS Tunneling / Exfiltration (FIX 2C: label length aligned to RFC 1035)
    st.markdown("---")
    st.markdown("#### 📡 Deteksi DNS Tunneling & Eksfiltrasi Data Payload")
    tunneling_candidates = detect_dns_tunneling(df)
    n_tunnel = len(tunneling_candidates)
    
    col_tun1, col_tun2 = st.columns([1, 2])
    with col_tun1:
        st.metric("Kandidat Kueri Tunneling", f"{n_tunnel:,}", f"{(n_tunnel/total_records*100):.3f}% total trafik")
        st.markdown("""
        <div style="font-size:0.82rem; color:#64748b; line-height:1.5;">
            <b>Indikator Anomali (RFC 1035 Aligned):</b><br>
            • Kueri TXT berukuran payload <code>&gt;300 Byte</code>.<br>
            • Label subdomain tunggal <code>&ge;48 karakter</code> (mendekati batas RFC 63 oktet).<br>
            • FQDN ekstrem <code>&gt;90 karakter</code> yang mencirikan saluran C2 / kebocoran data.
        </div>
        """, unsafe_allow_html=True)
    with col_tun2:
        if n_tunnel > 0:
            st.dataframe(
                tunneling_candidates[['qname_raw', 'qtype_name', 'dns_len', 'frame_len', 'rcode']].head(10).rename(
                    columns={'qname_raw': 'Nama Kueri', 'qtype_name': 'Tipe', 'dns_len': 'DNS Len', 'frame_len': 'Frame Len', 'rcode': 'Status'}
                ),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Tidak terdeteksi kueri bermuatan payload ekstrem pada filter saat ini.")

    # Scatter of threat signals
    st.markdown("#### 🌌 Matriks Anomali: Panjang Nama Domain vs Ukuran Paket")
    sample_threat = df.sample(min(2000, len(df)), random_state=42).copy()
    sample_threat['Status Ancaman'] = np.where(sample_threat['is_gambling'], 'Pola Judi Online',
                                       np.where(sample_threat['is_mixed'], '0x20 Mixed-Case', 'Normal Traffic'))
    
    fig_scatter = px.scatter(
        sample_threat, x='dns_len', y='frame_len', color='Status Ancaman',
        color_discrete_map={'Pola Judi Online': '#ef4444', '0x20 Mixed-Case': '#3b82f6', 'Normal Traffic': '#94a3b8'},
        opacity=0.7,
        labels={'dns_len': 'Panjang DNS Payload (Byte)', 'frame_len': 'Total Frame (Byte)'},
        title="Distribusi Beban Transaksi berdasarkan Klasifikasi Ancaman"
    )
    fig_scatter.update_layout(height=320, font=dict(family="Plus Jakarta Sans"))
    st.plotly_chart(fig_scatter, use_container_width=True)

    with st.expander("📖 Metodologi Intelijen Ancaman & Standar NIST SP 800-81B"):
        st.markdown("""
        **1. Standar NIST Special Publication 800-81B (Secure Domain Name System Deployment Guide):**
        * Memandatkan mekanisme mitigasi *Cache Poisoning* dan *Spoofing* melalui randomisasi ID transaksi dan huruf besar/kecil (DNS 0x20 bit encoding).
        * Menyarankan pemantauan kontinu terhadap kueri berulang yang memicu lonjakan NXDOMAIN sebagai indikator pemindaian DGA (Domain Generation Algorithm).

        **2. DNS Tunneling & Exfiltration (MITRE ATT&CK T1071.004):**
        * Protokol DNS sering kali diizinkan melewati firewall tanpa inspeksi *deep packet inspection* (DPI).
        * Peretas memanfaatkan kueri record `TXT` atau subdomain heksadesimal/base64 acak untuk membangun saluran kontrol (*Command & Control / C2*) atau membocorkan data rahasia.
        """)

# ------------------------------------------------------------
# TAB 4: KOMPARASI SEKTOR SLD & INVESTIGASI NXDOMAIN
# ------------------------------------------------------------
with tab4:
    st.markdown("### 🌐 Analisis Komparatif Sektor SLD & Investigasi Tingkat NXDOMAIN")
    st.caption("Pemeriksaan mendalam terhadap ketahanan operasional antar-zona domain (.id, .co.id, .go.id, .sch.id, .ac.id).")
    
    # FIX 1B: observed=True to eliminate empty categories and division by zero
    sector_summary = responses.groupby('sector', observed=True).agg(
        Total_Respons=('rcode', 'count'),
        NOERROR_Count=('rcode', lambda x: (x == 0).sum()),
        NXDOMAIN_Count=('rcode', lambda x: (x == 3).sum())
    ).reset_index()
    
    sector_summary = sector_summary[sector_summary['Total_Respons'] > 0].copy()
    sector_summary['Tingkat_Sukses_%'] = sector_summary['NOERROR_Count'] / sector_summary['Total_Respons'] * 100.0
    sector_summary['Tingkat_NXDOMAIN_%'] = sector_summary['NXDOMAIN_Count'] / sector_summary['Total_Respons'] * 100.0
    sector_summary = sector_summary.sort_values('Total_Respons', ascending=False)
    
    col_t4a, col_t4b = st.columns([5, 4])
    
    with col_t4a:
        fig_sec_bar = px.bar(
            sector_summary, x='sector', y='Tingkat_NXDOMAIN_%',
            color='Tingkat_NXDOMAIN_%',
            color_continuous_scale=['#10b981', '#f59e0b', '#ef4444'],
            text='Tingkat_NXDOMAIN_%',
            title="<b>Tingkat Kegagalan NXDOMAIN per Sektor SLD (%)</b>",
            labels={'sector': 'Sektor SLD', 'Tingkat_NXDOMAIN_%': 'Rasio NXDOMAIN (%)'}
        )
        fig_sec_bar.update_traces(
            texttemplate='%{text:.2f}%', textposition='outside',
            hovertemplate="<b>%{x}</b><br>Rasio NXDOMAIN: %{y:.2f}%<extra></extra>"
        )
        fig_sec_bar.update_layout(height=340, font=dict(family="Plus Jakarta Sans"), coloraxis_showscale=False)
        st.plotly_chart(fig_sec_bar, use_container_width=True)
        
    with col_t4b:
        st.markdown("#### 🚨 Anomali Sektor Sekolah (.sch.id)")
        st.markdown("""
        <div class="callout-strip callout-rose">
            <b>Temuan Sektor Pendidikan Sekolah:</b><br>
            Sektor <code>.sch.id</code> mencatat rasio NXDOMAIN sebesar <b>3.84%</b> (hampir <b>4 kali lipat</b> sektor universitas <code>.ac.id</code> di angka 0.94%).<br><br>
            • <b>Akar Masalah:</b> Banyaknya situs sekolah yang telah mati / tidak diperpanjang, namun masih diakses otomatis oleh aplikasi rapor atau sistem administrasi kesiswaan.<br>
            • <b>Rekomendasi:</b> Perlu kampanye pembersihan domain kadaluwarsa bersama kementerian terkait demi mencegah <i>subdomain takeover</i>.
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("#### 📊 Tabel Ringkasan Kinerja Sektor SLD")
    st.dataframe(
        sector_summary.style.format({
            'Total_Respons': '{:,}',
            'NOERROR_Count': '{:,}',
            'NXDOMAIN_Count': '{:,}',
            'Tingkat_Sukses_%': '{:.2f}%',
            'Tingkat_NXDOMAIN_%': '{:.2f}%'
        }),
        use_container_width=True,
        hide_index=True
    )

# ------------------------------------------------------------
# TAB 5: SANDBOX RISIKO DOMAIN (INTERACTIVE THREAT INSPECTOR)
# ------------------------------------------------------------
with tab5:
    st.markdown("### 🛡️ Sandbox Audit Ancaman Domain (Interactive Risk Inspector)")
    st.caption("Mesin audit heuristik mandiri berbasis entropi Shannon, deteksi DGA kluster konsonan, kedalaman subdomain, dan reputasi ancaman.")
    
    st.markdown("#### ⚡ Uji Coba Cepat (Preset Domain Demo)")
    
    # State Lifecycle Fix: Bind preset buttons via callbacks to session_state
    if "domain_input" not in st.session_state:
        st.session_state["domain_input"] = "kemkes.go.id"

    def set_domain(val: str):
        st.session_state["domain_input"] = val

    preset_cols = st.columns(5)
    preset_cols[0].button("🏛️ kemkes.go.id", on_click=set_domain, args=("kemkes.go.id",), use_container_width=True)
    preset_cols[1].button("🚨 slot-gacor88.go.id", on_click=set_domain, args=("slot-gacor88.dprdpasuruankab.go.id",), use_container_width=True)
    preset_cols[2].button("🏫 sman1-bdg.sch.id", on_click=set_domain, args=("sman1-bdg.sch.id",), use_container_width=True)
    preset_cols[3].button("🎰 halobet.ac.id", on_click=set_domain, args=("halobet-asli.staidapayakumbuh.ac.id",), use_container_width=True)
    preset_cols[4].button("💳 bca-verif.my.id", on_click=set_domain, args=("verifikasi-bca-login.my.id",), use_container_width=True)
        
    eval_domain = st.text_input("Ketikkan Domain / Subdomain untuk Diaudit:", key="domain_input")
    
    audit_res = calculate_domain_risk(eval_domain)
    
    col_res1, col_res2, col_res3 = st.columns([4, 3, 5])
    
    with col_res1:
        score_val = audit_res['score']
        gauge_color = "#10b981" if score_val <= 35 else "#f59e0b" if score_val <= 70 else "#ef4444"
        
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score_val,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': f"<b>{audit_res['severity']}</b>", 'font': {'size': 15, 'family': 'Plus Jakarta Sans', 'color': gauge_color}},
            number={'suffix': "/100", 'font': {'size': 28, 'weight': 'bold', 'color': gauge_color}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#cbd5e1"},
                'bar': {'color': gauge_color, 'thickness': 0.28},
                'bgcolor': "white",
                'borderwidth': 1,
                'bordercolor': "#e2e8f0",
                'steps': [
                    {'range': [0, 35], 'color': '#ecfdf5'},
                    {'range': [35, 70], 'color': '#fffbeb'},
                    {'range': [70, 100], 'color': '#fef2f2'}
                ]
            }
        ))
        fig_gauge.update_layout(height=260, margin=dict(l=15, r=15, t=40, b=15))
        st.plotly_chart(fig_gauge, use_container_width=True)
        
    with col_res2:
        st.markdown("#### 📐 Parameter Leksikal")
        cdn_badge = "✅ Terverifikasi CDN/Cloud" if audit_res['is_cdn_whitelisted'] else "Bukan CDN"
        st.markdown(f"""
        <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; padding:14px; font-size:0.82rem; line-height:1.7;">
            • Entropi Karakter: <b>{audit_res['entropy']:.2f} bit</b><br>
            • Panjang String: <b>{audit_res['length']} huruf</b><br>
            • Tingkat Titik (Dots): <b>{audit_res['dots']} level</b><br>
            • Tanda Hubung (Hyphens): <b>{audit_res['hyphens']} buah</b><br>
            • Digit Angka: <b>{audit_res['digits']} karakter</b><br>
            • Rasio Vokal: <b>{audit_res['vowel_ratio']:.1%}</b><br>
            • Kluster Konsonan: <b>{audit_res['consonant_cluster']} huruf</b><br>
            • Infrastruktur: <b>{cdn_badge}</b>
        </div>
        """, unsafe_allow_html=True)
        
    with col_res3:
        st.markdown("#### 📋 Temuan Audit & Rekomendasi Mitigasi")
        if audit_res['reasons']:
            for r in audit_res['reasons']:
                st.markdown(f"• {r}")
                
            if audit_res['score'] >= 71:
                st.markdown("""
                <div class="callout-strip callout-rose" style="margin-top:10px;">
                    <b>🛡️ Playbook Insiden Kritis (NIST SP 800-81B / RFC 1035):</b><br>
                    1. Aktifkan penahanan darurat via <b>DNS RPZ Sinkhole</b> nasional.<br>
                    2. Terbitkan peringatan CSIRT untuk sanitasi file root server CMS.<br>
                    3. Hapus entri rekaman DNS palsu (A / CNAME) dari Authoritative Zone.
                </div>
                """, unsafe_allow_html=True)
            elif audit_res['score'] >= 36:
                st.markdown("""
                <div class="callout-strip callout-amber" style="margin-top:10px;">
                    <b>🛡️ Playbook Waspada:</b> Terapkan Response Rate Limiting (RRL) dan audit riwayat registrasi WHOIS domain.
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="callout-strip callout-green" style="margin-top:10px;">
                <b>🟢 Domain Aman & Wajar:</b> Profil string leksikal dan reputasi domain berada pada batas normal standar RFC 1035. Tidak ditemukan indikasi bahaya.
            </div>
            """, unsafe_allow_html=True)

    with st.expander("📖 Landasan Teoretis: Formula Entropi Shannon & Arsitektur Deteksi DGA"):
        st.markdown("""
        **1. Formula Entropi Shannon (Claude Shannon, 1948):**
        $$H(X) = -\\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
        * Entropi mengukur derajat keacakan distribusi karakter dalam sebuah string leksikal.
        * Domain kata dalam bahasa manusia (misal: `kemkes`, `universitas`) memiliki entropi rendah ($H < 3.2$ bit) karena huruf-huruf tertentu muncul dengan frekuensi yang dapat diprediksi.
        * Domain DGA (*Domain Generation Algorithm*) acak menghasilkan entropi tinggi ($H > 3.85$ bit).

        **2. Reduksi False Positive (Whitelist CDN & Analisis Fonetik):**
        * Server CDN resmi (seperti `d3c33hcgiwev3.cloudfront.net`) sering kali memiliki string hash leksikal acak. Modul ini menerapkan *whitelist prefix/suffix* untuk mencegah kesalahan klasifikasi (*false positive*).
        * Sinyal kluster konsonan berturut-turut ($\ge 4$ atau $\ge 5$ karakter tanpa diselingi vokal) menjadi penguat independen deteksi botnet.
        """)

# ============================================================
# 7. FOOTER
# ============================================================
st.markdown("---")
st.markdown(f"""
<div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; color:#64748b; font-size:0.78rem; padding:4px 0;">
    <div>
        <b>DNS Analytics Dashboard</b> • Tim: <b>datascape</b> • PeDaS 2026 Final
    </div>
    <div>
        Kepatuhan Protokol RFC 1035 & RFC 6891 • IDADX .id Registry Telemetry Log
    </div>
</div>
""", unsafe_allow_html=True)

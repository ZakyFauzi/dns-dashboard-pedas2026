"""
Heuristics & Cyber Threat Intelligence Module — Tim datascape
PeDaS 2026 Final | Rule-Based Telemetry Analytics Engine
Standards: RFC 1035, RFC 6891, RFC 5452, NIST SP 800-81B
"""

import re
import math
from collections import Counter
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np

# ============================================================
# 1. KONSTANTA & POLA REGEX TERKOMPILASI
# ============================================================
# Rasio sampling sistematik data log IDADX 30 menit (1 dari 35 baris diekstrak)
# Digunakan untuk merekonstruksi total throughput kueri nasional (QPS) sebenarnya.
SYSTEMATIC_SAMPLE_RATIO: float = 35.0

# Pola regex kata kunci perjudian daring (Compiled Regex for Vectorized Search)
GAMBLING_REGEX = re.compile(
    r'(togel|slot|casino|judi|poker|bet|ontogel|bandar|sbobet|gacor|maxwin|habanero|pragmatic|zeus|olympus|depo|wd)',
    re.IGNORECASE
)

# Whitelist infrastruktur Cloud & CDN terpercaya untuk mereduksi False Positive DGA
CDN_WHITELIST = (
    'cloudfront.net', 'akamai.net', 'akamaiedge.net', 'cloudflare.com',
    'googleapis.com', 'google.com', 'azure.com', 'azureedge.net',
    'trafficmanager.net', 'amazonaws.com', 'fastly.net', 'github.io',
    'windows.net', 'msedge.net', 'akadns.net'
)

# Pola token terisolasi untuk brand perbankan/finansial (mencegah false positive pada 'danabos' atau 'danadesa')
BANKING_REGEX = re.compile(
    r'(?:^|[\.-])(bca|klikbca|mandiri|bri|bni|cimb|gopay|ovo|linkaja|shopeepay|dana)(?:[\.-]|$)',
    re.IGNORECASE
)

LEGIT_BANKING_DOMAINS = (
    'bca.co.id', 'bankmandiri.co.id', 'bri.co.id', 'bni.co.id', 
    'cimbniaga.co.id', 'gopay.co.id', 'dana.id', 'klikbca.com'
)

# Pola deteksi label tunggal sangat panjang (>= 48 karakter) mendekati batas RFC 1035 (63 oktet)
LABEL_48_REGEX = re.compile(r'(?:^|\.)[^.]{48,}(?:\.|$)')

# ============================================================
# 2. KLASIFIKASI SEKTOR SLD (SECOND-LEVEL DOMAIN)
# ============================================================
def classify_sld(name: str) -> str:
    """Mengklasifikasikan nama domain ke dalam sektor SLD Indonesia."""
    if not isinstance(name, str):
        return 'Lainnya'
    n = name.lower().rstrip('.')
    if n.endswith('.co.id'):
        return 'Komersial (.co.id)'
    elif n.endswith('.go.id'):
        return 'Pemerintah (.go.id)'
    elif n.endswith('.ac.id'):
        return 'Universitas (.ac.id)'
    elif n.endswith('.sch.id'):
        return 'Sekolah (.sch.id)'
    elif n.endswith('.or.id'):
        return 'Organisasi (.or.id)'
    elif n.endswith('.net.id'):
        return 'Internet (.net.id)'
    elif n.endswith('.my.id'):
        return 'Personal (.my.id)'
    elif n.endswith('.web.id'):
        return 'Web (.web.id)'
    elif n.endswith('.id'):
        return 'Bare (.id)'
    else:
        return 'Lainnya'

def classify_sld_vectorized(series: pd.Series) -> pd.Series:
    """Klasifikasi SLD tervektorisasi untuk performa tinggi di atas ratusan ribu baris."""
    s = series.astype(str).str.lower().str.rstrip('.')
    conditions = [
        s.str.endswith('.co.id'),
        s.str.endswith('.go.id'),
        s.str.endswith('.ac.id'),
        s.str.endswith('.sch.id'),
        s.str.endswith('.or.id'),
        s.str.endswith('.net.id'),
        s.str.endswith('.my.id'),
        s.str.endswith('.web.id'),
        s.str.endswith('.id')
    ]
    choices = [
        'Komersial (.co.id)',
        'Pemerintah (.go.id)',
        'Universitas (.ac.id)',
        'Sekolah (.sch.id)',
        'Organisasi (.or.id)',
        'Internet (.net.id)',
        'Personal (.my.id)',
        'Web (.web.id)',
        'Bare (.id)'
    ]
    return pd.Series(np.select(conditions, choices, default='Lainnya'), index=series.index, dtype='category')

def is_public_sector(s: str) -> bool:
    """Mengecek apakah domain termasuk sektor publik/institusi resmi (.go.id, .ac.id, .sch.id)."""
    if not isinstance(s, str):
        return False
    sl = s.lower().rstrip('.')
    return sl.endswith(('.go.id', '.ac.id', '.sch.id'))

def is_public_sector_vectorized(series: pd.Series) -> pd.Series:
    """Pengecekan sektor publik tervektorisasi."""
    s = series.astype(str).str.lower().str.rstrip('.')
    return s.str.endswith(('.go.id', '.ac.id', '.sch.id'))

# ============================================================
# 3. ANALISIS SINYAL DGA & ENTROPI SHANNON
# ============================================================
def calculate_shannon_entropy(s: str) -> float:
    """
    Menghitung entropi informasi Shannon: H(X) = -sum(P(x) * log2(P(x))).
    String acak DGA umumnya memiliki entropi > 3.8 bit.
    """
    if not s:
        return 0.0
    length = len(s)
    probs = [count / length for count in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def analyze_dga_signals(label: str) -> Tuple[float, int]:
    """
    Menganalisis rasio vokal-konsonan dan kluster konsonan berturut-turut.
    Nama domain hasil DGA acak memiliki kepadatan vokal sangat rendah (<15%) 
    atau deretan konsonan berurutan >= 4 karakter.
    """
    chars = [c for c in label.lower() if c.isalpha()]
    if not chars:
        return 0.5, 0
    vowels = sum(1 for c in chars if c in 'aeiou')
    vowel_ratio = vowels / len(chars)
    
    consonant_matches = re.findall(r'[^aeiou0-9\.\-_]+', label.lower())
    max_consonants = max((len(m) for m in consonant_matches), default=0)
    return vowel_ratio, max_consonants

# ============================================================
# 4. MESIN AUDIT RISIKO DOMAIN (RISK INSPECTION ENGINE)
# ============================================================
def calculate_domain_risk(domain_str: str) -> Dict[str, Any]:
    """
    Audit komprehensif tingkat risiko keamanan domain berbasis:
    - Entropi Shannon (RFC 1035 leksikal)
    - Rasio vokal & kluster konsonan DGA
    - Reputasi kata kunci terlarang (Judi online / Phishing brand)
    - Kedalaman subdomain & manipulasi karakter
    - Whitelist mitigasi false positive Cloud / CDN
    """
    dom = str(domain_str).strip().lower().rstrip('.')
    if not dom:
        return {
            'domain': '', 'score': 0, 'severity': 'Normal',
            'entropy': 0.0, 'length': 0, 'dots': 0, 'hyphens': 0, 'digits': 0,
            'vowel_ratio': 0.5, 'consonant_cluster': 0, 'is_cdn_whitelisted': False,
            'reasons': [], 'mitigation': []
        }
        
    length = len(dom)
    entropy = calculate_shannon_entropy(dom)
    dots = dom.count('.')
    hyphens = dom.count('-')
    digits = sum(c.isdigit() for c in dom)
    vowel_ratio, consonant_cluster = analyze_dga_signals(dom)
    
    # 1. Cek Whitelist CDN / Cloud
    is_cdn_whitelisted = any(dom.endswith(cdn) for cdn in CDN_WHITELIST)
    
    score = 10
    reasons = []
    mitigation = []
    
    # 2. Pengecekan Eksploitasi Sektor Publik vs Kata Kunci Judi
    has_gambling = bool(GAMBLING_REGEX.search(dom))
    is_public = is_public_sector(dom)
    
    if is_public and has_gambling:
        score += 75
        reasons.append("🚨 Pembajakan reputasi domain instansi resmi publik (.go.id/.ac.id/.sch.id) oleh sindikat judi online (SEO Poisoning).")
        mitigation.append("Isolasi rekaman DNS (A/CNAME tidak sah) dari panel authoritative zone.")
        mitigation.append("Lakukan pembersihan file web-shell injeksi pada direktori root CMS instansi.")
        mitigation.append("Aktifkan perlindungan DNS RPZ Sinkhole nasional untuk proteksi instan masyarakat.")
    elif has_gambling:
        score += 55
        reasons.append("⚠️ Mengandung kata kunci perjudian daring terlarang (slot/togel/casino/gacor).")
        mitigation.append("Blokir resolusi kueri pada DNS Resolver Otoritatif / Trust Positif.")
        
    # 3. Pengecekan Phishing Brand Perbankan / E-Wallet (Mencegah false positive pada instansi publik/dana bantuan)
    has_bank = bool(BANKING_REGEX.search(dom))
    is_legit_bank = any(dom.endswith(legit) for legit in LEGIT_BANKING_DOMAINS)
    
    if has_bank and not is_legit_bank and not is_public:
        score += 65
        reasons.append("⚠️ Pemalsuan identitas brand finansial / perbankan nasional (Indikasi Kuat Phishing Kredensial).")
        mitigation.append("Laporkan ke CSIRT Finansial dan registrar domain terkait untuk takedown segera.")
        
    # 4. Sinyal Leksikal DGA (Domain Generation Algorithm)
    if is_cdn_whitelisted:
        reasons.append("ℹ️ Domain terverifikasi dalam Whitelist Infrastruktur Cloud/CDN resmi (Entropi tinggi merupakan penanda routing hash).")
    else:
        if entropy > 3.85 and length > 16:
            score += 25
            reasons.append(f"Entropi string acak tinggi ({entropy:.2f} bit) — pola leksikal khas algoritma bot DGA.")
        if consonant_cluster >= 5:
            score += 35
            reasons.append(f"Deretan kluster {consonant_cluster} konsonan berurutan tanpa vokal — indikasi kuat string acak bot DGA.")
        elif consonant_cluster == 4:
            score += 20
            reasons.append(f"Terdapat 4 konsonan berurutan — karakteristik leksikal tidak wajar.")
        elif vowel_ratio < 0.15 and length >= 8:
            score += 20
            reasons.append(f"Rasio huruf vokal sangat rendah ({vowel_ratio:.1%}) — karakteristik string leksikal terkomputerisasi.")
            
    # 5. Kedalaman Subdomain & Manipulasi Karakter
    if digits >= 4:
        score += 15
        reasons.append(f"Terdapat {digits} digit angka acak pada subdomain.")
    if hyphens >= 3:
        score += 15
        reasons.append(f"Penggunaan karakter tanda hubung berulang ({hyphens} hyphen).")
    if dots >= 4:
        score += 15
        reasons.append(f"Kedalaman subdomain ekstrem ({dots} dot levels) — potensi teknik DNS tunneling.")
        
    # Normalisasi Skor
    if is_cdn_whitelisted and not has_gambling and not has_bank:
        score = min(score, 25)
        
    score = min(100, max(5, score))
    
    if score >= 71:
        severity = "Kritis (High Risk)"
    elif score >= 36:
        severity = "Waspada (Medium Risk)"
    else:
        severity = "Aman (Low Risk)"
        
    return {
        'domain': dom,
        'score': score,
        'severity': severity,
        'entropy': entropy,
        'length': length,
        'dots': dots,
        'hyphens': hyphens,
        'digits': digits,
        'vowel_ratio': vowel_ratio,
        'consonant_cluster': consonant_cluster,
        'is_cdn_whitelisted': is_cdn_whitelisted,
        'reasons': reasons,
        'mitigation': mitigation
    }

# ============================================================
# 5. DETEKSI DNS TUNNELING / EXFILTRATION (RFC 1035 ALIGNED)
# ============================================================
def detect_dns_tunneling(df: pd.DataFrame) -> pd.DataFrame:
    """
    Mendeteksi kandidat kueri DNS Tunneling atau eksfiltrasi data payload:
    - Kueri TXT dengan panjang payload dns_len > 300 byte (mendekati batas EDNS)
    - Atau label tunggal >= 48 karakter (mendekati batas maksimal RFC 1035: 63 oktet)
    - Atau total FQDN > 90 karakter dengan muatan string acak.
    """
    if 'qtype_name' not in df.columns or 'dns_len' not in df.columns or 'qname_raw' not in df.columns:
        return pd.DataFrame()
        
    cond_txt_large = (df['qtype_name'] == 'TXT') & (df['dns_len'] > 300)
    
    s_raw = df['qname_raw'].astype(str)
    cond_long_label = s_raw.str.contains(LABEL_48_REGEX, regex=True, na=False)
    cond_fqdn_extreme = s_raw.str.len() > 90
    
    suspicious = df[cond_txt_large | cond_long_label | cond_fqdn_extreme].copy()
    return suspicious

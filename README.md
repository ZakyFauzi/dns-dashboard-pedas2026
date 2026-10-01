# 🛡️ DNS Analytics & Infrastructure Security Dashboard
### Pesta Data Nasional (PeDaS) 2026 — Babak Final
**Tim:** `datascape` | **Dataset:** IDADX DNS Telemetry Logs | **Standar Rujukan:** RFC 1035, RFC 6891

---

## 🌟 Ringkasan Eksekutif

Dashboard Business Analytics & Keamanan Infrastruktur DNS ini dirancang khusus untuk menganalisis log transaksi DNS skala besar dari ekosistem IDADX (.id registry). Dashboard menyajikan visualisasi data interaktif, pemantauan kualitas layanan (*Quality of Service / QoS*), deteksi anomali trafik siber, audit subdomain berisiko, serta simulator interaktif penilaian ancaman domain secara *real-time*.

### Karakteristik Kunci Sistem:
- 💡 **High-Contrast Enterprise Light Mode**: Desain bersih (*clean modern interface*) dengan kontras tinggi (latar putih/slate-50, tipografi charcoal gelap, aksen navy blue & emerald) yang nyaman dibaca dan ramah presentasi.
- ⚡ **100% Rule-Based & Offline**: Bebas dari dependensi model berbayar atau API eksternal yang lambat/rentan putus, memastikan eksekusi deterministik, stabil, dan bebas error (*zero-runtime error*).
- 🚀 **Optimasi Parquet Berperforma Tinggi**: Dataset log mentah 2.4 GB (~11.6 juta baris) telah dirampingkan secara sistematis (*systematic sampling* sepanjang 30 menit penuh) menjadi format **Apache Parquet (10.8 MB)**. Hasilnya: aplikasi memuat dalam **0.37 detik** dan hanya menggunakan **~46 MB RAM** (sangat aman di Streamlit Community Cloud gratis).
- 📜 **Kepatuhan Protokol Ketat**: Menghitung metrik sesuai kaidah teknis RFC 1035—memisahkan kueri (`qr=0`) dari respons (`qr=1`), menggunakan denominator yang tepat pada penghitungan persentase respons code (`rcode`), serta mengaudit mekanisme keamanan DNS 0x20.

---

## 📑 Arsitektur 6 Tab Analisis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       DNS Analytics Dashboard (datascape)                   │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬───────┤
│ Tab 1: QoS  │ Tab 2: QPS  │ Tab 3: Cyber│ Tab 4: SLD  │ Tab 5: Risk │ Tab 6:│
│ & Rcode     │ & Temporal  │ & Anomaly   │ & NXDOMAIN  │  Simulator  │ Brief │
└─────────────┴─────────────┴─────────────┴─────────────┴─────────────┴───────┘
```

1. 📊 **Tab 1: QoS & Analisis Rcode**
   - KPI Utama: Total volume transaksi, rasio kueri vs respons, success rate (NOERROR), error rate (NXDOMAIN, SERVFAIL, FORMERR).
   - Bar chart & tabel distribusi kode respons berdasarkan RFC 1035 dengan denominator total respons.
   - Audit anomali protocol: Truncation flag (`tc=1`), respons jumbo (>=1.000 Byte), dan dukungan EDNS0 buffer.

2. ⏱️ **Tab 2: Trafik & Temporal (QPS & Throughput)**
   - Line chart throughput transaksi per detik (Queries Per Second / QPS) di sepanjang jendela waktu observasi 30 menit.
   - Deteksi lonjakan beban puncak (*peak load detection*) dan kalkulasi *burst factor*.
   - Sebaran tipe kueri DNS: Record A (IPv4), AAAA (IPv6), NS, DS (DNSSEC), TXT, HTTPS, dsb.

3. 🚨 **Tab 3: Anomali & Cyber Security**
   - **DNS 0x20 Bit Probing**: Deteksi mixed-case query (misal: `wWw.kEmKeS.gO.Id`) sebagai mekanisme mitigasi *cache poisoning* (ditemukan pada 46.4% kueri).
   - **Audit Subdomain Terkompromi**: Deteksi otomatis subdomain instansi publik (`.go.id`, `.ac.id`, `.sch.id`) yang disusupi pola judi online (*gambling keyword injection*).
   - Tabel investigasi interaktif domain mencurigakan beserta status rcode dan panjang paket.

4. 🌐 **Tab 4: Sektor SLD & Tingkat Kegagalan (NXDOMAIN)**
   - Perbandingan distribusi trafik pada seluruh Second-Level Domain (.id, .co.id, .go.id, .ac.id, .sch.id, .net.id, .my.id).
   - Analisis tingginya rasio domain tidak ditemukan (NXDOMAIN) pada sektor institusi pendidikan / sekolah (`.sch.id` mencapai 3.84%).
   - Peringkat Top Domain dengan kegagalan resolusi terbanyak untuk tindakan *typosquatting cleanup*.

5. 🛡️ **Tab 5: Simulator Risiko Domain Interaktif**
   - Alat audit domain mandiri: masukkan domain apa saja untuk dianalisis oleh mesin heuristik.
   - Menghitung Shannon Entropy karakter, kedalaman subdomain (*dot depth*), rasio digit/vokal, serta deteksi kata kunci phishing/malware.
   - Skor Risiko Keamanan 0–100 (Aman, Waspada, Berbahaya) lengkap dengan rincian faktor risiko dan rekomendasi mitigasi teknis.

6. 📑 **Tab 6: Rekomendasi Strategis & Briefing Operasional**
   - Matriks rekomendasi strategis R1–R5 (Deployment DNSSEC, Caching Resolver Tuning, DNS Hygiene Kampanye Sekolah, Penertiban Defacement Publik, EDNS Buffer Standardization).
   - Generator briefing operasional otomatis berbasis aturan (*rule-based narrative*) untuk tim Network Operations Center (NOC) & SOC.

---

## 📁 Struktur Direktori Repositori

```
dns-dashboard-pedas2026/
├── app.py                 # File aplikasi utama Streamlit (entry point)
├── dns_dashboard.py       # File alternatif dashboard
├── dns_sample.parquet     # Dataset teringkas representatif 30 menit (10.8 MB)
├── requirements.txt       # Dependensi Python minimal (streamlit, pandas, numpy, plotly, pyarrow)
├── .gitignore             # File exclusion untuk cache Python
└── README.md              # Dokumentasi lengkap repositori
```

---

## 💻 Cara Menjalankan Secara Lokal

### Prasyarat
- Python 3.10 atau lebih baru (Disarankan Python 3.11 / 3.12).

### Langkah Instalasi & Eksekusi:
1. Clone repositori ini:
   ```bash
   git clone https://github.com/ZakyFauzi/dns-dashboard-pedas2026.git
   cd dns-dashboard-pedas2026
   ```

2. Pasang dependensi yang dibutuhkan:
   ```bash
   pip install -r requirements.txt
   ```

3. Jalankan dashboard via Streamlit:
   ```bash
   streamlit run app.py
   ```

4. Buka peramban (*browser*) Anda pada tautan lokal yang ditampilkan:
   `http://localhost:8501`

---

## ☁️ Panduan Deploy Gratis ke Streamlit Community Cloud

Dashboard ini telah dioptimasi secara khusus agar **100% kompatibel dan ringan** saat di-deploy ke **Streamlit Community Cloud (Gratis)**:

1. Pastikan seluruh folder ini telah di-push ke akun GitHub Anda (misal: `https://github.com/ZakyFauzi/dns-dashboard-pedas2026`).
2. Kunjungi [share.streamlit.io](https://share.streamlit.io) dan masuk (*Sign In*) menggunakan akun GitHub Anda.
3. Klik tombol **"New app"** di pojok kanan atas.
4. Masukkan konfigurasi aplikasi:
   - **Repository:** `ZakyFauzi/dns-dashboard-pedas2026`
   - **Branch:** `main`
   - **Main file path:** `app.py`
5. Klik **"Deploy!"**.
6. Dalam waktu ~1 menit, dashboard Anda akan aktif secara publik dengan tautan resmi (contoh: `https://dns-dashboard-pedas2026.streamlit.app`).

---

## 📊 Spesifikasi Dataset

| Parameter | Keterangan |
|---|---|
| **Sumber Data Asli** | IDADX DNS Traffic Log (PeDaS 2026 Babak Final) |
| **Durasi Observasi** | 30 Menit Penuh (`2026-08-19 07:49:57` s.d. `08:19:57 UTC`) |
| **Metode Sampling** | *Systematic Sampling* (1 dari setiap 35 baris di sepanjang timeline) |
| **Jumlah Baris** | 334.688 baris log |
| **Format Berkas** | Apache Parquet (Kompresi Gzip/Snappy) |
| **Ukuran Berkas** | 10.8 MB (sangat hemat bandwidth & memori) |
| **Waktu Pemuatan** | ~0.37 detik |

---

## 👥 Tim Peserta

**Tim datascape** — Babak Final PeDaS 2026 (Pesta Data Nasional)  

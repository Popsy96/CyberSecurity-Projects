# 🌐 Australia Cyber Threat Intelligence (CTI) Dashboard

> **AAHE Poster Competition Winner — June 2026**  
> CYB815 Cybersecurity Capstone | Group 14 | Australasian Academy of Higher Education (AAHE)

---

## 📌 Overview

A real-time **Cyber Threat Intelligence Dashboard** designed for Australian SOC operations. The dashboard integrates four live OSINT threat feeds, enriches IOC data, and maps threats across five industry frameworks — providing actionable intelligence for security analysts.

Built as part of the Master of Cybersecurity capstone at AAHE, this project won the **AAHE Poster Competition 2026**.

---

## 🏆 Recognition

| Award | Details |
|:---|:---|
| 🏆 AAHE Poster Competition Winner | June 2026 |
| 📄 Conference Paper | In progress — co-authored with Dr. Haafizah Rameeza Shaukat |

---

## 🔴 Live OSINT Feeds

| Feed | Description |
|:---|:---|
| **AlienVault OTX** | Open Threat Exchange — IOC pulses and threat indicators |
| **AbuseIPDB** | Malicious IP reputation database |
| **URLhaus** | Malicious URL and malware distribution tracking |
| **Feodo Tracker** | Botnet C2 server tracking |

---

## 📊 Framework Mapping

| Framework | Purpose |
|:---|:---|
| **MITRE ATT&CK** | Tactic and technique classification |
| **NIST CSF** | Cybersecurity function mapping |
| **ASD Essential Eight** | Australian security control alignment |
| **CVSS v3.1** | Vulnerability severity scoring |
| **ISO 27001** | Information security control mapping |

---

## 🛠️ Tech Stack

```
Backend          →  Python · SQLite
Frontend         →  HTML · CSS · JavaScript
Visualisation    →  Chart.js · Leaflet.js · Plotly
OSINT APIs       →  AlienVault OTX · AbuseIPDB · URLhaus · Feodo Tracker
Frameworks       →  MITRE ATT&CK · NIST CSF · ASD Essential Eight · CVSS v3.1 · ISO 27001
```

---

## 📁 Project Structure

```
Cyber-Threat-Intelligence-Dashboard/
│
├── main.py                    ← Entry point — runs all feeds and processing
├── Raw_feeds.py               ← Raw feed testing scripts
├── config.example.py          ← API key template (copy to config.py)
├── requirements.txt           ← Python dependencies
├── LICENSE                    ← MIT License
│
├── feeds/                     ← OSINT feed integrations
│   ├── otx_feed.py            ← AlienVault OTX
│   ├── abuseipdb_feed.py      ← AbuseIPDB
│   ├── urlhaus_feed.py        ← URLhaus
│   ├── feodo_feed.py          ← Feodo Tracker
│   └── base.py                ← Base feed class
│
├── processing/                ← Data normalisation & enrichment
│   ├── normalise.py           ← IOC normalisation
│   ├── classifier.py          ← Threat classification
│   ├── cvss.py                ← CVSS scoring
│   ├── mitre.py               ← MITRE ATT&CK mapping
│   ├── nist.py                ← NIST CSF mapping
│   ├── location.py            ← Geolocation (AU-first)
│   └── response.py            ← Incident response mapping
│
├── database/                  ← SQLite database management
│   └── db.py                  ← Database operations
│
└── dashboard/                 ← Frontend
    ├── index.html             ← Main dashboard (5 tabs)
    ├── streamlit_app.py       ← Streamlit alternative view
    ├── css/
    │   └── style.css          ← Dashboard styling
    └── js/
        ├── main.js            ← Core dashboard logic
        ├── charts.js          ← Threat visualisations
        ├── table.js           ← IOC data tables
        ├── map.js             ← Geolocation threat map
        └── ir.js              ← Incident response view
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- API keys for OTX, AbuseIPDB, URLhaus

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Popsy96/CyberSecurity-Projects.git
cd CyberSecurity-Projects/Cyber-Threat-Intelligence-Dashboard

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys
cp config.example.py config.py
# Edit config.py and add your API keys

# 5. Run the dashboard
python main.py
```

### Running the Dashboard

```bash
# Run main data collection
python main.py

# Open dashboard in browser
# Open dashboard/index.html in your browser
```

---

## ⚙️ Key Technical Decisions

| Decision | Rationale |
|:---|:---|
| 100 IOC cap per OTX pulse | Prevents API rate limiting and data overload |
| AU-first geolocation strategy | Prioritises Australian threat context |
| AEST timezone conversion | Localises threat timestamps for Australian analysts |
| Three-step CVSS calculation | Base → Temporal → Environmental scoring |
| SQLite backend | Lightweight, portable, no server required |

---

## 👥 Team

| Role | Member |
|:---|:---|
| Project Manager & Dashboard Lead | Poojit Kasina (Popsy) |
| Supervisor | Dr. Haafizah Rameeza Shaukat |
| Institution | Australasian Academy of Higher Education (AAHE) |

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](./LICENSE) for details.

---

## 🤝 Connect

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Poojit_Kasina-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/poojitkasina-aus23)
[![Email](https://img.shields.io/badge/Email-poojitkasina@gmail.com-D14836?style=flat-square&logo=gmail&logoColor=white)](mailto:poojitkasina@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-Popsy96-black?style=flat-square&logo=github&logoColor=white)](https://github.com/Popsy96)

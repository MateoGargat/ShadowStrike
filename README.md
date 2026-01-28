# ShadowStrike

**AI-Powered Active Reconnaissance and Penetration Testing Framework**

ShadowStrike is an offensive security tool designed for professional penetration testers and red team operators. It combines aggressive active scanning with AI-driven vulnerability analysis (Mixture of Agents + GraphRAG) to identify, prioritize, and exploit attack surfaces.

**⚠️ CRITICAL WARNING: Active reconnaissance directly interacts with target systems. This tool is for AUTHORIZED penetration testing only. Unauthorized use is illegal and may result in criminal prosecution.**

---

## Philosophy

Unlike passive OSINT tools, ShadowStrike is built **offense-first**:
- **Active scanning by default** — Direct interaction with targets to discover vulnerabilities
- **Exploitation-focused** — AI prioritizes findings by exploitability, not just severity
- **Attack path mapping** — Automated discovery of multi-hop compromise routes
- **Red team ready** — Stealth modes, evasion techniques, and export to Metasploit

Passive intelligence gathering is available as an optional **recon supplement** for target enumeration, but the core value is in active vulnerability assessment.

---

## Table of Contents

- [Features](#features)
- [Active Scanners](#active-scanners)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [AI Analysis](#ai-analysis)
- [GraphRAG Attack Path Analysis](#graphrag-attack-path-analysis)
- [Usage Scenarios](#usage-scenarios)
- [Scan Profiles](#scan-profiles)
- [Export & Integration](#export--integration)
- [Legal & Ethics](#legal--ethics)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

---

## Features

### 🎯 Active Exploitation
- **10+ integrated scanners** — nmap, nuclei, nikto, gobuster, whatweb, wafw00f, sslscan, dnsrecon, ffuf, wpscan
- **Automatic service enumeration** — Ports, versions, OS fingerprinting, web technologies
- **Vulnerability discovery** — CVE detection, misconfigurations, weak ciphers, exposed admin panels
- **Web attack surface mapping** — Directory brute-forcing, parameter fuzzing, WAF detection
- **WordPress/CMS targeting** — Plugin enumeration, known exploits, user discovery

### 🤖 AI-Powered Analysis
- **Mixture of Agents (MoA)** — Multi-LLM consensus for reduced false positives
- **Exploit prioritization** — Ranks findings by exploitability, impact, and ease of weaponization
- **Attack scenario generation** — AI suggests exploitation sequences and pivot paths
- **GraphRAG integration** — Extracts attack graphs, hub identification, lateral movement routes
- **Multi-provider support** — Groq (Llama 3.3 70B), OpenAI (GPT-4), Anthropic (Claude)

### 🕸️ Attack Graph Intelligence
- **NetworkX-based knowledge graph** — Nodes: Domains, IPs, Ports, Services, Vulnerabilities
- **Attack path enumeration** — Chains: `Subdomain → IP → Port → CVE → Exploit`
- **Critical node detection** — Identifies high-value targets (domain controllers, databases, admin interfaces)
- **Lateral movement suggestions** — Discovers internal network pivot opportunities
- **Shared vulnerability mapping** — Finds systemic weaknesses across infrastructure

### 🛠️ Pentest Workflow
- **Phased execution** — Sequential scanner dependencies (nmap first, then web scanners)
- **Concurrent scanning** — Parallel execution of independent tools
- **Intensity profiles** — Quick (5min), Standard (10min), Aggressive (20min+)
- **Tool auto-detection** — Graceful fallback if scanners are missing
- **Resilient pipeline** — Individual scanner failures don't crash the entire workflow

### 📊 Reporting & Export
- **Markdown reports** — Full technical details for documentation
- **PDF exports** — Executive summaries with risk scoring
- **Interactive graph visualization** — Force-directed network graphs
- **JSON output** — Structured data for CI/CD and SIEM integration

---

## Active Scanners

| Scanner | Category | Purpose | Key Features |
|---------|----------|---------|--------------|
| **nmap** | Port Scan | Service detection & OS fingerprinting | TCP/UDP, version detection, NSE scripts |
| **nuclei** | Vuln Scan | Template-based CVE/misconfiguration detection | 5000+ templates, severity filtering |
| **nikto** | Web Scan | Web server vulnerability scanner | Known exploits, dangerous files, outdated software |
| **gobuster** | Web Enum | Directory & file brute-forcing | Multi-threaded, custom wordlists |
| **ffuf** | Web Fuzzing | Fast web fuzzer (alternative to gobuster) | Parameter discovery, vhost enumeration |
| **whatweb** | Fingerprint | Web technology identification | CMS, frameworks, plugins, versions |
| **wafw00f** | WAF Detection | Web Application Firewall identification | Vendor detection, evasion planning |
| **sslscan** | SSL/TLS | Certificate and cipher analysis | Weak ciphers, protocol downgrade vulnerabilities |
| **dnsrecon** | DNS Enum | Advanced DNS reconnaissance | Zone transfers, subdomain brute-force, cache snooping |
| **wpscan** | CMS | WordPress-specific vulnerability scanner | Plugin/theme exploits, user enumeration |

### Planned Additions
- **masscan** — Ultra-fast port scanner (300,000 pps)
- **httpx** — HTTP probing at scale
- **feroxbuster** — Recursive directory brute-forcer (Rust-based)
- **sqlmap** — Automated SQL injection
- **testssl.sh** — Comprehensive SSL/TLS audit
- **dalfox** — XSS scanner

---

## Installation

### Prerequisites

- **Python 3.12+**
- **Security tools** — At minimum: `nmap`, `nuclei`, `nikto` (others optional)
- **AI API key** — Groq (free tier), OpenAI, or Anthropic

### Steps

```bash
# Clone the repository
git clone https://github.com/MateoGargat/ShadowStrike.git
cd ShadowStrike

# Create virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Add your API keys

# Verify scanner installation
python -c "from scanners.tool_detector import detect_all_tools; [print(f'{t.name}: {t.installed}') for t in detect_all_tools()]"
```

### Installing Security Tools

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap nikto -y
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**macOS (Homebrew):**
```bash
brew install nmap nikto nuclei gobuster
```

**Kali Linux:**
```bash
# Most tools pre-installed
sudo apt install nuclei gobuster ffuf
```

---

## Quick Start

### Web Interface (Recommended)

```bash
streamlit run app.py
```

1. **Sidebar**: Enable active scanning (toggle ON)
2. **Sidebar**: Select scan intensity (Quick/Standard/Aggressive)
3. **Sidebar**: Choose scanners to run
4. **Main input**: Enter target (domain, IP, or CIDR)
5. **Click**: "🔍 Scan"

### Command-Line Usage

```python
from core.models import AppConfig, ActiveScanConfig, ScanIntensity
from workflow import WorkflowRunner

# Configure aggressive active scan
config = AppConfig(
    groq_api_key="your_groq_api_key",
    active_scan=ActiveScanConfig(
        enabled=True,
        intensity=ScanIntensity.AGGRESSIVE,
        selected_scanners=["nmap", "nuclei", "nikto", "gobuster"],
        scanner_timeout=1800
    )
)

# Run scan
runner = WorkflowRunner(config=config)
state = runner.run("target.com")

# Extract results
scan_result = runner.get_scan_result(state)
analysis = runner.get_analysis(state)

print(f"Vulnerabilities: {len(scan_result.vulnerabilities)}")
print(f"Risk Score: {analysis.risk_score}/100")
print(f"Critical Findings: {len([f for f in analysis.findings if f.severity == 'critical'])}")
```

---

## Configuration

### Environment Variables

```bash
# === AI Analysis (required) ===
GROQ_API_KEY=gsk_...                     # Groq (Llama 3.3 70B)
OPENAI_API_KEY=sk-...                    # OpenAI (GPT-4) - optional for MoA
ANTHROPIC_API_KEY=sk-ant-...             # Anthropic (Claude) - optional for MoA

# === Active Scanning (default enabled) ===
ENABLE_ACTIVE_SCAN=true
SCAN_INTENSITY=aggressive                # quick | standard | aggressive
SELECTED_SCANNERS=nmap,nuclei,nikto,gobuster,whatweb,wafw00f,sslscan,dnsrecon,wpscan

# === Optional: Passive Recon (for target enumeration) ===
SHODAN_API_KEY=                          # Shodan API for port intelligence
VIRUSTOTAL_API_KEY=                      # VirusTotal for subdomain discovery
IPINFO_TOKEN=                            # ipinfo.io for geolocation/ASN

# === Advanced ===
SCANNER_TIMEOUT=600                      # Timeout per scanner (seconds)
MAX_CONCURRENT_SCANNERS=3                # Parallel scanner limit
WORDLIST_PATH=/usr/share/wordlists/dirb/common.txt
```

---

## AI Analysis

ShadowStrike uses **Mixture of Agents (MoA)** for multi-perspective security analysis:

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Scan Data + GraphRAG Context                               │
│  (Ports, Services, Vulns, Attack Paths, Hub Nodes)          │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │   Layer 1: Proposers    │  (Parallel Analysis)
        ├─────────────────────────┤
        │ • Llama 3.3 70B (Groq)  │  → Analysis 1
        │ • GPT-4 (OpenAI)        │  → Analysis 2
        │ • Claude Sonnet         │  → Analysis 3
        └────────────┬────────────┘
                     │
        ┌────────────┴────────────┐
        │  Layer 2: Aggregator    │  (Consensus Building)
        ├─────────────────────────┤
        │ Synthesizes findings    │  → Unified Analysis
        │ Resolves conflicts      │  → Risk Score
        │ Prioritizes by exploit  │  → Attack Scenarios
        └────────────┬────────────┘
                     │
        ┌────────────┴────────────┐
        │ Layer 3: Reflection     │  (Quality Check)
        ├─────────────────────────┤
        │ Validates consistency   │  → Final Report
        │ Flags missing insights  │  → Recommendations
        └─────────────────────────┘
```

### AI-Generated Insights

- **Exploit Prioritization**: Ranks vulnerabilities by weaponization difficulty
- **Attack Scenario Synthesis**: Multi-stage exploitation chains
- **Lateral Movement Suggestions**: Pivot opportunities based on discovered services
- **Credential Spray Candidates**: Services susceptible to default/weak credentials
- **Systemic Risk Identification**: Shared vulnerabilities across infrastructure

---

## GraphRAG Attack Path Analysis

**GraphRAG** (Graph-based Retrieval Augmented Generation) extracts offensive intelligence from the knowledge graph:

### Attack Path Discovery

```
Internet → subdomain.target.com → 203.0.113.5 → 22/tcp (SSH OpenSSH 7.4) → CVE-2023-XXXX → RCE
                                               → 80/tcp (Apache 2.4.29) → CVE-2021-44790 → LFI
                                               → 3306/tcp (MySQL 5.7) → Weak Auth → Data Access
```

### Critical Node Detection

Identifies high-value targets:
- **Domain Controllers** (ports 88, 389, 445)
- **Databases** (3306, 5432, 1433, 27017)
- **Admin Interfaces** (/admin, /wp-admin, /phpmyadmin)
- **VPN Gateways** (443, 1194, 500/4500)

### Lateral Movement Mapping

```
DMZ Host (203.0.113.5) → Pivot Candidates:
  • Port 445 (SMB) → Internal network enumeration
  • Port 3389 (RDP) → Credential stuffing
  • Port 22 (SSH) → Key-based lateral movement
```

### Shared Vulnerability Analysis

```
nginx 1.18.0 detected on 15 hosts:
  → CVE-2021-23017 (RCE)
  → Single exploit chain compromises entire cluster
  → Systemic risk level: CRITICAL
```

---

## Usage Scenarios

### Scenario 1: External Penetration Test

**Objective**: Identify exploitable vulnerabilities in internet-facing infrastructure

```bash
# .env configuration
ENABLE_ACTIVE_SCAN=true
SCAN_INTENSITY=aggressive
SELECTED_SCANNERS=nmap,nuclei,nikto,gobuster,whatweb,wafw00f,sslscan

# Run scan
streamlit run app.py
# Target: client-domain.com
```

**Expected Output**:
- 200+ open ports across 50 subdomains
- 15 high/critical CVEs
- 8 exploitable paths (subdomain → RCE)
- PDF report with exploitation priority

---

### Scenario 2: Red Team Exercise

**Objective**: Simulate APT attack with multi-stage compromise

```python
from core.models import AppConfig, ActiveScanConfig, MoAConfig

# Multi-model consensus for reduced false positives
moa = MoAConfig(
    proposers=[
        {"provider": "groq", "model": "llama-3.3-70b-versatile"},
        {"provider": "openai", "model": "gpt-4"},
    ],
    aggregator={"provider": "groq", "model": "llama-3.3-70b-versatile"},
    enable_reflection=True
)

config = AppConfig(
    groq_api_key="...",
    openai_api_key="...",
    active_scan=ActiveScanConfig(
        enabled=True,
        intensity=ScanIntensity.AGGRESSIVE,
        selected_scanners=["nmap", "nuclei", "dnsrecon", "gobuster", "wpscan"]
    ),
    moa_config=moa
)

runner = WorkflowRunner(config=config)
state = runner.run("10.0.0.0/24")

# Export attack graph
graph_data = state.get("graph_data")
# Identify pivot opportunities
analysis = runner.get_analysis(state)
print(analysis.recommendations)
```

---

### Scenario 3: Web Application Pentest

**Objective**: Comprehensive web vulnerability assessment

```bash
# Focus on web scanners only
SELECTED_SCANNERS=nmap,nikto,gobuster,whatweb,wafw00f,nuclei,wpscan
SCAN_INTENSITY=aggressive
WORDLIST_PATH=/usr/share/seclists/Discovery/Web-Content/common.txt

streamlit run app.py
# Target: https://webapp.target.com
```

**AI Analysis Focus**:
- XSS injection points
- SQL injection candidates
- Authentication bypasses
- Sensitive file exposure (/backup.sql, /.env)

---

## Scan Profiles

| Profile | Port Range | Wordlist Size | Nuclei Templates | Timeout | Use Case |
|---------|-----------|---------------|------------------|---------|----------|
| **Quick** | Top 100 | 2,000 entries | Critical only | 5 min | Initial recon |
| **Standard** | Top 1,000 | 10,000 entries | High+ | 10 min | Balanced coverage |
| **Aggressive** | All 65,535 | 50,000+ entries | All severities | 20+ min | Full audit |

---

## Export & Integration

### Markdown Reports

```python
from exporters.markdown_export import export_markdown

md = export_markdown(scan_result, analysis)
with open("report.md", "w") as f:
    f.write(md)
```

### PDF Reports

```python
from exporters.pdf_export import export_pdf

pdf_bytes = export_pdf(scan_result, analysis)
with open("report.pdf", "wb") as f:
    f.write(pdf_bytes)
```

### JSON Export (for Metasploit, SIEM)

```python
import json

# Export vulnerabilities
vulns = [v.model_dump() for v in scan_result.vulnerabilities]
with open("vulns.json", "w") as f:
    json.dump(vulns, f, indent=2)
```

---

## Legal & Ethics

### Authorization Requirements

**YOU MUST HAVE EXPLICIT WRITTEN PERMISSION** before scanning any target you do not own.

Unauthorized penetration testing is **illegal** in most jurisdictions and may violate:
- **Computer Fraud and Abuse Act (CFAA)** — USA
- **Computer Misuse Act** — UK
- **GDPR** — European Union
- **Criminal Code** — Canada, Australia, others

### Responsible Use

✅ **Authorized Use Cases**:
- Penetration tests with signed contracts
- Red team exercises for your employer
- Bug bounty programs (follow scope rules)
- Personal infrastructure you own

❌ **Unauthorized Use**:
- Scanning targets without permission
- "Grey hat" testing of third parties
- Credential stuffing/brute-forcing
- Denial-of-service attacks

### Responsible Disclosure

If you discover vulnerabilities:
1. **Notify the organization privately** (security@target.com)
2. **Allow 90 days** for remediation
3. **Do not publish exploits** until patched
4. **Follow coordinated disclosure** standards (ISO 29147)

---

## Roadmap

### Phase 1: Additional Scanners (Q1 2025)
- [ ] **masscan** — Ultra-fast port scanning
- [ ] **httpx** — HTTP probing at scale
- [ ] **feroxbuster** — Recursive directory brute-forcing
- [ ] **testssl.sh** — Comprehensive SSL/TLS audit

### Phase 2: Exploitation Framework (Q2 2025)
- [ ] **Metasploit integration** — Auto-launch exploits for discovered CVEs
- [ ] **Payload generation** — Context-aware exploit payloads
- [ ] **Post-exploitation** — Credential harvesting, lateral movement automation

### Phase 3: Stealth & Evasion (Q3 2025)
- [ ] **Rate limiting** — Adaptive scan speed to avoid detection
- [ ] **Proxy rotation** — Tor/SOCKS5 support
- [ ] **IDS evasion** — Fragmentation, timing randomization
- [ ] **Decoy traffic** — Noise generation to mask real scans

### Phase 4: Collaboration & Reporting (Q4 2025)
- [ ] **Multi-user support** — Team-based penetration testing
- [ ] **MISP/TheHive integration** — Threat intelligence correlation
- [ ] **REST API** — Headless scanning for CI/CD pipelines
- [ ] **Docker container** — Portable pentest lab

---

## Contributing

Contributions are welcome! Areas of interest:
- New scanner integrations (sqlmap, dalfox, subfinder)
- AI prompt engineering for better exploit prioritization
- GraphRAG enhancements (temporal analysis, credential graphs)
- Evasion techniques (IDS bypasses, anti-fingerprinting)

**Development Guidelines**:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-scanner`)
3. Add tests for new functionality (`pytest tests/`)
4. Submit pull request with detailed description

---

## Disclaimer

**ShadowStrike is a security research tool for authorized testing only.**

- The authors are not liable for misuse or illegal activity
- Users are responsible for obtaining proper authorization
- Violation of computer crime laws may result in prosecution
- This tool is provided "as-is" without warranty

**USE AT YOUR OWN RISK. ALWAYS FOLLOW RESPONSIBLE DISCLOSURE.**

---

## Credits

- **Original Project**: Shadow-OSINT (passive reconnaissance tool)
- **Fork Maintainer**: [MateoGargat](https://github.com/MateoGargat)
- **AI Models**: Groq (Meta Llama), OpenAI (GPT), Anthropic (Claude)
- **Security Tools**: nmap, nuclei, nikto, gobuster, and the offensive security community

---

## License

**Educational and Authorized Security Assessment Only**

This software is provided for:
- Authorized penetration testing
- Security research
- Educational purposes

Unauthorized use for malicious purposes is strictly prohibited and may violate local and international laws.

---

**ShadowStrike** — *Offense is the best defense.*

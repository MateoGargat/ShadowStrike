# Shadow-OSINT

Advanced OSINT reconnaissance and attack surface analysis tool. Shadow-OSINT combines passive intelligence gathering with optional active scanning capabilities, then uses a sophisticated AI analysis system (Mixture of Agents + GraphRAG) to produce comprehensive security assessments.

**Dual-mode operation:**
- **Passive mode** — Collects data from public sources: Certificate Transparency logs, DNS records, WHOIS databases, Shodan's InternetDB, and other APIs (no direct interaction with target)
- **Active mode** — Integrates 10 professional security scanners (nmap, nuclei, nikto, etc.) for deep vulnerability assessment when authorized

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Supported Inputs](#supported-inputs)
- [Data Sources](#data-sources)
- [Active Scanners](#active-scanners)
- [Project Structure](#project-structure)
- [Workflow Pipeline](#workflow-pipeline)
- [Graph Model](#graph-model)
- [GraphRAG: Graph-Enhanced Context Extraction](#graphrag-graph-enhanced-context-extraction)
- [AI Analysis](#ai-analysis)
- [Export Formats](#export-formats)
- [Cache System](#cache-system)
- [Testing](#testing)
- [Usage Scenarios](#usage-scenarios)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Data Collection
- **Multi-target support** — accepts domains, IPv4/IPv6 addresses, and CIDR ranges (up to /24)
- **7 passive collectors** — crt.sh, DNS, WHOIS, HackerTarget, Shodan, VirusTotal, ipinfo.io
- **10 active scanners** — nmap, nuclei, nikto, gobuster, whatweb, wafw00f, sslscan, dnsrecon, ffuf, wpscan
- **Scan intensity profiles** — Quick, Standard, Aggressive (configurable timeouts, wordlists, flags)
- **Auto tool detection** — automatic detection of installed security tools with version extraction

### AI Analysis
- **Mixture of Agents (MoA)** — multi-LLM architecture with propose/aggregate/reflect pattern
- **Multi-provider support** — Groq, OpenAI, Anthropic with unified interface
- **GraphRAG integration** — extracts structured context from knowledge graph for enhanced LLM reasoning
- **Graph analytics** — hub detection, attack path identification, community clustering, orphan detection
- **Structured output** — guaranteed schema conformance via instructor + Pydantic v2

### Orchestration & Visualization
- **LangGraph workflow** — stateful pipeline with conditional routing and parallel execution
- **Interactive graph** — force-directed network visualization with typed nodes and relations
- **Dual export** — Markdown and PDF report generation with risk scoring
- **Local cache** — JSON file cache with configurable TTL to avoid redundant API calls
- **Resilient execution** — collector/scanner failures are isolated and never crash the pipeline

---

## Architecture

```
                          +------------------+
                          |   Streamlit UI   |
                          |     (app.py)     |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |  LangGraph Flow  |
                          |  (workflow.py)   |
                          +--------+---------+
                                   |
              +--------------------+--------------------+
              |                    |                     |
     +--------v--------+  +-------v--------+  +--------v--------+
     | collect_domain   |  |  collect_ip    |  |  collect_cidr   |
     | (crtsh, dns,     |  |  (shodan,      |  |  (shodan per IP)|
     |  whois, ht, vt)  |  |   ipinfo)      |  |                 |
     +--------+---------+  +-------+--------+  +--------+--------+
              |                    |                     |
              +--------------------+--------------------+
                                   |
                          +--------v---------+
                          |     enrich       |
                          | (dns resolve,    |
                          |  shodan ports)   |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |  active_scan     |  [OPTIONAL]
                          | Phase 1: nmap,   |
                          |  dnsrecon, wafw00f|
                          | Phase 2: nuclei, |
                          | nikto, gobuster, |
                          | whatweb, wpscan  |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |   build_graph    |
                          |  (NetworkX +     |
                          |   active data)   |
                          +--------+---------+
                                   |
              +--------------------+--------------------+
              |                                         |
     +--------v---------+                   +-----------v----------+
     |   GraphRAG       |                   |   ai_analyze (MoA)   |
     | - Hub detection  |                   | Layer 1: Proposers   |
     | - Attack paths   |------------------>| (multi-LLM parallel) |
     | - Communities    |   Context         | Layer 2: Aggregator  |
     | - Orphan nodes   |   Extraction      | Layer 3: Reflection  |
     | - Shared tech    |                   | (Groq/OpenAI/Claude) |
     +------------------+                   +----------+-----------+
                                                       |
                                            +----------v-----------+
                                            |      Results         |
                                            | (Graph, AI Analysis, |
                                            |  PDF, Markdown)      |
                                            +----------------------+
```

**Pipeline flow:**
1. **Input routing** — conditional branching based on target type (domain/IP/CIDR)
2. **Data collection** — passive collectors run concurrently via `asyncio.gather`
3. **Enrichment** — DNS resolution and IP intelligence augmentation
4. **Active scanning** — optional, phased execution with dependency resolution
5. **Graph construction** — typed knowledge graph with passive + active data
6. **GraphRAG extraction** — structural analysis for LLM context enhancement
7. **MoA analysis** — multi-layer AI reasoning with consensus aggregation

Each stage receives and returns a shared `ScanState` dictionary. Failures are isolated and logged without pipeline interruption.

---

## Installation

### Prerequisites

- Python 3.12 or higher
- A Groq API key (free tier available at [console.groq.com](https://console.groq.com))

### Steps

```bash
git clone <repository-url>
cd ShadowOsint

python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your GROQ_API_KEY
```

### Dependencies

| Package          | Role                                      |
|------------------|-------------------------------------------|
| langgraph        | Workflow orchestration                    |
| instructor       | Structured LLM output (Pydantic)          |
| groq             | Groq API client                           |
| openai           | OpenAI API client (optional)              |
| anthropic        | Anthropic API client (optional)           |
| langchain-groq   | Groq LLM integration                      |
| pydantic         | Data validation and serialization         |
| httpx            | Async HTTP client                         |
| dnspython        | DNS resolution                            |
| python-whois     | WHOIS lookups                             |
| networkx         | Graph data structure + algorithms         |
| pyvis            | Interactive graph visualization           |
| streamlit        | Web interface                             |
| fpdf2            | PDF generation                            |
| mistune          | Markdown parsing                          |
| python-dotenv    | Environment variable loading              |
| defusedxml       | Secure XML parsing (scanner outputs)      |

---

## Configuration

### Environment Variables

Create a `.env` file at the project root:

```
# === AI Analysis (at least one required) ===
GROQ_API_KEY=your_groq_api_key_here
OPENAI_API_KEY=                        # Optional: for GPT models
ANTHROPIC_API_KEY=                     # Optional: for Claude models

# === Passive Collection (optional) ===
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
IPINFO_TOKEN=

# === Active Scanning Configuration (optional) ===
# Enable active scanning (default: false)
ENABLE_ACTIVE_SCAN=false

# Scan intensity: quick, standard, aggressive (default: standard)
SCAN_INTENSITY=standard

# Comma-separated list of scanners to enable (default: all except ffuf)
# Available: nmap,nuclei,nikto,gobuster,whatweb,wafw00f,sslscan,dnsrecon,ffuf,wpscan
SELECTED_SCANNERS=nmap,nuclei,nikto,gobuster,whatweb,wafw00f,sslscan,dnsrecon,wpscan

# Custom tool paths (optional, auto-detected by default)
NMAP_PATH=/custom/path/to/nmap
NUCLEI_PATH=/custom/path/to/nuclei
```

### API Keys Behavior

| Key                | Required | Without Key                          | With Key                      |
|--------------------|----------|--------------------------------------|-------------------------------|
| GROQ_API_KEY       | Yes*     | AI analysis disabled                 | Full AI security assessment   |
| OPENAI_API_KEY     | No       | OpenAI models unavailable            | GPT-4 for MoA proposers       |
| ANTHROPIC_API_KEY  | No       | Claude models unavailable            | Claude Sonnet for MoA         |
| SHODAN_API_KEY     | No       | Uses InternetDB (free, limited data) | Full Shodan API with banners  |
| VIRUSTOTAL_API_KEY | No       | Collector skipped                    | Additional subdomain data     |
| IPINFO_TOKEN       | No       | Collector skipped                    | IP geolocation and ASN data   |

\* At least one LLM provider key is required for AI analysis. Without any key, only raw data collection and graph visualization are available.

All keys can also be entered directly in the Streamlit sidebar at runtime.

---

## Usage

### Web Interface

```bash
streamlit run app.py
```

This opens a browser with the full interface. Enter a target in the input field, click Scan, and navigate the result tabs.

### Programmatic Usage

#### Basic Passive Scan

```python
from core.models import AppConfig
from cache.cache_manager import CacheManager
from workflow import WorkflowRunner

config = AppConfig(groq_api_key="your_key")
cache = CacheManager(enabled=True)
runner = WorkflowRunner(config=config, cache=cache)

state = runner.run("example.com")

scan_result = runner.get_scan_result(state)
analysis = runner.get_analysis(state)

print(f"Subdomains found: {len(scan_result.subdomains)}")
print(f"Risk score: {analysis.risk_score}/100")
```

#### Active Scan with Custom Profile

```python
from core.models import AppConfig, ActiveScanConfig, ScanIntensity
from workflow import WorkflowRunner

# Configure active scanning
active_config = ActiveScanConfig(
    enabled=True,
    intensity=ScanIntensity.AGGRESSIVE,
    selected_scanners=["nmap", "nuclei", "nikto", "gobuster"],
    scanner_timeout=1800  # 30 minutes
)

config = AppConfig(
    groq_api_key="your_key",
    active_scan_config=active_config
)

runner = WorkflowRunner(config=config)
state = runner.run("example.com")

# Access vulnerability findings
scan_result = runner.get_scan_result(state)
print(f"Vulnerabilities found: {len(scan_result.vulnerabilities)}")
for vuln in scan_result.vulnerabilities:
    print(f"  [{vuln.severity}] {vuln.title}")
```

#### Mixture of Agents Configuration

```python
from core.models import AppConfig, MoAConfig

# Configure MoA with multiple proposers
moa_config = MoAConfig(
    proposers=[
        {"provider": "groq", "model": "llama-3.3-70b-versatile"},
        {"provider": "openai", "model": "gpt-4"},
        {"provider": "anthropic", "model": "claude-3-sonnet-20240229"},
    ],
    aggregator={"provider": "groq", "model": "llama-3.3-70b-versatile"},
    enable_reflection=True,
    max_reflection_iterations=2
)

config = AppConfig(
    groq_api_key="your_groq_key",
    openai_api_key="your_openai_key",
    anthropic_api_key="your_anthropic_key",
    moa_config=moa_config
)

runner = WorkflowRunner(config=config)
state = runner.run("example.com")

# MoA analysis includes consensus from multiple models
analysis = runner.get_analysis(state)
print(f"Consensus risk score: {analysis.risk_score}/100")
```

---

## Supported Inputs

| Type   | Examples                            | Notes                              |
|--------|-------------------------------------|------------------------------------|
| Domain | `example.com`, `sub.example.com`    | Automatically lowercased, trailing dots removed |
| IPv4   | `8.8.8.8`, `192.168.1.1`           | Standard dotted notation           |
| IPv6   | `2001:db8::1`                       | Standard colon notation            |
| CIDR   | `8.8.8.0/28`, `192.168.1.0/24`     | Maximum /24 (256 addresses)        |

Invalid inputs are rejected with descriptive error messages.

---

## Data Sources

### Priority 0 — Always Active (no API key needed)

| Source       | Data Collected                                    |
|--------------|---------------------------------------------------|
| crt.sh       | Subdomains via Certificate Transparency logs      |
| DNS          | A, AAAA, MX, NS, TXT, CNAME, SOA records         |
| WHOIS        | Registrar, dates, nameservers, organization       |
| HackerTarget | Subdomains with associated IPs, ASN lookup        |

### Priority 1 — Free Tier Available

| Source       | Data Collected                                    |
|--------------|---------------------------------------------------|
| Shodan       | InternetDB: open ports, CPEs, hostnames, vulns    |

### Priority 2 — API Key Required

| Source       | Data Collected                                    |
|--------------|---------------------------------------------------|
| VirusTotal   | Additional subdomains via API v3                  |
| ipinfo.io    | IP geolocation, ASN, organization                 |

---

## Active Scanners

**⚠️ Authorization Required:** Active scanning directly interacts with target systems. Only use on infrastructure you own or have explicit written permission to test.

Shadow-OSINT integrates 10 professional security tools for comprehensive vulnerability assessment:

| Scanner    | Purpose                              | Output Parsed                          |
|------------|--------------------------------------|----------------------------------------|
| **nmap**   | Port scanning and service detection  | Open ports, services, versions, OS     |
| **nuclei** | Template-based vulnerability scanner | CVEs, misconfigurations, exposures     |
| **nikto**  | Web server scanner                   | Known vulnerabilities, server issues   |
| **gobuster** | Directory/file brute-forcing       | Hidden paths, sensitive files          |
| **whatweb** | Web technology fingerprinting       | CMS, frameworks, plugins, versions     |
| **wafw00f** | Web Application Firewall detection  | WAF vendor, confidence level           |
| **sslscan** | SSL/TLS configuration analysis      | Ciphers, certificate info, weaknesses  |
| **dnsrecon** | Advanced DNS enumeration           | Zone transfers, brute-force, records   |
| **ffuf**   | Fast web fuzzer (alternative to gobuster) | Directories, parameters, vhosts   |
| **wpscan** | WordPress-specific vulnerability scanner | Plugins, themes, users, vulns      |

### Scan Profiles

| Profile       | nmap Scope   | Wordlist  | Nuclei Severity | Timeout | Use Case              |
|---------------|--------------|-----------|-----------------|---------|------------------------|
| **Quick**     | Top 100      | common    | high, critical  | 5 min   | Fast initial recon     |
| **Standard**  | Top 1000     | medium    | low+            | 10 min  | Balanced coverage      |
| **Aggressive**| All 65535    | big       | info+           | 20 min  | Comprehensive audit    |

### Phased Execution

Scanners run in two phases to optimize dependency resolution:

- **Phase 1** (no dependencies): `nmap`, `dnsrecon`, `wafw00f`
- **Phase 2** (uses Phase 1 results): `whatweb`, `sslscan`, `gobuster`, `nikto`, `nuclei`, `wpscan`

Mutual exclusions apply automatically (e.g., only `gobuster` OR `ffuf` runs unless explicitly overridden).

### Tool Detection

Shadow-OSINT automatically detects installed tools at startup:

```python
from scanners.tool_detector import detect_all_tools

tools = detect_all_tools()
for tool in tools:
    print(f"{tool.name}: {'✓' if tool.installed else '✗'} {tool.version or ''}")
```

Missing tools are skipped gracefully. No tool is mandatory — run what you have installed.

---

## Project Structure

```
ShadowOsint/
|
|-- app.py                         Streamlit web interface
|-- workflow.py                    LangGraph pipeline orchestration
|-- requirements.txt               Python dependencies
|-- .env.example                   Environment variable template
|-- conftest.py                    Root pytest configuration
|
|-- core/
|   |-- models.py                  Pydantic models, enums, TypedDict state
|   |-- input_parser.py            Input validation (domain, IP, CIDR)
|   |-- graph.py                   NetworkX graph construction and stats
|
|-- collectors/
|   |-- __init__.py                Collector registry and factory functions
|   |-- base.py                    Abstract base with HTTP, caching, rate limiting
|   |-- crtsh.py                   Certificate Transparency (crt.sh)
|   |-- dns_resolver.py            DNS resolution (dnspython)
|   |-- whois_collector.py         WHOIS registration data
|   |-- hackertarget.py            HackerTarget hostsearch and ASN
|   |-- shodan_collector.py        Shodan InternetDB + full API
|   |-- virustotal.py              VirusTotal API v3
|   |-- ipinfo_collector.py        ipinfo.io geolocation and ASN
|
|-- analyzers/
|   |-- ai_analyst.py              Mixture of Agents (MoA) orchestration
|   |-- llm_providers.py           Multi-provider LLM abstraction (Groq/OpenAI/Anthropic)
|   |-- graph_rag.py               GraphRAG context extraction from knowledge graph
|   |-- prompts.py                 System prompts for proposer/aggregator/reflection
|
|-- scanners/
|   |-- __init__.py                Scanner registry and factory
|   |-- base.py                    Abstract base for subprocess-based scanners
|   |-- profiles.py                Scan intensity profiles (Quick/Standard/Aggressive)
|   |-- tool_detector.py           Auto-detection of installed security tools
|   |-- nmap_scanner.py            Nmap port scanner
|   |-- nuclei_scanner.py          Nuclei vulnerability scanner
|   |-- nikto_scanner.py           Nikto web server scanner
|   |-- gobuster_scanner.py        Gobuster directory brute-forcer
|   |-- whatweb_scanner.py         WhatWeb technology fingerprinter
|   |-- wafw00f_scanner.py         Wafw00f WAF detector
|   |-- ssl_scanner.py             SSLScan TLS analyzer
|   |-- dnsrecon_scanner.py        DNSRecon advanced DNS enumeration
|   |-- ffuf_scanner.py            Ffuf web fuzzer
|   |-- wpscan_scanner.py          WPScan WordPress scanner
|   |-- output_parsers/            Structured parsers for all scanner outputs
|
|-- visualization/
|   |-- graph_renderer.py          pyvis interactive graph rendering
|
|-- exporters/
|   |-- markdown_export.py         Markdown report generation
|   |-- pdf_export.py              PDF report generation (fpdf2)
|
|-- cache/
|   |-- cache_manager.py           JSON file cache with TTL
|
|-- tests/
    |-- conftest.py                Shared test fixtures
    |-- test_input_parser.py       12 tests — input validation
    |-- test_graph.py              9 tests — graph construction
    |-- test_cache.py              9 tests — cache operations
    |-- test_ai_analyst.py         5 tests — AI analysis
    |-- test_integration.py        3 tests — end-to-end workflow
    |-- test_collectors/
    |   |-- test_crtsh.py          6 tests
    |   |-- test_dns.py            6 tests
    |   |-- test_whois.py          4 tests
    |   |-- test_hackertarget.py   4 tests
    |   |-- test_shodan.py         4 tests
    |   |-- test_virustotal.py     3 tests
    |-- test_scanners/
        |-- test_nmap.py           Scanner + parser tests
        |-- test_nuclei.py         Scanner + parser tests
        |-- test_nikto.py          Scanner + parser tests
        |-- test_gobuster.py       Scanner + parser tests
        |-- test_tool_detector.py  Tool detection tests
```

---

## Workflow Pipeline

The LangGraph workflow follows this execution path:

```
START
  |
  v
parse_input -----> Validates and classifies the raw input
  |
  v
route_by_type ---> Conditional branching based on InputType
  |
  +-- domain --> collect_domain (crtsh + dns + whois + hackertarget + virustotal)
  +-- ip -----> collect_ip     (shodan + ipinfo)
  +-- cidr ---> collect_cidr   (shodan per IP in range)
  |
  v
enrich ----------> Resolves subdomain DNS, queries Shodan for discovered IPs
  |
  v
build_graph -----> Constructs typed knowledge graph from all collected data
  |
  v
ai_analyze ------> Sends context to Groq LLM, receives structured AIAnalysis
  |
  v
END
```

### State Management

All nodes share a `ScanState` TypedDict. Each node receives the full state and returns a partial dictionary that gets merged back. This design ensures:

- Collectors can run concurrently within a node
- Failures are recorded without halting the pipeline
- Progress can be tracked at each stage

---

## Graph Model

The knowledge graph uses typed nodes and directed edges to represent the complete attack surface:

### Node Types

| Type           | Description                      | Visual          | Source        |
|----------------|----------------------------------|-----------------|---------------|
| Domain         | Root target domain               | Red star        | Passive       |
| Subdomain      | Discovered subdomain             | Orange dot      | Passive       |
| IP             | IPv4 or IPv6 address             | Blue diamond    | Passive       |
| Port           | Open port on an IP               | Green square    | Passive/Active|
| Technology     | Software or service              | Purple triangle | Passive/Active|
| ASN            | Autonomous System Number         | Teal hexagon    | Passive       |
| Vulnerability  | Identified security issue        | Red octagon     | **Active**    |
| WebDirectory   | Discovered web path              | Yellow folder   | **Active**    |
| WAF            | Web Application Firewall         | Blue shield     | **Active**    |
| SSLCert        | SSL/TLS certificate              | Green lock      | **Active**    |

### Relation Types

| Relation           | From             | To            | Description                    |
|--------------------|------------------|---------------|--------------------------------|
| HAS_SUBDOMAIN      | Domain           | Subdomain     | Domain ownership               |
| RESOLVES_TO        | Domain/Subdomain | IP            | DNS resolution                 |
| HAS_PORT           | IP               | Port          | Network service                |
| RUNS               | Port/IP          | Technology    | Software identification        |
| BELONGS_TO_ASN     | IP               | ASN           | Network allocation             |
| HAS_VULNERABILITY  | IP/Port          | Vulnerability | Security finding (active scan) |
| HAS_DIRECTORY      | IP               | WebDirectory  | Web content (active scan)      |
| PROTECTED_BY       | Domain           | WAF           | Firewall detection             |
| HAS_SSL_CERT       | IP               | SSLCert       | Certificate association        |

---

## GraphRAG: Graph-Enhanced Context Extraction

Shadow-OSINT uses **GraphRAG** (Graph-based Retrieval Augmented Generation) to extract high-level structural insights from the knowledge graph before AI analysis. This enhances LLM reasoning by providing graph-derived intelligence beyond raw data tables.

### Extracted Features

1. **Graph Statistics**
   - Total nodes and edges by type
   - Graph density and connectivity metrics
   - Average degree distribution

2. **Hub Nodes (High-Risk Concentration Points)**
   - Identifies assets with unusually high connectivity
   - Example: An IP hosting 50+ subdomains may indicate shared infrastructure
   - Ranked by degree centrality

3. **Attack Path Enumeration**
   - Discovers routes from internet-facing assets to internal resources
   - Chains like: `Subdomain → IP → Port → Technology → Vulnerability`
   - Prioritizes paths ending in critical vulnerabilities

4. **Community Detection**
   - Groups related assets using graph clustering algorithms
   - Reveals infrastructure patterns (e.g., AWS vs. GCP clusters)
   - Identifies shadow IT based on isolated communities

5. **Orphan Subdomain Detection**
   - Finds subdomains without IP resolution (dangling DNS)
   - Potential subdomain takeover vulnerabilities
   - Indicates abandoned infrastructure

6. **Shared Technology Mapping**
   - Identifies common software across multiple assets
   - Example: "nginx 1.18" on 15 IPs → single patch fixes widespread issue
   - Highlights systemic vulnerabilities

7. **ASN Distribution Analysis**
   - Maps IP allocation across Autonomous Systems
   - Reveals cloud provider diversity or single-point-of-failure risks
   - Geolocation distribution insights

### Integration with LLM Analysis

GraphRAG context is prepended to the scan data before LLM analysis:

```
# Knowledge Graph Context
## Graph Statistics
Total nodes: 247 (subdomain: 180, ip: 42, port: 18, technology: 7)
...

## High-Connectivity Nodes (Hubs)
- 203.0.113.5 (type=ip, connections=23) — hosting many services
- nginx (type=technology, connections=15) — widespread deployment

## Attack Paths (12 found)
- www.example.com -> 203.0.113.5 -> 443/tcp -> Apache 2.4.29 -> CVE-2021-44790
...
```

This structured context helps LLMs identify:
- **Systemic risks** (shared vulnerabilities)
- **Critical paths** (high-impact attack routes)
- **Infrastructure patterns** (multi-cloud, shadow IT)
- **Abandoned assets** (orphan subdomains)

---

## AI Analysis

Shadow-OSINT employs a **Mixture of Agents (MoA)** architecture combined with **GraphRAG** for sophisticated security analysis.

### Architecture Layers

#### Layer 1: Proposers (Parallel Analysis)
Multiple LLM instances independently analyze the scan data from different perspectives:
- Each proposer receives the full scan context + GraphRAG-extracted insights
- Proposers can use different models/providers (Groq Llama 3.3, GPT-4, Claude Sonnet)
- All proposers run in parallel for maximum diversity

#### Layer 2: Aggregator (Consensus Building)
A specialized aggregator model receives all proposer analyses and:
- Identifies consensus findings
- Resolves conflicting assessments
- Synthesizes a unified security assessment
- Produces structured `AIAnalysis` output with risk scoring

#### Layer 3: Reflection (Optional Quality Check)
An optional reflection layer reviews the aggregated analysis and:
- Validates logical consistency
- Checks for missing critical insights
- Can trigger re-analysis if quality is insufficient
- Iterates up to `max_reflection_iterations` (default: 1)

### GraphRAG Context Enhancement

Before LLM analysis, GraphRAG extracts structural insights from the knowledge graph:

- **Hub detection** — identifies high-connectivity nodes (concentration points)
- **Attack path enumeration** — finds routes from internet-exposed assets to sensitive resources
- **Community detection** — clusters related assets (shared infrastructure)
- **Orphan identification** — discovers dangling subdomains without IP resolution
- **Technology mapping** — identifies shared software creating common vulnerabilities
- **ASN distribution** — reveals multi-cloud or single-provider dependencies

This structured context enhances LLM reasoning beyond raw data tables.

### Output Structure

- **Risk Score** (0-100) — quantified exposure rating
- **Executive Summary** — high-level assessment
- **Findings** — individual issues with severity, description, affected assets, and recommendations
- **Exposed Services Summary** — overview of the attack surface
- **Recommendations** — prioritized action items

### Severity Levels

| Level    | Description                                           |
|----------|-------------------------------------------------------|
| Critical | Immediately exploitable, known CVEs, exposed databases |
| High     | Significant risk, outdated software, admin panels      |
| Medium   | Excessive sprawl, missing email security               |
| Low      | Best-practice recommendations                          |
| Info     | Neutral observations                                   |

### Multi-Provider Support

Shadow-OSINT supports multiple LLM providers via unified abstraction:

| Provider   | Models Supported              | Required API Key       |
|------------|-------------------------------|------------------------|
| Groq       | llama-3.3-70b-versatile       | GROQ_API_KEY           |
| OpenAI     | gpt-4, gpt-4-turbo, gpt-3.5   | OPENAI_API_KEY         |
| Anthropic  | claude-3-sonnet, claude-3-opus| ANTHROPIC_API_KEY      |

All providers use `instructor` for guaranteed structured output conforming to the `AIAnalysis` Pydantic model.

---

## Export Formats

### Markdown

Full report with tables for subdomains, IPs, ports, technologies, DNS records, WHOIS data, and AI findings. Suitable for documentation or further processing.

### PDF

Formatted report with sections, risk-colored score, finding details, and asset listings. Uses fpdf2 with custom headers and footers.

Both formats include all scan data and the complete AI analysis when available.

---

## Cache System

Collector results are cached as JSON files in the `cache/` directory.

| Parameter  | Default | Description                        |
|------------|---------|------------------------------------|
| Enabled    | true    | Toggle caching on/off              |
| TTL        | 86400s  | Cache entry lifetime (24 hours)    |
| Directory  | cache/  | Storage location                   |

Cache keys are derived from `sha256(source:target)`, truncated to 16 characters. Expired entries are cleaned on access. The cache can be cleared manually from the Streamlit sidebar or programmatically:

```python
from cache.cache_manager import CacheManager

cache = CacheManager()
cache.clear_all()       # Remove everything
cache.clear_expired()   # Remove only expired entries
cache.invalidate("crtsh", "example.com")  # Remove specific entry
```

---

## Testing

All tests use mocks — no network calls are made during testing.

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov

# Run a specific module
pytest tests/test_input_parser.py

# Run collector tests only
pytest tests/test_collectors/
```

### Test Summary

| Module          | Tests | Coverage Target | Notes                          |
|-----------------|-------|-----------------|--------------------------------|
| Input Parser    | 12    | 100%            | Domain/IP/CIDR validation      |
| Graph           | 9     | 80%+            | Graph construction + new nodes |
| Cache           | 9     | 90%+            | TTL and invalidation           |
| AI Analyst      | 5     | 90%+            | MoA + GraphRAG                 |
| Collectors (7)  | 27    | 90%+            | All passive sources            |
| Scanners (10)   | ~40   | 85%+            | Active scanners + parsers      |
| Integration     | 3     | Pipeline paths  | End-to-end workflows           |
| **Total**       | **100+** | **80%+**     | All tests use mocks            |

---

## Usage Scenarios

### Scenario 1: Initial Reconnaissance (Passive Only)

**Objective:** Understand external attack surface without touching the target.

```bash
streamlit run app.py
# Enter: example.com
# Enable: Passive mode only
# Expected: Subdomains, IPs, ports from public sources
```

**Use case:** Pre-engagement scoping, competitive intelligence, supply chain assessment.

### Scenario 2: Authorized Vulnerability Assessment (Active)

**Objective:** Deep security audit with full tool suite.

```bash
# Set in .env:
ENABLE_ACTIVE_SCAN=true
SCAN_INTENSITY=aggressive
SELECTED_SCANNERS=nmap,nuclei,nikto,gobuster,whatweb,wafw00f,sslscan,wpscan

streamlit run app.py
# Enter: yourdomain.com (you own this!)
```

**Use case:** Pre-deployment security audit, red team exercise, compliance scanning.

### Scenario 3: Multi-Model Consensus Analysis (MoA)

**Objective:** Reduce AI hallucinations through multi-model voting.

```python
from core.models import AppConfig, MoAConfig

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
    moa_config=moa
)
```

**Use case:** High-stakes assessments requiring maximum AI accuracy.

### Scenario 4: Continuous Monitoring with Cache

**Objective:** Daily recon with minimal API usage.

```bash
# Set cache TTL to 24 hours (default)
# Run daily cron job:
0 9 * * * cd /path/to/ShadowOsint && python -c "from workflow import WorkflowRunner; ..."
```

**Use case:** Detecting new subdomains, port changes, certificate expirations.

---

## Best Practices

### Security & Ethics

1. **Authorization First**
   - NEVER run active scans without explicit written permission
   - Passive reconnaissance is legal but be aware of terms of service
   - Consider rate limits and responsible disclosure

2. **API Key Management**
   - Use environment variables, never commit keys to git
   - Rotate keys regularly
   - Use separate keys for testing vs. production

3. **Rate Limiting**
   - Respect API rate limits (built-in for collectors)
   - Use cache to avoid redundant requests
   - Spread large CIDR scans over time

### Performance Optimization

1. **Cache Strategy**
   - Enable cache for repeated scans
   - Adjust TTL based on target volatility
   - Use `cache.clear_expired()` to free space

2. **Active Scan Tuning**
   - Start with `quick` profile for initial assessment
   - Use `aggressive` only when time permits
   - Exclude scanners not relevant to target (e.g., skip wpscan for non-WordPress)

3. **MoA Configuration**
   - Single proposer (Groq) for speed
   - 2-3 proposers for accuracy
   - Disable reflection for simple targets

### Operational Tips

1. **Phased Approach**
   - Day 1: Passive recon only
   - Day 2: Active scan with `quick` profile
   - Day 3: Targeted deep scan on high-risk assets

2. **Result Validation**
   - Cross-reference findings with other tools
   - Manually verify AI-identified vulnerabilities
   - Use PDF reports for stakeholder communication

3. **Integration**
   - Export Markdown for CI/CD pipelines
   - Parse JSON output for SIEM integration
   - Use graph data for custom visualization

---

## Troubleshooting

### "Tool not found" errors

```bash
# Check tool installation
python -c "from scanners.tool_detector import detect_all_tools; print(detect_all_tools())"

# Install missing tools (example for Ubuntu/Debian)
sudo apt install nmap nikto
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### LLM API errors

- **Groq rate limit:** Wait 60s or upgrade to paid tier
- **OpenAI timeout:** Increase `llm_max_tokens` or reduce context
- **Anthropic unavailable:** Check API key format (should start with `sk-ant-`)

### Active scan hangs

- Check `scanner_timeout` in config
- Verify target is reachable: `ping <target>`
- Run individual scanner manually to debug: `nmap -sV <target>`

### Graph visualization not loading

- Ensure `pyvis` is installed: `pip install pyvis`
- Check browser console for JavaScript errors
- Try refreshing the page or clearing browser cache

---

## Roadmap

- [ ] **Integration with MISP/TheHive** for threat intelligence correlation
- [ ] **Scheduled scanning** with webhooks for change detection
- [ ] **Docker container** for easy deployment
- [ ] **REST API** for programmatic access
- [ ] **Additional scanners** (testssl.sh, subjack, subfinder)
- [ ] **Enhanced GraphRAG** with temporal analysis (certificate expiry prediction)
- [ ] **Custom ML models** for vulnerability prioritization

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes with clear messages
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Submit a pull request

---

## License

This project is intended for **authorized security assessments and educational purposes only**.

**Legal Notice:**
- Passive reconnaissance uses public data sources and is generally legal
- Active scanning directly interacts with target systems and requires explicit authorization
- Unauthorized security testing may violate computer fraud laws (CFAA, GDPR, etc.)
- Always obtain written permission before testing infrastructure you do not own
- The authors assume no liability for misuse of this tool

**Responsible Disclosure:**
If you discover vulnerabilities using Shadow-OSINT, follow responsible disclosure practices:
1. Notify the affected organization privately
2. Allow reasonable time for remediation (90 days typical)
3. Do not publicly disclose until patched or agreed timeline expires

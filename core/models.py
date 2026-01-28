from __future__ import annotations

import hashlib
import operator
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from typing import Annotated, Any, Optional, TypedDict

from pydantic import BaseModel, Field, field_validator


# === ENUMS ===

class InputType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class NodeType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    PORT = "port"
    TECHNOLOGY = "technology"
    ASN = "asn"
    VULNERABILITY = "vulnerability"
    WEB_DIRECTORY = "web_directory"
    WAF = "waf"
    SSL_CERT = "ssl_cert"


class RelationType(str, Enum):
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    HAS_PORT = "HAS_PORT"
    RUNS = "RUNS"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    HAS_DIRECTORY = "HAS_DIRECTORY"
    PROTECTED_BY = "PROTECTED_BY"
    HAS_SSL_CERT = "HAS_SSL_CERT"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanIntensity(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


# === INPUT ===

class ParsedInput(BaseModel):
    raw: str
    input_type: InputType
    target: str
    targets: list[str] = Field(default_factory=list)


# === ENTITIES ===

class GeoLocation(BaseModel):
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None


class ASNInfo(BaseModel):
    asn: str
    name: Optional[str] = None
    domain: Optional[str] = None
    route: Optional[str] = None
    asn_type: Optional[str] = None


class SubdomainRecord(BaseModel):
    name: str
    source: str
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return v.strip().lower().rstrip(".")


class IPRecord(BaseModel):
    address: str
    version: int = 4
    hostnames: list[str] = Field(default_factory=list)
    geolocation: Optional[GeoLocation] = None
    asn_info: Optional[ASNInfo] = None


class PortRecord(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    service: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    ip_address: str


class TechnologyRecord(BaseModel):
    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    category: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None


class WhoisRecord(BaseModel):
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    nameservers: list[str] = Field(default_factory=list)
    organization: Optional[str] = None
    country: Optional[str] = None
    emails: list[str] = Field(default_factory=list)
    dnssec: Optional[str] = None
    status: list[str] = Field(default_factory=list)


class DNSRecords(BaseModel):
    domain: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    soa: Optional[str] = None


# === COLLECTOR RESULT ===

class CollectorResult(BaseModel):
    source: str
    success: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    subdomains: list[SubdomainRecord] = Field(default_factory=list)
    ips: list[IPRecord] = Field(default_factory=list)
    ports: list[PortRecord] = Field(default_factory=list)
    technologies: list[TechnologyRecord] = Field(default_factory=list)
    whois: Optional[WhoisRecord] = None
    dns: Optional[DNSRecords] = None
    raw_data: Optional[dict[str, Any]] = None


# === ACTIVE SCAN RECORDS ===

class VulnerabilityRecord(BaseModel):
    vuln_id: Optional[str] = None
    title: str
    severity: VulnSeverity = VulnSeverity.UNKNOWN
    affected_host: Optional[str] = None
    affected_port: Optional[int] = None
    affected_url: Optional[str] = None
    scanner: str = ""
    references: list[str] = Field(default_factory=list)
    cvss: Optional[float] = None
    description: Optional[str] = None


class WebDirectoryRecord(BaseModel):
    url: str
    status_code: int
    content_length: Optional[int] = None
    host: Optional[str] = None
    port: Optional[int] = None
    scanner: str = ""


class WAFRecord(BaseModel):
    host: str
    detected: bool = False
    waf_name: Optional[str] = None
    waf_vendor: Optional[str] = None
    confidence: Optional[float] = None


class SSLRecord(BaseModel):
    host: str
    port: int = 443
    protocol_versions: list[str] = Field(default_factory=list)
    cipher_suites: list[str] = Field(default_factory=list)
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    certificate_san: list[str] = Field(default_factory=list)
    has_weak_ciphers: bool = False
    vulnerabilities: list[str] = Field(default_factory=list)


class ActiveDNSRecord(BaseModel):
    host: str
    record_type: str
    value: str
    source_method: str = ""


class OSDetectionRecord(BaseModel):
    ip_address: str
    os_family: Optional[str] = None
    os_generation: Optional[str] = None
    os_accuracy: Optional[int] = None
    os_cpe: Optional[str] = None


class ActiveScannerResult(BaseModel):
    scanner_name: str
    success: bool
    error: Optional[str] = None
    duration_seconds: float = 0.0
    command_executed: str = ""
    vulnerabilities: list[VulnerabilityRecord] = Field(default_factory=list)
    web_directories: list[WebDirectoryRecord] = Field(default_factory=list)
    waf_records: list[WAFRecord] = Field(default_factory=list)
    ssl_records: list[SSLRecord] = Field(default_factory=list)
    active_dns_records: list[ActiveDNSRecord] = Field(default_factory=list)
    os_detections: list[OSDetectionRecord] = Field(default_factory=list)
    ports: list[PortRecord] = Field(default_factory=list)
    technologies: list[TechnologyRecord] = Field(default_factory=list)


class ToolInfo(BaseModel):
    name: str
    installed: bool = False
    path: Optional[str] = None
    version: Optional[str] = None


class ActiveScanConfig(BaseModel):
    enabled: bool = False
    intensity: ScanIntensity = ScanIntensity.STANDARD
    nmap_path: Optional[str] = None
    gobuster_path: Optional[str] = None
    nikto_path: Optional[str] = None
    nuclei_path: Optional[str] = None
    whatweb_path: Optional[str] = None
    wafw00f_path: Optional[str] = None
    sslscan_path: Optional[str] = None
    dnsrecon_path: Optional[str] = None
    ffuf_path: Optional[str] = None
    wpscan_path: Optional[str] = None
    wordlist_path: Optional[str] = None
    max_concurrent_scanners: int = 3
    nmap_top_ports: Optional[int] = None
    scanner_timeout: int = 600
    selected_scanners: list[str] = Field(default_factory=list)


# === SCAN RESULT ===

class ScanResult(BaseModel):
    target: str
    input_type: InputType
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    subdomains: list[SubdomainRecord] = Field(default_factory=list)
    ips: list[IPRecord] = Field(default_factory=list)
    ports: list[PortRecord] = Field(default_factory=list)
    technologies: list[TechnologyRecord] = Field(default_factory=list)
    whois: Optional[WhoisRecord] = None
    dns_records: list[DNSRecords] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    sources_used: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityRecord] = Field(default_factory=list)
    web_directories: list[WebDirectoryRecord] = Field(default_factory=list)
    waf_info: list[WAFRecord] = Field(default_factory=list)
    ssl_info: list[SSLRecord] = Field(default_factory=list)
    active_dns: list[ActiveDNSRecord] = Field(default_factory=list)
    os_detection: list[OSDetectionRecord] = Field(default_factory=list)
    active_scan_performed: bool = False


# === AI ANALYSIS ===

class Finding(BaseModel):
    title: str
    severity: RiskLevel
    description: str
    affected_assets: list[str] = Field(default_factory=list)
    recommendation: str


class AIAnalysis(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    executive_summary: str
    attack_surface_size: str
    findings: list[Finding] = Field(default_factory=list)
    exposed_services_summary: str
    recommendations: list[str] = Field(default_factory=list)
    methodology_notes: str = ""
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    analysis_version: int = Field(default=1)
    proposer_count: int = Field(default=1)
    consensus_level: str = Field(default="single")


class ProposerAnalysis(BaseModel):
    """Analyse produite par un agent proposer (Layer 1)."""
    provider: str
    model: str
    risk_score: int = Field(ge=0, le=100)
    executive_summary: str
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class ProposerInput(BaseModel):
    """Input envoye a chaque proposer via Send API."""
    provider: str
    model: str
    system_prompt: str
    context: str


class MoAConfig(BaseModel):
    """Configuration du systeme Mixture of Agents."""
    proposers: list[dict] = Field(default_factory=lambda: [
        {"provider": "groq", "model": "llama-3.3-70b-versatile"},
    ])
    aggregator: dict = Field(default_factory=lambda: {
        "provider": "groq", "model": "llama-3.3-70b-versatile"
    })
    enable_reflection: bool = True
    max_reflection_iterations: int = 1


# === GRAPH ===

class GraphNode(BaseModel):
    id: str
    label: str
    node_type: NodeType
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: RelationType
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphData(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


# === CACHE ===

class CacheEntry(BaseModel):
    key: str
    source: str
    target: str
    data: dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    ttl_seconds: int = 86400

    @property
    def is_expired(self) -> bool:
        return (datetime.utcnow() - self.created_at).total_seconds() > self.ttl_seconds

    @staticmethod
    def make_key(source: str, target: str) -> str:
        return hashlib.sha256(f"{source}:{target}".encode()).hexdigest()[:16]


# === CONFIG ===

class AppConfig(BaseModel):
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    ipinfo_token: Optional[str] = None
    groq_api_key: str = ""
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    http_timeout: int = 30
    dns_timeout: int = 10
    cache_enabled: bool = True
    cache_ttl: int = 86400
    cache_dir: str = "cache"
    llm_model: str = "llama-3.3-70b-versatile"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096
    max_cidr_prefix: int = 24
    max_concurrent_requests: int = 5
    active_scan: ActiveScanConfig = Field(default_factory=ActiveScanConfig)
    moa_config: MoAConfig = Field(default_factory=MoAConfig)


# === LANGGRAPH STATE ===

class ScanState(TypedDict, total=False):
    raw_input: str
    input_type: str
    target: str
    targets: list[str]
    subdomains: list[dict]
    ips: list[dict]
    ports: list[dict]
    technologies: list[dict]
    whois: dict | None
    dns_records: list[dict]
    graph_data: dict
    ai_analysis: dict
    errors: list[str]
    sources_used: list[str]
    current_step: str
    progress: float
    active_scan_enabled: bool
    active_scan_results: list[dict]
    vulnerabilities: list[dict]
    web_directories: list[dict]
    waf_info: list[dict]
    ssl_info: list[dict]
    active_dns: list[dict]
    os_detection: list[dict]
    installed_tools: list[dict]
    # MoA fields
    proposer_analyses: Annotated[list[dict], operator.add]
    graph_context: str

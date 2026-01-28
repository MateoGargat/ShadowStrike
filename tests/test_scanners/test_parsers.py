"""Tests for all output parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanners.output_parsers.gobuster_parser import parse_gobuster_output
from scanners.output_parsers.nikto_parser import parse_nikto_json
from scanners.output_parsers.wafw00f_parser import parse_wafw00f_json
from scanners.output_parsers.whatweb_parser import parse_whatweb_json
from scanners.output_parsers.dnsrecon_parser import parse_dnsrecon_json
from scanners.output_parsers.ffuf_parser import parse_ffuf_json
from scanners.output_parsers.sslscan_parser import parse_sslscan_xml
from scanners.output_parsers.wpscan_parser import parse_wpscan_json

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# === Gobuster ===

class TestGobusterParser:
    def test_parse_basic(self):
        text = (FIXTURES_DIR / "gobuster_dirs.txt").read_text()
        records = parse_gobuster_output(text, base_url="http://example.com")
        assert len(records) == 5
        admin = next(r for r in records if "/admin" in r.url)
        assert admin.status_code == 200
        assert admin.content_length == 1234

    def test_parse_empty(self):
        records = parse_gobuster_output("")
        assert records == []

    def test_parse_with_base_url(self):
        text = "/test (Status: 200) [Size: 100]"
        records = parse_gobuster_output(text, base_url="http://target.com")
        assert len(records) == 1
        assert records[0].url == "http://target.com/test"
        assert records[0].host == "target.com"


# === Nikto ===

class TestNiktoParser:
    def test_parse_json(self):
        json_data = '{"host":"example.com","port":"80","vulnerabilities":[{"OSVDB":"3092","method":"GET","url":"/admin/","msg":"Admin directory found"}]}'
        records = parse_nikto_json(json_data)
        assert len(records) == 1
        assert records[0].scanner == "nikto"
        assert "admin" in records[0].title.lower() or "admin" in (records[0].description or "").lower()

    def test_parse_empty(self):
        records = parse_nikto_json("")
        assert records == []


# === wafw00f ===

class TestWafw00fParser:
    def test_parse_detected(self):
        json_data = '[{"url":"http://example.com","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."}]'
        records = parse_wafw00f_json(json_data)
        assert len(records) == 1
        assert records[0].detected
        assert records[0].waf_name == "Cloudflare"
        assert records[0].host == "example.com"

    def test_parse_not_detected(self):
        json_data = '[{"url":"http://example.com","detected":false,"firewall":"","manufacturer":""}]'
        records = parse_wafw00f_json(json_data)
        assert len(records) == 1
        assert not records[0].detected

    def test_parse_empty(self):
        records = parse_wafw00f_json("")
        assert records == []


# === WhatWeb ===

class TestWhatWebParser:
    def test_parse_json(self):
        json_data = '{"target":"http://example.com","plugins":{"jQuery":{"version":["3.6.0"]},"WordPress":{"version":["6.0"],"string":["cms"]},"Title":{"string":["Example"]}}}'
        records = parse_whatweb_json(json_data)
        # Should skip Title
        names = {r.name for r in records}
        assert "jQuery" in names
        assert "WordPress" in names
        assert "Title" not in names

    def test_parse_with_version(self):
        json_data = '{"target":"http://example.com","plugins":{"Apache":{"version":["2.4.52"]}}}'
        records = parse_whatweb_json(json_data)
        assert len(records) == 1
        assert records[0].version == "2.4.52"

    def test_parse_empty(self):
        records = parse_whatweb_json("")
        assert records == []


# === DNSRecon ===

class TestDNSReconParser:
    def test_parse_json(self):
        json_data = '[{"type":"A","name":"example.com","address":"93.184.216.34"},{"type":"MX","name":"example.com","address":"mail.example.com","method":"std"},{"type":"info","name":"test"}]'
        records = parse_dnsrecon_json(json_data)
        assert len(records) == 2  # info type skipped
        a_rec = next(r for r in records if r.record_type == "A")
        assert a_rec.host == "example.com"
        assert a_rec.value == "93.184.216.34"

    def test_parse_empty(self):
        records = parse_dnsrecon_json("")
        assert records == []


# === ffuf ===

class TestFfufParser:
    def test_parse_json(self):
        json_data = '{"results":[{"url":"http://example.com/admin","status":200,"length":1234},{"url":"http://example.com/login","status":301,"length":0}]}'
        records = parse_ffuf_json(json_data)
        assert len(records) == 2
        assert records[0].url == "http://example.com/admin"
        assert records[0].status_code == 200

    def test_parse_empty(self):
        records = parse_ffuf_json("")
        assert records == []


# === sslscan ===

class TestSSLScanParser:
    def test_parse_xml(self):
        xml = '''<?xml version="1.0"?>
        <document>
          <ssltest host="example.com" port="443">
            <protocol type="TLS" version="1.2" enabled="1"/>
            <protocol type="TLS" version="1.3" enabled="1"/>
            <protocol type="SSL" version="3.0" enabled="0"/>
            <cipher status="preferred" cipher="ECDHE-RSA-AES256-GCM-SHA384" bits="256"/>
            <cipher status="accepted" cipher="RC4-SHA" bits="128"/>
            <certificate>
              <subject>CN=example.com</subject>
              <issuer>CN=Let's Encrypt</issuer>
              <not-valid-after>2024-12-31</not-valid-after>
            </certificate>
            <heartbleed vulnerable="0"/>
          </ssltest>
        </document>'''
        records = parse_sslscan_xml(xml)
        assert len(records) == 1
        ssl = records[0]
        assert ssl.host == "example.com"
        assert ssl.port == 443
        assert "TLSv1.2" in ssl.protocol_versions
        assert "TLSv1.3" in ssl.protocol_versions
        assert ssl.has_weak_ciphers  # RC4
        assert ssl.certificate_subject == "CN=example.com"
        assert ssl.certificate_expiry == "2024-12-31"

    def test_parse_empty(self):
        records = parse_sslscan_xml("")
        assert records == []


# === wpscan ===

class TestWPScanParser:
    def test_parse_json(self):
        json_data = '''{
            "target_url": "http://example.com",
            "version": {
                "number": "6.4.1",
                "vulnerabilities": [
                    {"title": "WP Core XSS", "id": "CVE-2024-1234", "references": {"url": ["https://example.com"]}, "cvss": {"score": 6.5}}
                ]
            },
            "plugins": {
                "akismet": {
                    "version": {"number": "5.0"},
                    "vulnerabilities": []
                }
            }
        }'''
        result = parse_wpscan_json(json_data)
        assert len(result["technologies"]) >= 2  # WordPress + akismet
        assert any(t.name == "WordPress" for t in result["technologies"])
        assert len(result["vulnerabilities"]) >= 1

    def test_parse_empty(self):
        result = parse_wpscan_json("")
        assert result["vulnerabilities"] == []
        assert result["technologies"] == []

"""Tests for core.input_parser module."""

import pytest
from core.input_parser import parse_input
from core.models import InputType


class TestValidDomain:
    def test_valid_domain(self):
        result = parse_input("example.com")
        assert result.input_type == InputType.DOMAIN
        assert result.target == "example.com"

    def test_valid_subdomain(self):
        result = parse_input("sub.example.com")
        assert result.input_type == InputType.DOMAIN
        assert result.target == "sub.example.com"

    def test_domain_trailing_dot(self):
        result = parse_input("example.com.")
        assert result.target == "example.com"

    def test_domain_uppercase(self):
        result = parse_input("EXAMPLE.COM")
        assert result.target == "example.com"


class TestValidIP:
    def test_valid_ipv4(self):
        result = parse_input("192.168.1.1")
        assert result.input_type == InputType.IP
        assert result.target == "192.168.1.1"

    def test_valid_ipv6(self):
        result = parse_input("2001:db8::1")
        assert result.input_type == InputType.IP
        assert result.target == "2001:db8::1"

    def test_ip_with_spaces(self):
        result = parse_input("  8.8.8.8  ")
        assert result.input_type == InputType.IP
        assert result.target == "8.8.8.8"


class TestValidCIDR:
    def test_valid_cidr(self):
        result = parse_input("192.168.1.0/24")
        assert result.input_type == InputType.CIDR
        assert len(result.targets) > 0

    def test_cidr_slash_28(self):
        result = parse_input("8.8.8.0/28")
        assert result.input_type == InputType.CIDR
        assert len(result.targets) == 14  # /28 = 16 - network - broadcast


class TestInvalid:
    def test_cidr_too_large(self):
        with pytest.raises(ValueError, match="too large"):
            parse_input("10.0.0.0/16")

    def test_invalid_empty(self):
        with pytest.raises(ValueError, match="empty"):
            parse_input("")

    def test_invalid_garbage(self):
        with pytest.raises(ValueError):
            parse_input("not-a-valid-input!!!")

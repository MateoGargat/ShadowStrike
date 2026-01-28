"""Tests for cache.cache_manager module."""

import json
import time
from pathlib import Path

import pytest

from cache.cache_manager import CacheManager
from core.models import CacheEntry


@pytest.fixture
def cache_dir(tmp_path):
    return str(tmp_path / "test_cache")


@pytest.fixture
def cache(cache_dir):
    return CacheManager(cache_dir=cache_dir, ttl_seconds=3600, enabled=True)


class TestCacheManager:
    def test_set_and_get(self, cache):
        cache.set("source1", "target1", {"key": "value"})
        result = cache.get("source1", "target1")
        assert result is not None
        assert result["key"] == "value"

    def test_cache_miss(self, cache):
        result = cache.get("nonexistent", "target")
        assert result is None

    def test_cache_expired(self, cache_dir):
        cache = CacheManager(cache_dir=cache_dir, ttl_seconds=1, enabled=True)
        cache.set("source", "target", {"data": True})
        # Verify it's there
        assert cache.get("source", "target") is not None
        # Wait for expiration
        time.sleep(1.5)
        assert cache.get("source", "target") is None

    def test_invalidate(self, cache):
        cache.set("source", "target", {"data": True})
        assert cache.get("source", "target") is not None
        result = cache.invalidate("source", "target")
        assert result is True
        assert cache.get("source", "target") is None

    def test_invalidate_missing(self, cache):
        result = cache.invalidate("nonexistent", "target")
        assert result is False

    def test_clear_all(self, cache):
        cache.set("s1", "t1", {"a": 1})
        cache.set("s2", "t2", {"b": 2})
        count = cache.clear_all()
        assert count == 2
        assert cache.get("s1", "t1") is None
        assert cache.get("s2", "t2") is None

    def test_clear_expired(self, cache_dir):
        cache = CacheManager(cache_dir=cache_dir, ttl_seconds=1, enabled=True)
        cache.set("old", "target", {"data": "old"})
        time.sleep(1.5)
        # Add a fresh one
        cache2 = CacheManager(cache_dir=cache_dir, ttl_seconds=3600, enabled=True)
        cache2.set("new", "target", {"data": "new"})
        count = cache2.clear_expired()
        assert count == 1  # only the old one
        assert cache2.get("new", "target") is not None


class TestCacheEntry:
    def test_key_generation(self):
        key1 = CacheEntry.make_key("source", "target")
        key2 = CacheEntry.make_key("source", "target")
        key3 = CacheEntry.make_key("other", "target")
        assert key1 == key2
        assert key1 != key3
        assert len(key1) == 16

    def test_disabled_cache(self, cache_dir):
        cache = CacheManager(cache_dir=cache_dir, ttl_seconds=3600, enabled=False)
        cache.set("source", "target", {"data": True})
        assert cache.get("source", "target") is None

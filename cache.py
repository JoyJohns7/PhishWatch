"""
cache.py - In-memory lookup cache for the phishing analyzer backend.

Caches the expensive network lookups (WHOIS, TLS/cert, redirect-chain) so
repeated analysis of the same domain/URL doesn't re-hit the network. Works on
both sync and async functions - the decorator detects which it wrapped.

Usage:
    from cache import cached_lookup, cache_stats

    @cached_lookup("whois")
    def fetch_whois(domain: str):
        return whois.whois(domain)

Dependency: pip install cachetools
"""

from __future__ import annotations

import asyncio
import functools
import threading
import time
from typing import Any, Callable

from cachetools import TTLCache

# Per-lookup caches. TTLs reflect how fast each source actually changes.
_CACHES: dict[str, TTLCache] = {
    "whois":     TTLCache(maxsize=2_000, ttl=24 * 60 * 60),   # 24h
    "tls":       TTLCache(maxsize=2_000, ttl=6 * 60 * 60),    # 6h
    "redirects": TTLCache(maxsize=2_000, ttl=10 * 60),        # 10m
    "default":   TTLCache(maxsize=2_000, ttl=60 * 60),        # 1h
}

_SYNC_LOCKS: dict[str, threading.Lock] = {n: threading.Lock() for n in _CACHES}
_ASYNC_LOCKS: dict[str, asyncio.Lock] = {n: asyncio.Lock() for n in _CACHES}

_STATS: dict[str, dict[str, float]] = {
    n: {"hits": 0, "misses": 0, "saved_seconds": 0.0} for n in _CACHES
}


def _cache_for(ns: str) -> TTLCache:
    return _CACHES.get(ns, _CACHES["default"])


def _make_key(args: tuple, kwargs: dict) -> str:
    target = str(args[0]).strip().lower() if args else ""
    if kwargs:
        extra = ":".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
        return f"{target}|{extra}"
    return target


def cached_lookup(namespace: str = "default") -> Callable[[Callable], Callable]:
    """Cache an expensive lookup, keyed on its first argument. Auto-detects
    sync vs async, so the same decorator works on either."""

    def decorator(func: Callable) -> Callable:
        ns = namespace if namespace in _CACHES else "default"
        cache = _cache_for(ns)
        stats = _STATS[ns]

        if asyncio.iscoroutinefunction(func):
            alock = _ASYNC_LOCKS[ns]

            @functools.wraps(func)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                key = _make_key(args, kwargs)
                if key in cache:
                    stats["hits"] += 1
                    return cache[key]
                async with alock:
                    if key in cache:
                        stats["hits"] += 1
                        return cache[key]
                    stats["misses"] += 1
                    start = time.perf_counter()
                    result = await func(*args, **kwargs)
                    stats["saved_seconds"] += time.perf_counter() - start
                    cache[key] = result
                    return result

            return awrapper

        slock = _SYNC_LOCKS[ns]

        @functools.wraps(func)
        def swrapper(*args: Any, **kwargs: Any) -> Any:
            key = _make_key(args, kwargs)
            if key in cache:
                stats["hits"] += 1
                return cache[key]
            with slock:
                if key in cache:
                    stats["hits"] += 1
                    return cache[key]
                stats["misses"] += 1
                start = time.perf_counter()
                result = func(*args, **kwargs)
                stats["saved_seconds"] += time.perf_counter() - start
                cache[key] = result
                return result

        return swrapper

    return decorator


def cache_stats() -> dict[str, Any]:
    """Aggregate stats for the dashboard's Lookup Cache panel."""
    hits = sum(s["hits"] for s in _STATS.values())
    misses = sum(s["misses"] for s in _STATS.values())
    saved = sum(s["saved_seconds"] for s in _STATS.values())
    entries = sum(len(c) for c in _CACHES.values())

    lookups = hits + misses
    hit_rate = (hits / lookups) if lookups else 0.0
    avg_saved = (saved / misses) if misses else 0.0

    return {
        "hit_rate": round(hit_rate, 3),
        "entries": entries,
        "avg_saved_seconds": round(avg_saved, 2),
        "by_namespace": {
            n: {"hits": int(s["hits"]), "misses": int(s["misses"]),
                "entries": len(_CACHES[n])}
            for n, s in _STATS.items()
        },
    }


def clear_cache(namespace=None) -> None:
    for n in ([namespace] if namespace else list(_CACHES)):
        if n in _CACHES:
            _CACHES[n].clear()
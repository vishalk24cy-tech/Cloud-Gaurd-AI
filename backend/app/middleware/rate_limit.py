"""
CloudGuardAI Production Rate Limiting
=====================================

Distributed Redis-backed rate limiter with a safe local
in-memory fallback for development.

Production:
    Redis is preferred.

Development:
    Falls back to an in-memory limiter if Redis is unavailable.

The limiter protects sensitive endpoints from abuse while
preserving normal CloudGuardAI usage.
"""

import hashlib
import os
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple

from fastapi import Request
from starlette.responses import JSONResponse

try:
    from redis.asyncio import Redis
except ImportError:
    Redis = None


# ============================================================
# CONFIGURATION
# ============================================================

APP_ENV = os.getenv(
    "APP_ENV",
    "development"
).strip().lower()

IS_PRODUCTION = APP_ENV == "production"

REDIS_URL = os.getenv(
    "REDIS_URL",
    ""
).strip()


# ============================================================
# RATE LIMIT RULES
# ============================================================

# Format:
#
# path_prefix:
#     (requests, window_seconds)
#
# More specific rules are evaluated before general rules.

RATE_LIMIT_RULES = {

    # Authentication protection
    "/auth/login": (10, 60),
    "/auth/register": (5, 60),

    # Password/security operations
    "/auth/forgot-password": (5, 60),
    "/auth/reset-password": (5, 60),
    "/auth/verify-email": (10, 60),

    # AWS scanning is expensive.
    "/cloud/aws/scan": (5, 600),

    # AI requests can consume external API quota.
    "/ai": (30, 60),

    # Remediation changes AWS infrastructure.
    "/remediation": (20, 60),

    # General API protection.
    "/": (120, 60),
}


# ============================================================
# METHODS TO LIMIT
# ============================================================

RATE_LIMITED_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}


# ============================================================
# IN-MEMORY FALLBACK
# ============================================================

_memory_store: Dict[
    str,
    Tuple[int, float]
] = {}

_memory_lock = Lock()


# ============================================================
# REDIS CLIENT
# ============================================================

_redis_client = None


def get_redis_client():
    """
    Create a Redis client lazily.

    Redis is only initialized when REDIS_URL is configured.
    """

    global _redis_client

    if Redis is None:
        return None

    if not REDIS_URL:
        return None

    if _redis_client is None:
        try:
            _redis_client = Redis.from_url(
                REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
        except Exception:
            _redis_client = None

    return _redis_client


# ============================================================
# CLIENT IDENTITY
# ============================================================

def get_client_ip(request: Request) -> str:
    """
    Resolve client IP.

    For production deployments behind a trusted reverse proxy,
    the proxy should provide X-Forwarded-For correctly.
    """

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:
        # Use the first address in the trusted forwarding chain.
        return forwarded_for.split(",")[0].strip()

    if request.client:
        return request.client.host

    return "unknown"


def get_identity_key(request: Request) -> str:
    """
    Build a privacy-conscious rate-limit identity.

    IP is always included.

    When an Authorization header exists, we add a SHA-256
    fingerprint rather than storing the JWT itself.
    """

    ip = get_client_ip(request)

    authorization = request.headers.get(
        "Authorization",
        ""
    )

    if authorization:
        token_fingerprint = hashlib.sha256(
            authorization.encode("utf-8")
        ).hexdigest()[:16]

        return f"ip:{ip}:auth:{token_fingerprint}"

    return f"ip:{ip}"


# ============================================================
# RULE MATCHING
# ============================================================

def get_rate_limit_rule(
    path: str,
    method: str
):
    """
    Return the most specific matching rate-limit rule.
    """

    if method.upper() not in RATE_LIMITED_METHODS:
        return None

    # Do not rate-limit documentation/static resources.
    if path.startswith(
        (
            "/docs",
            "/redoc",
            "/openapi.json",
        )
    ):
        return None

    matching_rules = []

    for prefix, rule in RATE_LIMIT_RULES.items():

        if path.startswith(prefix):
            matching_rules.append(
                (len(prefix), rule)
            )

    if not matching_rules:
        return None

    # Longest prefix wins.
    matching_rules.sort(
        key=lambda item: item[0],
        reverse=True
    )

    return matching_rules[0][1]


# ============================================================
# MEMORY LIMITER
# ============================================================

def check_memory_limit(
    key: str,
    limit: int,
    window: int
):
    """
    Development fallback limiter.

    Returns:

        allowed,
        remaining,
        retry_after
    """

    now = time.time()

    with _memory_lock:

        current = _memory_store.get(key)

        if current is None:
            _memory_store[key] = (
                1,
                now
            )

            return True, limit - 1, 0

        count, window_start = current

        elapsed = now - window_start

        if elapsed >= window:

            _memory_store[key] = (
                1,
                now
            )

            return True, limit - 1, 0

        if count >= limit:

            retry_after = max(
                1,
                int(window - elapsed)
            )

            return False, 0, retry_after

        count += 1

        _memory_store[key] = (
            count,
            window_start
        )

        return True, limit - count, 0


# ============================================================
# REDIS LIMITER
# ============================================================

async def check_redis_limit(
    key: str,
    limit: int,
    window: int
):
    """
    Atomic-ish Redis counter using INCR + EXPIRE.

    Redis failures intentionally fall back to the local limiter
    rather than taking CloudGuardAI completely offline.
    """

    redis = get_redis_client()

    if redis is None:
        return None

    redis_key = f"cloudguardai:ratelimit:{key}"

    try:

        count = await redis.incr(redis_key)

        if count == 1:
            await redis.expire(
                redis_key,
                window
            )

        ttl = await redis.ttl(
            redis_key
        )

        if count > limit:

            retry_after = max(
                1,
                int(ttl)
            )

            return (
                False,
                0,
                retry_after
            )

        remaining = max(
            0,
            limit - int(count)
        )

        return (
            True,
            remaining,
            0
        )

    except Exception:
        return None


# ============================================================
# RATE LIMIT MIDDLEWARE
# ============================================================

async def rate_limit_middleware(
    request: Request,
    call_next
):
    """
    Global CloudGuardAI rate limiter.

    Sensitive endpoints receive tighter limits while other
    mutating API requests receive the general limit.
    """

    method = request.method.upper()
    path = request.url.path

    rule = get_rate_limit_rule(
        path,
        method
    )

    # No applicable rule.
    if rule is None:
        return await call_next(request)

    limit, window = rule

    identity = get_identity_key(
        request
    )

    # Include route bucket to prevent unrelated endpoints
    # sharing the same counter.
    bucket = f"{method}:{path}:{identity}"

    redis_result = await check_redis_limit(
        bucket,
        limit,
        window
    )

    if redis_result is not None:

        allowed, remaining, retry_after = (
            redis_result
        )

    else:

        allowed, remaining, retry_after = (
            check_memory_limit(
                bucket,
                limit,
                window
            )
        )

    if not allowed:

        request_id = getattr(
            request.state,
            "request_id",
            None
        )

        headers = {
            "Retry-After": str(
                retry_after
            ),
            "X-RateLimit-Limit": str(
                limit
            ),
            "X-RateLimit-Remaining": "0",
        }

        if request_id:
            headers[
                "X-Request-ID"
            ] = request_id

        return JSONResponse(
            status_code=429,
            content={
                "status": "error",
                "message": (
                    "Too many requests. "
                    "Please try again later."
                ),
                "request_id": request_id,
            },
            headers=headers,
        )

    response = await call_next(
        request
    )

    # Expose useful rate-limit information.
    response.headers[
        "X-RateLimit-Limit"
    ] = str(limit)

    response.headers[
        "X-RateLimit-Remaining"
    ] = str(remaining)

    return response


# ============================================================
# RESET MEMORY LIMITER
# ============================================================

def reset_memory_limiter():
    """
    Development/test helper.

    Clears the local fallback limiter.
    """

    with _memory_lock:
        _memory_store.clear()
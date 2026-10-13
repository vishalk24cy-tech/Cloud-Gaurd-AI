import os
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.database.connection import db

from app.api.auth import router as auth_router
from app.api.cloud import router as cloud_router
from app.api.dashboard import router as dashboard_router
from app.api.report import router as report_router
from app.api.ai_chat import router as ai_chat_router
from app.api.notifications import router as notification_router
from app.api.compliance import router as compliance_router
from app.api.aws_accounts import router as aws_account_router
from app.api.cost_optimizer import router as cost_optimizer_router
from app.api.findings import router as findings_router
from app.api.remediation import router as remediation_router
from app.api.remediation_settings import router as remediation_settings_router
from app.api.security_graph import router as security_graph_router
from app.api.security_correlation import router as security_correlation_router
from app.api.audit import router as audit_router
from app.api.organizations import router as organization_router
from app.api.subscriptions import router as subscription_router
from app.api.razorpay_webhook import router as razorpay_webhook_router
from app.api.scan_jobs import router as scan_jobs_router
from app.api.scan_worker import router as scan_worker_router

from app.services.scan_job_service import recover_stale_scan_jobs

from app.services.monitoring.scheduler import start_scheduler

from app.middleware.rate_limit import rate_limit_middleware
from app.core.logging_config import log_event, log_exception, log_request

import logging
import time


# ============================================================
# ENVIRONMENT
# ============================================================

APP_ENV = os.getenv(
    "APP_ENV",
    "development"
).strip().lower()

IS_PRODUCTION = APP_ENV == "production"


# ============================================================
# CORS CONFIGURATION
# ============================================================

DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
]
_frontend_url = os.getenv("FRONTEND_URL", "").strip()
CORS_ORIGINS = DEFAULT_CORS_ORIGINS.copy()
if _frontend_url and _frontend_url not in CORS_ORIGINS:
    CORS_ORIGINS.append(_frontend_url)


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="CloudGuardAI API",
    version="1.0.0"
)


# ============================================================
# REQUEST ID MIDDLEWARE
# ============================================================

@app.middleware("http")
async def request_id_middleware(
    request: Request,
    call_next
):

    request_id = request.headers.get(
        "X-Request-ID"
    ) or uuid4().hex

    request.state.request_id = request_id

    try:

        response = await call_next(request)

    except Exception:

        raise

    response.headers[
        "X-Request-ID"
    ] = request_id

    return response


# ============================================================
# RATE LIMITING MIDDLEWARE
# ============================================================

@app.middleware("http")
async def rate_limit(
    request: Request,
    call_next
):

    return await rate_limit_middleware(
        request,
        call_next
    )


# ============================================================
# STRUCTURED REQUEST / SECURITY LOGGING
# ============================================================

@app.middleware("http")
async def structured_logging_middleware(
    request: Request,
    call_next
):

    started_at = time.perf_counter()

    request_id = getattr(
        request.state,
        "request_id",
        uuid4().hex
    )

    client_ip = (
        request.client.host
        if request.client
        else None
    )

    user_id = None
    status_code = 500

    try:

        response = await call_next(request)

        status_code = response.status_code

        user = getattr(
            request.state,
            "user",
            None
        )

        if isinstance(user, dict):

            user_id = (
                user.get("_id")
                or user.get("user_id")
            )

        duration_ms = (
            time.perf_counter() - started_at
        ) * 1000

        log_request(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            duration_ms=duration_ms,
            client_ip=client_ip,
            user_id=str(user_id) if user_id else None,
        )

        return response

    except Exception as exc:

        duration_ms = (
            time.perf_counter() - started_at
        ) * 1000

        log_exception(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=500,
            exception_type=type(exc).__name__,
        )

        log_event(
            logging.ERROR,
            "REQUEST_FAILED",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_ms=round(duration_ms, 2),
            client_ip=client_ip or "unknown",
            exception_type=type(exc).__name__,
        )

        raise


# ============================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================

@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next
):

    response = await call_next(
        request
    )

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"

    response.headers[
        "Permissions-Policy"
    ] = (
        "camera=(), "
        "microphone=(), "
        "geolocation=(), "
        "payment=(), "
        "usb=()"
    )

    sensitive_prefixes = (
        "/auth",
        "/cloud",
        "/aws",
        "/dashboard",
        "/findings",
        "/remediation",
        "/notifications",
        "/compliance",
        "/security-graph",
        "/security-correlation",
        "/audit",
        "/ai",
        "/cost",
        "/report",
        "/organizations",
    )

    if request.url.path.startswith(
        sensitive_prefixes
    ):

        response.headers[
            "Cache-Control"
        ] = "no-store"

        response.headers[
            "Pragma"
        ] = "no-cache"

    if IS_PRODUCTION:

        response.headers[
            "Strict-Transport-Security"
        ] = (
            "max-age=31536000; "
            "includeSubDomains"
        )

    return response


# ============================================================
# CONTENT SECURITY POLICY
# ============================================================

@app.middleware("http")
async def content_security_policy_middleware(
    request: Request,
    call_next
):

    response = await call_next(
        request
    )

    if request.url.path.startswith(
        "/docs"
    ):

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'self'; "
            "script-src 'self' "
            "'unsafe-inline' "
            "'unsafe-eval' "
            "https://cdn.jsdelivr.net; "
            "style-src 'self' "
            "'unsafe-inline' "
            "https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https:; "
            "connect-src 'self' http: https:;"
        )

    else:

        response.headers[
            "Content-Security-Policy"
        ] = (
            "default-src 'none'; "
            "frame-ancestors 'none';"
        )

    return response


# ============================================================
# GLOBAL HTTP EXCEPTION HANDLER
# ============================================================

@app.exception_handler(
    StarletteHTTPException
)
async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException
):

    request_id = getattr(
        request.state,
        "request_id",
        uuid4().hex
    )

    detail = exc.detail

    if isinstance(
        detail,
        dict
    ):

        message = (
            detail.get("message")
            or detail.get("detail")
            or "Request failed."
        )

    else:

        message = str(
            detail
        )

    return JSONResponse(
        status_code=exc.status_code,

        content={
            "status": "error",
            "message": message,
            "request_id": request_id,
        },

        headers={
            "X-Request-ID": request_id,
        },
    )


# ============================================================
# REQUEST VALIDATION EXCEPTION HANDLER
# ============================================================

@app.exception_handler(
    RequestValidationError
)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):

    request_id = getattr(
        request.state,
        "request_id",
        uuid4().hex
    )

    return JSONResponse(
        status_code=422,

        content={
            "status": "error",
            "message": "Invalid request data.",
            "request_id": request_id,
        },

        headers={
            "X-Request-ID": request_id,
        },
    )


# ============================================================
# GLOBAL UNHANDLED EXCEPTION HANDLER
# ============================================================

@app.exception_handler(
    Exception
)
async def unhandled_exception_handler(
    request: Request,
    exc: Exception
):

    request_id = getattr(
        request.state,
        "request_id",
        uuid4().hex
    )

    log_event(
        logging.ERROR,
        "UNHANDLED_EXCEPTION",
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        exception_type=type(exc).__name__,
    )

    return JSONResponse(
        status_code=500,

        content={
            "status": "error",
            "message": (
                "An unexpected server error occurred. "
                "Please try again or contact support."
            ),
            "request_id": request_id,
        },

        headers={
            "X-Request-ID": request_id,
        },
    )


# ============================================================
# BACKGROUND SCAN JOB WORKER
# ============================================================
#
# IMPORTANT:
# The scan worker now runs as a separate process:
#
#     python worker.py
#
# The old in-process worker functions are intentionally
# retained here because the manual /scan-worker endpoint
# and shutdown compatibility may depend on them.
#
# FastAPI startup DOES NOT start this worker anymore.
# ============================================================

_scan_worker_stop_event = threading.Event()
_scan_worker_thread = None


def _run_background_scan_worker():

    print(
        "[SCAN-WORKER] Background worker started"
    )

    while not _scan_worker_stop_event.is_set():

        try:

            recovery = recover_stale_scan_jobs(
                stale_after_seconds=600
            )

            if recovery["recovered"] or recovery["failed"]:

                print(
                    "[SCAN-WORKER] Stale recovery: "
                    f"recovered={recovery['recovered']}, "
                    f"failed={recovery['failed']}"
                )

            now = datetime.now(
                timezone.utc
            )

            job = db.scan_jobs.find_one(
                {
                    "$or": [
                        {
                            "status": "queued"
                        },
                        {
                            "status": "retrying",
                            "$or": [
                                {
                                    "next_retry_at": None
                                },
                                {
                                    "next_retry_at": {
                                        "$lte": now
                                    }
                                }
                            ]
                        }
                    ]
                },
                sort=[
                    (
                        "queued_at",
                        1
                    )
                ]
            )

            if not job:

                _scan_worker_stop_event.wait(3)
                continue

            job_id = str(
                job.get("_id")
            )

            organization_id = str(
                job.get("organization_id")
            )

            print(
                "[SCAN-WORKER] "
                f"Processing job {job_id}"
            )

            # NOTE:
            # This legacy in-process loop is retained for
            # compatibility but is NOT started by FastAPI.

            result = process_scan_job(
                job_id=job_id,
                organization_id=organization_id
            )

            result_status = (
                result.get("status")
                if isinstance(result, dict)
                else None
            )

            print(
                "[SCAN-WORKER] "
                f"Job {job_id} result: "
                f"{result_status}"
            )

        except Exception as exc:

            print(
                "[SCAN-WORKER] "
                "Worker loop error: "
                f"{type(exc).__name__}: {exc}"
            )

            _scan_worker_stop_event.wait(5)


def _start_background_scan_worker():

    global _scan_worker_thread

    if (
        _scan_worker_thread is not None
        and _scan_worker_thread.is_alive()
    ):
        return

    _scan_worker_stop_event.clear()

    _scan_worker_thread = threading.Thread(
        target=_run_background_scan_worker,
        name="cloudguardai-scan-worker",
        daemon=True
    )

    _scan_worker_thread.start()


def _stop_background_scan_worker():

    global _scan_worker_thread

    _scan_worker_stop_event.set()

    if (
        _scan_worker_thread is not None
        and _scan_worker_thread.is_alive()
    ):

        _scan_worker_thread.join(
            timeout=10
        )

    _scan_worker_thread = None

    print(
        "[SCAN-WORKER] Background worker stopped"
    )


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
def startup_event():

    print(
        "[STARTUP] CloudGuardAI environment: "
        f"{APP_ENV}"
    )

    print(
        "[STARTUP] CORS origins: "
        f"{CORS_ORIGINS}"
    )

    log_event(
        logging.INFO,
        "APPLICATION_STARTED",
        environment=APP_ENV,
        cors_origins=CORS_ORIGINS,
    )

    # --------------------------------------------------------
    # Monitoring scheduler
    # --------------------------------------------------------

    try:

        start_scheduler()

        print(
            "[OK] Monitoring scheduler started"
        )

    except Exception as exc:

        print(
            "[WARNING] Monitoring scheduler "
            f"unavailable: {type(exc).__name__}: {exc}"
        )

    # --------------------------------------------------------
    # Audit indexes
    # --------------------------------------------------------

    try:

        from app.models.audit_log import ensure_indexes

        ensure_indexes()

        print(
            "[OK] Audit indexes initialized"
        )

    except Exception as exc:

        print(
            "[WARNING] Audit indexes unavailable: "
            f"{type(exc).__name__}: {exc}"
        )

    # --------------------------------------------------------
    # Remediation indexes
    # --------------------------------------------------------

    try:

        from app.models.remediation import ensure_indexes as ensure_remediation_indexes

        ensure_remediation_indexes()

        print(
            "[OK] Remediation indexes initialized"
        )

    except Exception as exc:

        print(
            "[WARNING] Remediation indexes unavailable: "
            f"{type(exc).__name__}: {exc}"
        )

    # --------------------------------------------------------
    # Organization usage indexes
    # --------------------------------------------------------

    try:

        from app.services.organization_usage_service import (
            initialize_usage_indexes
        )

        initialize_usage_indexes()

        print(
            "[OK] Organization usage indexes initialized"
        )

    except Exception as exc:

        print(
            "[WARNING] Organization usage indexes unavailable: "
            f"{type(exc).__name__}: {exc}"
        )

    # --------------------------------------------------------
    # Scan Job indexes
    # --------------------------------------------------------

    try:

        from app.services.scan_job_service import (
            initialize_scan_job_indexes
        )

        initialize_scan_job_indexes()

        print(
            "[OK] Scan job indexes initialized"
        )

    except Exception as exc:

        print(
            "[WARNING] Scan job indexes unavailable: "
            f"{type(exc).__name__}: {exc}"
        )

    # --------------------------------------------------------
    # Background scan worker
    # --------------------------------------------------------
    #
    # IMPORTANT:
    # Do NOT start the scan worker inside FastAPI.
    #
    # The standalone worker process is responsible for this:
    #
    #     python worker.py
    #

    print(
        "[OK] Background scan worker disabled "
        "(using standalone worker process)"
    )


# ============================================================
# SHUTDOWN
# ============================================================

@app.on_event("shutdown")
def shutdown_event():

    try:

        _stop_background_scan_worker()

    except Exception as exc:

        print(
            "[WARNING] Background scan worker shutdown "
            f"error: {type(exc).__name__}: {exc}"
        )


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=CORS_ORIGINS,

    allow_credentials=True,

    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],

    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Request-ID",
    ],

    expose_headers=[
        "X-Request-ID",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "Retry-After",
    ],
)


# ============================================================
# API ROUTERS
# ============================================================

app.include_router(
    auth_router,
    prefix="/auth",
    tags=["Authentication"]
)


app.include_router(
    cloud_router,
    prefix="/cloud",
    tags=["Cloud"]
)


app.include_router(
    dashboard_router,
    prefix="/dashboard",
    tags=["Dashboard"]
)


app.include_router(
    report_router,
    prefix="/report",
    tags=["Reports"]
)


app.include_router(
    ai_chat_router,
    prefix="/ai",
    tags=["AI Assistant"]
)


app.include_router(
    notification_router,
    prefix="/notifications",
    tags=["Notifications"]
)


app.include_router(
    compliance_router,
    prefix="/compliance",
    tags=["Compliance"]
)


app.include_router(
    aws_account_router,
    prefix="/aws",
    tags=["AWS Accounts"]
)


app.include_router(
    cost_optimizer_router,
    prefix="/cost",
    tags=["Cost Optimizer"]
)


# ============================================================
# FINDINGS
# ============================================================

app.include_router(
    findings_router
)


# ============================================================
# REMEDIATION
# ============================================================

app.include_router(
    remediation_router
)


# ============================================================
# REMEDIATION SETTINGS
# ============================================================

app.include_router(
    remediation_settings_router
)


# ============================================================
# SECURITY GRAPH
# ============================================================

app.include_router(
    security_graph_router
)


# ============================================================
# SECURITY CORRELATION
# ============================================================

app.include_router(
    security_correlation_router
)


# ============================================================
# AUDIT
# ============================================================

app.include_router(
    audit_router,
    tags=["Audit"]
)


# ============================================================
# ORGANIZATIONS
# ============================================================

app.include_router(
    organization_router
)


# ============================================================
# SUBSCRIPTIONS
# ============================================================

app.include_router(
    subscription_router
)


# ============================================================
# RAZORPAY WEBHOOKS
# ============================================================

app.include_router(
    razorpay_webhook_router
)


# ============================================================
# SCAN JOBS
# ============================================================

app.include_router(
    scan_jobs_router
)


# ============================================================
# SCAN WORKER
# ============================================================

app.include_router(
    scan_worker_router
)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "status": "success",
        "message": "Welcome to CloudGuardAI Backend"
    }


# ============================================================
# MONGODB TEST
# ============================================================

@app.get("/test-db")
def test_db():

    db.command(
        "ping"
    )

    return {
        "status": "success",
        "message": "MongoDB Connected Successfully"
    }
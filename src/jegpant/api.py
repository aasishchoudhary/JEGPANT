"""Private single-owner HTTP API for JEGPANT cases and asynchronous jobs.

Install the optional server dependencies with `pip install -e ".[server]"`.
No public registration, browser docs, CORS, or unauthenticated data routes exist.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .case_store import EncryptedCaseStore
from .job_queue import AnalysisJobQueue
from .owner_auth import (
    OwnerAuthorizationError,
    OwnerAuthorizationService,
    SignedDeviceRequest,
)
from .runtime import InvestigationEvidence


AUTH_HEADERS = {
    "instance_id": "x-jegpant-instance-id",
    "device_id": "x-jegpant-device-id",
    "request_id": "x-jegpant-request-id",
    "issued_at": "x-jegpant-issued-at",
    "expires_at": "x-jegpant-expires-at",
    "body_sha256": "x-jegpant-body-sha256",
    "signature": "x-jegpant-signature",
}


@dataclass(frozen=True, slots=True)
class PrivateAPIConfig:
    max_json_body_bytes: int = 1024 * 1024


def create_app(
    *,
    authorization: OwnerAuthorizationService,
    cases: EncryptedCaseStore,
    jobs: AnalysisJobQueue,
    config: PrivateAPIConfig | None = None,
) -> FastAPI:
    """Build the owner-only API from already initialised security/storage services."""
    config = config or PrivateAPIConfig()
    if config.max_json_body_bytes <= 0:
        raise ValueError("max_json_body_bytes must be positive")
    instance_id = authorization.instance_id
    if cases.instance_id != instance_id or jobs.instance_id != instance_id:
        raise ValueError("API services must belong to the same cognitive instance")

    app = FastAPI(
        title="JEGPANT Private Runtime",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    async def read_body(request: Request) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > config.max_json_body_bytes:
                raise HTTPException(status_code=413, detail="Request body too large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def authenticate(
        request: Request,
        *,
        body: bytes,
        required_scope: str,
    ) -> None:
        values = {
            name: request.headers.get(header)
            for name, header in AUTH_HEADERS.items()
        }
        if any(value is None for value in values.values()):
            raise HTTPException(status_code=401, detail="Device authentication required")
        signed = SignedDeviceRequest(
            instance_id=values["instance_id"] or "",
            device_id=values["device_id"] or "",
            request_id=values["request_id"] or "",
            method=request.method,
            path=request.url.path,
            issued_at=values["issued_at"] or "",
            expires_at=values["expires_at"] or "",
            body_sha256=values["body_sha256"] or "",
            signature_b64=values["signature"] or "",
        )
        try:
            await run_in_threadpool(
                authorization.verify_request,
                signed,
                body=body,
                required_scope=required_scope,
            )
        except OwnerAuthorizationError:
            raise HTTPException(
                status_code=403,
                detail="Device request is not authorised",
            ) from None
        except RuntimeError:
            raise HTTPException(
                status_code=503,
                detail="Authorisation state is temporarily unavailable",
            ) from None

    async def parse_json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(status_code=400, detail="Invalid JSON body") from None
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="JSON body must be an object")
        return payload

    @app.get("/health/live", include_in_schema=False)
    async def health_live() -> dict[str, str]:
        # Liveness only; does not reveal case counts, owner IDs, or dependency state.
        return {"status": "alive"}

    @app.post("/v1/cases", status_code=201)
    async def create_case(request: Request):
        body = await read_body(request)
        await authenticate(request, body=body, required_scope="create_case")
        payload = await parse_json(body)
        if payload:
            raise HTTPException(status_code=400, detail="Case creation body must be empty")
        case_id = await run_in_threadpool(cases.create_case)
        return {"case_id": case_id, "status": "created"}

    @app.post("/v1/cases/{case_id}/evidence", status_code=201)
    async def add_evidence(case_id: str, request: Request):
        body = await read_body(request)
        await authenticate(request, body=body, required_scope="write_evidence")
        payload = await parse_json(body)
        required = {
            "record_id",
            "source_ref",
            "independence_group",
            "observation",
        }
        if not required <= payload.keys():
            raise HTTPException(status_code=400, detail="Evidence fields are incomplete")
        allowed = required | {
            "quality_level",
            "source_start_ms",
            "source_end_ms",
            "limitations",
        }
        if set(payload) - allowed:
            raise HTTPException(status_code=400, detail="Unsupported evidence fields")
        try:
            evidence = InvestigationEvidence(
                record_id=payload["record_id"],
                source_ref=payload["source_ref"],
                independence_group=payload["independence_group"],
                observation=payload["observation"],
                quality_level=payload.get("quality_level", 2),
                source_start_ms=payload.get("source_start_ms"),
                source_end_ms=payload.get("source_end_ms"),
                limitations=tuple(payload.get("limitations", [])),
            )
            await run_in_threadpool(cases.add_evidence, case_id, evidence)
        except KeyError:
            raise HTTPException(status_code=404, detail="Case not found") from None
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Evidence validation failed") from None
        return {"record_id": evidence.record_id, "status": "stored"}

    @app.get("/v1/cases/{case_id}/evidence")
    async def list_evidence(case_id: str, request: Request):
        body = await read_body(request)
        await authenticate(request, body=body, required_scope="read_evidence")
        try:
            items = await run_in_threadpool(cases.list_evidence, case_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Case not found") from None
        return {
            "case_id": case_id,
            "evidence": [
                {
                    "record_id": item.record_id,
                    "source_ref": item.source_ref,
                    "independence_group": item.independence_group,
                    "observation": item.observation,
                    "quality_level": item.quality_level,
                    "source_start_ms": item.source_start_ms,
                    "source_end_ms": item.source_end_ms,
                    "limitations": list(item.limitations),
                }
                for item in items
            ],
        }

    @app.post("/v1/cases/{case_id}/investigations", status_code=202)
    async def enqueue_investigation(case_id: str, request: Request):
        body = await read_body(request)
        await authenticate(request, body=body, required_scope="queue_analysis")
        payload = await parse_json(body)
        if set(payload) - {"goal", "max_attempts"} or "goal" not in payload:
            raise HTTPException(status_code=400, detail="Investigation request is invalid")
        if not await run_in_threadpool(cases.case_exists, case_id):
            raise HTTPException(status_code=404, detail="Case not found")
        try:
            job_id = await run_in_threadpool(
                jobs.enqueue,
                case_id=case_id,
                goal=payload["goal"],
                max_attempts=payload.get("max_attempts", 3),
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Investigation request is invalid") from None
        return {"job_id": job_id, "case_id": case_id, "status": "queued"}

    @app.get("/v1/jobs/{job_id}")
    async def get_job(job_id: str, request: Request):
        body = await read_body(request)
        await authenticate(request, body=body, required_scope="read_jobs")
        try:
            status = await run_in_threadpool(jobs.get_status, job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Job not found") from None
        return {
            "job_id": status.job_id,
            "case_id": status.case_id,
            "status": status.status,
            "attempts": status.attempts,
            "max_attempts": status.max_attempts,
            "created_at": status.created_at,
            "updated_at": status.updated_at,
            "result_id": status.result_id,
            "error_code": status.error_code,
        }

    @app.get("/v1/cases/{case_id}/reports/{investigation_id}")
    async def get_report(case_id: str, investigation_id: str, request: Request):
        body = await read_body(request)
        await authenticate(request, body=body, required_scope="read_reports")
        try:
            report = await run_in_threadpool(
                cases.get_result,
                case_id,
                investigation_id,
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="Report not found") from None
        return JSONResponse(report)

    @app.exception_handler(HTTPException)
    async def http_error_handler(request: Request, exc: HTTPException):
        del request
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    return app

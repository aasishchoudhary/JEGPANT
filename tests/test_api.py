import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from jegpant.api import PrivateAPIConfig, create_app
from jegpant.case_store import EncryptedCaseStore
from jegpant.inference import ChatResponse
from jegpant.job_queue import AnalysisJobQueue
from jegpant.media_vault import EncryptedMediaVault
from jegpant.owner_auth import (
    DeviceEnrollment,
    OwnerAuthorizationService,
    enrollment_signing_bytes,
    request_signing_bytes,
)
from jegpant.owner_state_store import InMemoryOwnerStateStore
from jegpant.runtime import CognitiveRuntime
from jegpant.worker import AnalysisWorker


INSTANCE_ID = str(uuid4())


class FakeKeyProvider:
    def get_key(self, version):
        return b"a" * 32


class QueueClient:
    def __init__(self):
        self.responses = [
            {
                "hypotheses": [
                    {
                        "id": "h1",
                        "statement": "A person opened the door.",
                        "supporting_evidence_ids": ["e1"],
                        "contradicting_evidence_ids": [],
                        "assumptions": [],
                        "discriminating_questions": [],
                    },
                    {
                        "id": "h2",
                        "statement": "A mechanical fault moved the door.",
                        "supporting_evidence_ids": [],
                        "contradicting_evidence_ids": ["e1"],
                        "assumptions": [],
                        "discriminating_questions": [],
                    },
                ],
                "unresolved_questions": [],
            },
            {
                "judgements": [
                    {
                        "hypothesis_id": "h1",
                        "evidence_id": "e1",
                        "rating": "consistent",
                        "diagnosticity": 2,
                        "rationale": "The observation is compatible.",
                    },
                    {
                        "hypothesis_id": "h2",
                        "evidence_id": "e1",
                        "rating": "neutral",
                        "diagnosticity": 1,
                        "rationale": "The recording does not resolve the cause.",
                    },
                ],
                "review_notes": ["Verify the observation against the original."],
            },
        ]

    def complete(self, messages, *, temperature=0.0, max_tokens=2048):
        return ChatResponse(json.dumps(self.responses.pop(0)), "api-test-model")


def public_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def make_signed_headers(
    owner_key,
    device_key,
    *,
    device_id,
    method,
    path,
    body=b"",
    request_id=None,
):
    del owner_key
    now = datetime.now(UTC)
    signed = {
        "instance_id": INSTANCE_ID,
        "device_id": device_id,
        "request_id": request_id or str(uuid4()),
        "method": method,
        "path": path,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=45)).isoformat(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "signature_b64": "",
    }
    from jegpant.owner_auth import SignedDeviceRequest

    request = SignedDeviceRequest(**signed)
    signature = base64.b64encode(
        device_key.sign(request_signing_bytes(request))
    ).decode("ascii")
    return {
        "X-Jegpant-Instance-Id": INSTANCE_ID,
        "X-Jegpant-Device-Id": device_id,
        "X-Jegpant-Request-Id": signed["request_id"],
        "X-Jegpant-Issued-At": signed["issued_at"],
        "X-Jegpant-Expires-At": signed["expires_at"],
        "X-Jegpant-Body-Sha256": signed["body_sha256"],
        "X-Jegpant-Signature": signature,
    }


def setup_api(
    tmp_path,
    *,
    scopes=None,
    max_body_bytes=1024 * 1024,
    max_media_upload_bytes=8 * 1024 * 1024 * 1024,
):
    owner_key = Ed25519PrivateKey.generate()
    device_key = Ed25519PrivateKey.generate()
    device_id = str(uuid4())
    state_store = InMemoryOwnerStateStore(INSTANCE_ID)
    authorization = OwnerAuthorizationService(
        instance_id=INSTANCE_ID,
        owner_public_key=public_bytes(owner_key),
        state_store=state_store,
    )

    now = datetime.now(UTC)
    enrollment = DeviceEnrollment(
        instance_id=INSTANCE_ID,
        device_id=device_id,
        device_public_key_b64=base64.b64encode(public_bytes(device_key)).decode(),
        scopes=scopes
        or (
            "create_case",
            "write_evidence",
            "read_evidence",
            "queue_analysis",
            "read_jobs",
            "read_reports",
            "ingest_media",
        ),
        enrollment_id=str(uuid4()),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=3)).isoformat(),
        owner_signature_b64="",
        device_proof_b64="",
    )
    payload = enrollment_signing_bytes(enrollment)
    enrollment = replace(
        enrollment,
        owner_signature_b64=base64.b64encode(owner_key.sign(payload)).decode(),
        device_proof_b64=base64.b64encode(device_key.sign(payload)).decode(),
    )
    authorization.enroll_device(enrollment)

    cases = EncryptedCaseStore(
        tmp_path / "cases.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
    )
    jobs = AnalysisJobQueue(
        tmp_path / "jobs.sqlite",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
    )
    media_vault = EncryptedMediaVault(
        tmp_path / "media-vault",
        instance_id=INSTANCE_ID,
        key_provider=FakeKeyProvider(),
        chunk_size=64 * 1024,
    )
    app = create_app(
        authorization=authorization,
        cases=cases,
        jobs=jobs,
        media_vault=media_vault,
        config=PrivateAPIConfig(
            max_json_body_bytes=max_body_bytes,
            max_media_upload_bytes=max_media_upload_bytes,
        ),
    )
    app.state.media_vault = media_vault
    return TestClient(app), owner_key, device_key, device_id, cases, jobs


def test_private_api_end_to_end_case_evidence_job_and_report(tmp_path):
    client, owner_key, device_key, device_id, cases, jobs = setup_api(tmp_path)

    case_body = b"{}"
    response = client.post(
        "/v1/cases",
        content=case_body,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=case_body,
        ),
    )
    assert response.status_code == 201
    case_id = response.json()["case_id"]

    evidence_body = json.dumps(
        {
            "record_id": "e1",
            "source_ref": "video://asset-1",
            "independence_group": "camera-1",
            "observation": "Door moves inward at 00:01:10.",
            "quality_level": 3,
            "source_start_ms": 70000,
            "source_end_ms": 72000,
            "limitations": ["Partial handle view."],
        },
        separators=(",", ":"),
    ).encode()
    evidence_response = client.post(
        f"/v1/cases/{case_id}/evidence",
        content=evidence_body,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path=f"/v1/cases/{case_id}/evidence",
            body=evidence_body,
        ),
    )
    assert evidence_response.status_code == 201

    get_evidence_response = client.get(
        f"/v1/cases/{case_id}/evidence",
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="GET",
            path=f"/v1/cases/{case_id}/evidence",
            body=b"",
        ),
    )
    assert get_evidence_response.status_code == 200
    assert get_evidence_response.json()["evidence"][0]["record_id"] == "e1"

    job_body = b'{"goal":"Explain the door movement.","max_attempts":2}'
    job_response = client.post(
        f"/v1/cases/{case_id}/investigations",
        content=job_body,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path=f"/v1/cases/{case_id}/investigations",
            body=job_body,
        ),
    )
    assert job_response.status_code == 202
    job_id = job_response.json()["job_id"]
    assert jobs.get_status(job_id).status == "pending"

    outcome = AnalysisWorker(
        queue=jobs,
        case_store=cases,
        runtime=CognitiveRuntime(QueueClient()),
        worker_id="api-test-worker",
        lease_seconds=30,
    ).process_one()
    assert outcome.status == "completed"

    status_response = client.get(
        f"/v1/jobs/{job_id}",
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="GET",
            path=f"/v1/jobs/{job_id}",
            body=b"",
        ),
    )
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "completed"

    report_path = f"/v1/cases/{case_id}/reports/{outcome.result_id}"
    report_response = client.get(
        report_path,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="GET",
            path=report_path,
            body=b"",
        ),
    )
    assert report_response.status_code == 200
    assert report_response.json()["human_review_required"] is True


def test_private_api_denies_missing_and_invalid_device_signatures(tmp_path):
    client, owner_key, device_key, device_id, _, _ = setup_api(tmp_path)
    response = client.post("/v1/cases", content=b"{}")
    assert response.status_code == 401

    headers = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="POST",
        path="/v1/cases",
        body=b"{}",
    )
    headers["X-Jegpant-Signature"] = base64.b64encode(b"invalid").decode()
    denied = client.post("/v1/cases", content=b"{}", headers=headers)
    assert denied.status_code == 403


def test_private_api_enforces_least_privilege_scope(tmp_path):
    client, owner_key, device_key, device_id, _, _ = setup_api(
        tmp_path, scopes=("read_evidence",)
    )
    response = client.post(
        "/v1/cases",
        content=b"{}",
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=b"{}",
        ),
    )
    assert response.status_code == 403


def test_private_api_detects_body_tampering_and_request_replay(tmp_path):
    client, owner_key, device_key, device_id, cases, _ = setup_api(tmp_path)
    headers = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="POST",
        path="/v1/cases",
        body=b"{}",
    )
    tampered = client.post("/v1/cases", content=b'{"case_id":"wrong"}', headers=headers)
    assert tampered.status_code == 403

    fresh = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="POST",
        path="/v1/cases",
        body=b"{}",
    )
    created = client.post("/v1/cases", content=b"{}", headers=fresh)
    replay = client.post("/v1/cases", content=b"{}", headers=fresh)
    assert created.status_code == 201
    assert replay.status_code == 403


def test_private_api_disables_openapi_and_documentation(tmp_path):
    client, *_ = setup_api(tmp_path)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_private_api_limits_json_body_size(tmp_path):
    client, owner_key, device_key, device_id, _, _ = setup_api(
        tmp_path, max_body_bytes=16
    )
    body = b'{"payload":"this is too large"}'
    response = client.post(
        "/v1/cases",
        content=body,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=body,
        ),
    )
    assert response.status_code == 413



def test_private_api_streams_media_to_encrypted_vault_and_lists_metadata(tmp_path):
    client, owner_key, device_key, device_id, cases, _ = setup_api(tmp_path)
    case_body = b"{}"
    created = client.post(
        "/v1/cases",
        content=case_body,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=case_body,
        ),
    )
    case_id = created.json()["case_id"]

    data = bytes(range(256)) * 1024
    digest = hashlib.sha256(data).hexdigest()
    asset_id = str(uuid4())
    path = f"/v1/cases/{case_id}/media/{asset_id}"
    headers = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="PUT",
        path=path,
        body=data,
    )
    headers["X-Jegpant-Content-Sha256"] = digest
    headers["X-Jegpant-Content-Length"] = str(len(data))

    uploaded = client.put(path, content=data, headers=headers)
    assert uploaded.status_code == 201
    assert uploaded.json()["asset_id"] == asset_id
    assert uploaded.json()["sha256"] == digest

    encrypted_path = client.app.state.media_vault._asset_path(asset_id)
    assert encrypted_path.exists()
    assert data not in encrypted_path.read_bytes()

    listed_path = f"/v1/cases/{case_id}/media"
    listed = client.get(
        listed_path,
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="GET",
            path=listed_path,
            body=b"",
        ),
    )
    assert listed.status_code == 200
    assert listed.json()["media_assets"][0]["asset_id"] == asset_id
    assert cases.media_asset_exists(case_id, asset_id)


def test_private_api_rejects_media_digest_mismatch_and_removes_partial_asset(tmp_path):
    client, owner_key, device_key, device_id, cases, _ = setup_api(tmp_path)
    created = client.post(
        "/v1/cases",
        content=b"{}",
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=b"{}",
        ),
    )
    case_id = created.json()["case_id"]

    data = b"payload whose signed digest will be wrong" * 1000
    asset_id = str(uuid4())
    path = f"/v1/cases/{case_id}/media/{asset_id}"
    headers = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="PUT",
        path=path,
        body=b"x" * len(data),
    )
    headers["X-Jegpant-Content-Sha256"] = hashlib.sha256(b"x" * len(data)).hexdigest()
    headers["X-Jegpant-Content-Length"] = str(len(data))

    response = client.put(path, content=data, headers=headers)
    assert response.status_code == 400
    assert not client.app.state.media_vault._asset_path(asset_id).exists()
    assert not cases.media_asset_exists(case_id, asset_id)


def test_private_api_requires_ingest_media_scope(tmp_path):
    scopes = (
        "create_case",
        "write_evidence",
        "read_evidence",
        "queue_analysis",
        "read_jobs",
        "read_reports",
    )
    client, owner_key, device_key, device_id, _, _ = setup_api(
        tmp_path, scopes=scopes
    )
    case = client.post(
        "/v1/cases",
        content=b"{}",
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=b"{}",
        ),
    )
    assert case.status_code == 201
    case_id = case.json()["case_id"]
    data = b"small media upload"
    asset_id = str(uuid4())
    path = f"/v1/cases/{case_id}/media/{asset_id}"
    headers = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="PUT",
        path=path,
        body=data,
    )
    headers["X-Jegpant-Content-Sha256"] = hashlib.sha256(data).hexdigest()
    headers["X-Jegpant-Content-Length"] = str(len(data))

    response = client.put(path, content=data, headers=headers)
    assert response.status_code == 403


def test_private_api_rejects_upload_length_over_limit(tmp_path):
    client, owner_key, device_key, device_id, _, _ = setup_api(
        tmp_path, max_body_bytes=1024, max_media_upload_bytes=1024
    )
    case = client.post(
        "/v1/cases",
        content=b"{}",
        headers=make_signed_headers(
            owner_key,
            device_key,
            device_id=device_id,
            method="POST",
            path="/v1/cases",
            body=b"{}",
        ),
    )
    case_id = case.json()["case_id"]
    data = b"x" * 1025
    asset_id = str(uuid4())
    path = f"/v1/cases/{case_id}/media/{asset_id}"
    headers = make_signed_headers(
        owner_key,
        device_key,
        device_id=device_id,
        method="PUT",
        path=path,
        body=data,
    )
    headers["X-Jegpant-Content-Sha256"] = hashlib.sha256(data).hexdigest()
    headers["X-Jegpant-Content-Length"] = str(len(data))
    response = client.put(path, content=data, headers=headers)
    assert response.status_code == 413

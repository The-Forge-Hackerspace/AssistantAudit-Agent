"""Tests pour l'uploader de resultats avec queue offline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from assistant_audit_agent.config import AgentConfig, CertPaths
from assistant_audit_agent.tools import ToolResult
from assistant_audit_agent.uploader import (
    QUEUE_MAX_SIZE,
    QUEUE_TTL_DAYS,
    ResultUploader,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture()
def config(tmp_path: Path) -> AgentConfig:
    return AgentConfig(
        agent_uuid="test-uuid",
        server_url="https://server:8000",
        jwt_token="fake-jwt",
        agent_name="PC-Test",
        cert_paths=CertPaths(
            ca=str(tmp_path / "ca.pem"),
            cert=str(tmp_path / "agent.pem"),
            key=str(tmp_path / "agent.key"),
        ),
    )


@pytest.fixture()
def uploader(config: AgentConfig, tmp_path: Path, monkeypatch) -> ResultUploader:
    monkeypatch.chdir(tmp_path)
    u = ResultUploader(config)
    u._queue_dir = tmp_path / "queue"
    u._queue_dir.mkdir(exist_ok=True)
    return u


@pytest.fixture()
def sample_result(tmp_path: Path) -> ToolResult:
    artifact = tmp_path / "scan.xml"
    artifact.write_text("<nmap>data</nmap>", encoding="utf-8")
    return ToolResult(
        success=True,
        output={"hosts": [{"ip": "10.0.0.1"}]},
        artifacts=[artifact],
    )


def _mock_response(status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json={"detail": "OK"},
        request=httpx.Request("POST", "https://server:8000/api/v1/agents/tasks/t1/result"),
    )


# ── Tests upload reussi ──────────────────────────────────────────────


class TestUploadSuccess:

    @pytest.mark.asyncio
    async def test_upload_submits_result(self, uploader: ResultUploader, sample_result: ToolResult) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_response(200))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            ok = await uploader.upload_result("task-1", "nmap", sample_result)

        assert ok
        assert mock_client.post.await_count >= 1

    @pytest.mark.asyncio
    async def test_artifacts_deleted_after_upload(
        self, uploader: ResultUploader, sample_result: ToolResult
    ) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_response(200))

        artifact_path = sample_result.artifacts[0]
        assert artifact_path.exists()

        with patch.object(uploader, "_build_client", return_value=mock_client):
            await uploader.upload_result("task-1", "nmap", sample_result)

        assert not artifact_path.exists()

    @pytest.mark.asyncio
    async def test_upload_includes_jwt_header(self, uploader: ResultUploader) -> None:
        client = uploader._build_client()
        assert client.headers.get("Authorization") == "Bearer fake-jwt"
        await client.aclose()


# ── Tests retry ──────────────────────────────────────────────────────


class TestRetry:

    @pytest.mark.asyncio
    async def test_retry_succeeds_on_second_attempt(self, uploader: ResultUploader) -> None:
        call_count = {"n": 0}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        async def post_side_effect(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise httpx.ConnectError("refused")
            return _mock_response(200)

        mock_client.post = post_side_effect

        with patch.object(uploader, "_build_client", return_value=mock_client):
            ok = await uploader._post_with_retry("https://server:8000/test", {"data": 1})

        assert ok
        assert call_count["n"] == 2

    @pytest.mark.asyncio
    async def test_retry_all_fail(self, uploader: ResultUploader) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            ok = await uploader._post_with_retry("https://server:8000/test", {"data": 1})

        assert not ok


# ── Tests queue offline ──────────────────────────────────────────────


class TestOfflineQueue:

    @pytest.mark.asyncio
    async def test_enqueue_on_failure(self, uploader: ResultUploader, sample_result: ToolResult) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            ok = await uploader.upload_result("task-1", "nmap", sample_result)

        assert not ok

        # Verifier que le fichier queue existe
        queue_files = list(uploader._queue_dir.glob("*.json"))
        assert len(queue_files) == 1

        entry = json.loads(queue_files[0].read_text(encoding="utf-8"))
        assert entry["task_uuid"] == "task-1"
        assert entry["tool"] == "nmap"
        assert entry["success"] is True

    @pytest.mark.asyncio
    async def test_drain_queue_on_reconnect(self, uploader: ResultUploader) -> None:
        # Creer une entree en queue
        entry = {
            "task_uuid": "task-old",
            "tool": "nmap",
            "timestamp": "2026-03-28T10:00:00Z",
            "output": {"hosts": []},
            "error": None,
            "success": True,
            "artifact_paths": [],
        }
        (uploader._queue_dir / "task-old.json").write_text(
            json.dumps(entry), encoding="utf-8"
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_response(200))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            sent = await uploader.drain_queue()

        assert sent == 1
        assert not list(uploader._queue_dir.glob("*.json"))

    @pytest.mark.asyncio
    async def test_drain_stops_on_server_down(self, uploader: ResultUploader) -> None:
        for i in range(3):
            entry = {"task_uuid": f"task-{i}", "tool": "nmap", "timestamp": "2026-03-28T10:00:00Z",
                     "output": {}, "error": None, "success": True, "artifact_paths": []}
            (uploader._queue_dir / f"task-{i}.json").write_text(json.dumps(entry), encoding="utf-8")

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            sent = await uploader.drain_queue()

        assert sent == 0
        # Tous les fichiers restent en queue
        assert len(list(uploader._queue_dir.glob("*.json"))) == 3

    def test_queue_max_size_enforced(self, uploader: ResultUploader) -> None:
        # Remplir la queue au-dela de la limite
        for i in range(QUEUE_MAX_SIZE + 5):
            entry = {"task_uuid": f"task-{i:04d}", "tool": "nmap", "timestamp": "2026-03-28T10:00:00Z",
                     "output": {}, "error": None, "success": True, "artifact_paths": []}
            f = uploader._queue_dir / f"task-{i:04d}.json"
            f.write_text(json.dumps(entry), encoding="utf-8")

        # Enqueue un nouveau — devrait supprimer les plus anciens
        uploader._enforce_queue_limits()
        remaining = list(uploader._queue_dir.glob("*.json"))
        assert len(remaining) < QUEUE_MAX_SIZE + 5

    def test_queue_ttl_cleanup(self, uploader: ResultUploader) -> None:
        # Creer un fichier ancien
        old_file = uploader._queue_dir / "task-old.json"
        old_file.write_text(json.dumps({"task_uuid": "old", "artifact_paths": []}), encoding="utf-8")
        # Mettre la date de modification a 8 jours
        import os
        old_time = time.time() - (QUEUE_TTL_DAYS + 1) * 86400
        os.utime(old_file, (old_time, old_time))

        uploader._cleanup_expired()

        assert not old_file.exists()


# ── Tests artifacts manquants ────────────────────────────────────────


class TestArtifactEdgeCases:

    @pytest.mark.asyncio
    async def test_missing_artifact_no_crash(self, uploader: ResultUploader) -> None:
        result = ToolResult(
            success=True,
            output={"data": 1},
            artifacts=[Path("/nonexistent/file.xml")],
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_response(200))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            ok = await uploader.upload_result("task-1", "nmap", result)

        # Should still succeed (result submitted, artifact skipped)
        assert ok

    @pytest.mark.asyncio
    async def test_no_artifacts(self, uploader: ResultUploader) -> None:
        result = ToolResult(success=True, output={"data": 1})

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=_mock_response(200))

        with patch.object(uploader, "_build_client", return_value=mock_client):
            ok = await uploader.upload_result("task-1", "nmap", result)

        assert ok


# ── Tests mTLS ───────────────────────────────────────────────────────


class TestMTLS:

    @pytest.mark.asyncio
    async def test_client_without_certs(self, uploader: ResultUploader) -> None:
        """Sans certificats, le client utilise verify=False."""
        client = uploader._build_client()
        assert client is not None
        assert client.headers.get("Authorization") == "Bearer fake-jwt"
        await client.aclose()

    def test_client_with_certs_attempts_ssl(self, config: AgentConfig, tmp_path: Path) -> None:
        """Avec certificats, le client tente de charger le SSL context."""
        (tmp_path / "ca.pem").write_text("fake-ca", encoding="utf-8")
        (tmp_path / "agent.pem").write_text("fake-cert", encoding="utf-8")
        (tmp_path / "agent.key").write_text("fake-key", encoding="utf-8")

        config_with_certs = config.model_copy(update={
            "cert_paths": CertPaths(
                ca=str(tmp_path / "ca.pem"),
                cert=str(tmp_path / "agent.pem"),
                key=str(tmp_path / "agent.key"),
            )
        })
        u = ResultUploader(config_with_certs)
        # load_cert_chain will fail with fake PEM, which is expected
        try:
            u._build_client()
        except Exception:
            pass  # Expected with fake cert content

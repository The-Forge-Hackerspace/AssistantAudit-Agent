"""Tests pour le dispatcher de tâches (TaskRunner)."""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from assistant_audit_agent.config import AgentConfig
from assistant_audit_agent.task_runner import TaskRunner, setup_task_runner
from assistant_audit_agent.tools import OnProgressCallback, ToolBase, ToolResult
from assistant_audit_agent.websocket_client import AgentWebSocketClient


# ── Fixtures ─────────────────────────────────────────────────────────


class FakeTool(ToolBase):
    """Outil factice pour les tests."""

    def __init__(
        self,
        tool_name: str = "nmap",
        result: ToolResult | None = None,
        delay: float = 0.0,
        timeout: int = 3600,
    ) -> None:
        self._name = tool_name
        self._result = result or ToolResult(success=True, output={"hosts": 3})
        self._delay = delay
        self._timeout = timeout
        self._cancelled = False
        self.execute_called = False
        self.execute_params: dict = {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def default_timeout(self) -> int:
        return self._timeout

    async def execute(
        self, task_id: str, parameters: dict, on_progress: OnProgressCallback | None = None
    ) -> ToolResult:
        self.execute_called = True
        self.execute_params = parameters
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        if on_progress is not None:
            await on_progress(50, ["scan en cours..."])
        return self._result

    async def cancel(self) -> None:
        self._cancelled = True


class SlowTool(ToolBase):
    """Outil qui prend longtemps (pour tester timeout et cancel)."""

    def __init__(self, tool_name: str = "nmap") -> None:
        self._name = tool_name
        self._cancelled = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def default_timeout(self) -> int:
        return 1  # 1 seconde pour les tests

    async def execute(
        self, task_id: str, parameters: dict, on_progress: OnProgressCallback | None = None
    ) -> ToolResult:
        await asyncio.sleep(10)  # Beaucoup trop long → timeout
        return ToolResult(success=True)

    async def cancel(self) -> None:
        self._cancelled = True


class FailingTool(ToolBase):
    """Outil qui lève une exception."""

    @property
    def name(self) -> str:
        return "nmap"

    async def execute(
        self, task_id: str, parameters: dict, on_progress: OnProgressCallback | None = None
    ) -> ToolResult:
        raise RuntimeError("Erreur inattendue dans l'outil")

    async def cancel(self) -> None:
        pass


@pytest.fixture()
def config() -> AgentConfig:
    return AgentConfig(
        agent_uuid="test-uuid",
        server_url="https://server:8000",
        jwt_token="fake-jwt",
        agent_name="PC-Test",
        allowed_tools=["nmap", "oradad", "ad_collector"],
    )


@pytest.fixture()
def client(config: AgentConfig) -> AgentWebSocketClient:
    c = AgentWebSocketClient(config)
    c.send = AsyncMock()
    return c


@pytest.fixture()
def runner(client: AgentWebSocketClient) -> TaskRunner:
    return TaskRunner(client, allowed_tools=["nmap", "oradad", "ad_collector"])


# ── Tests réception et dispatch ──────────────────────────────────────


class TestTaskDispatch:
    """Tests du dispatch des tâches vers les outils."""

    @pytest.mark.asyncio
    async def test_task_dispatched_to_correct_tool(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        tool = FakeTool("nmap")
        runner.register_tool(tool)

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1",
            "tool": "nmap",
            "parameters": {"targets": "192.168.1.0/24"},
        })

        # Attendre l'exécution
        await asyncio.sleep(0.1)

        assert tool.execute_called
        assert tool.execute_params == {"targets": "192.168.1.0/24"}

    @pytest.mark.asyncio
    async def test_status_running_sent(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        runner.register_tool(FakeTool("nmap"))

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1",
            "tool": "nmap",
            "parameters": {},
        })
        await asyncio.sleep(0.1)

        # Vérifier que "running" a été envoyé
        calls = client.send.call_args_list
        status_calls = [c for c in calls if c[0][0] == "task_status"]
        statuses = [c[0][1]["status"] for c in status_calls]
        assert "running" in statuses

    @pytest.mark.asyncio
    async def test_status_completed_on_success(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        runner.register_tool(FakeTool("nmap"))

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1",
            "tool": "nmap",
            "parameters": {},
        })
        await asyncio.sleep(0.1)

        calls = client.send.call_args_list
        status_calls = [c for c in calls if c[0][0] == "task_status"]
        statuses = [c[0][1]["status"] for c in status_calls]
        assert "completed" in statuses

    @pytest.mark.asyncio
    async def test_result_sent_on_success(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        runner.register_tool(FakeTool("nmap", result=ToolResult(success=True, output={"hosts": 5})))

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1",
            "tool": "nmap",
            "parameters": {},
        })
        await asyncio.sleep(0.1)

        result_calls = [c for c in client.send.call_args_list if c[0][0] == "task_result"]
        assert len(result_calls) == 1
        assert result_calls[0][0][1]["result_summary"] == {"hosts": 5}

    @pytest.mark.asyncio
    async def test_agent_free_after_completion(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        runner.register_tool(FakeTool("nmap"))

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })
        await asyncio.sleep(0.1)

        assert not runner.is_busy
        assert runner.current_task_id is None


# ── Tests rejets ─────────────────────────────────────────────────────


class TestTaskRejection:
    """Tests des cas de rejet."""

    @pytest.mark.asyncio
    async def test_unauthorized_tool_rejected(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1",
            "tool": "metasploit",
            "parameters": {},
        })

        calls = client.send.call_args_list
        assert any(
            c[0][0] == "task_status" and c[0][1]["status"] == "rejected"
            for c in calls
        )

    @pytest.mark.asyncio
    async def test_unknown_tool_rejected(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        """Outil autorisé mais pas enregistré → rejected."""
        # nmap est dans allowed_tools mais pas enregistré
        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1",
            "tool": "nmap",
            "parameters": {},
        })

        calls = client.send.call_args_list
        assert any(
            c[0][0] == "task_status" and c[0][1]["status"] == "rejected"
            for c in calls
        )

    @pytest.mark.asyncio
    async def test_busy_rejection(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        """Si une tâche tourne déjà → busy."""
        runner.register_tool(FakeTool("nmap", delay=1.0))

        # Première tâche
        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })

        # Deuxième tâche immédiatement
        await runner.handle_new_task("new_task", {
            "task_uuid": "task-2", "tool": "nmap", "parameters": {},
        })

        calls = client.send.call_args_list
        busy_calls = [
            c for c in calls
            if c[0][0] == "task_status"
            and c[0][1].get("task_uuid") == "task-2"
            and c[0][1]["status"] == "busy"
        ]
        assert len(busy_calls) == 1

        # Cleanup
        if runner._execution_task:
            runner._execution_task.cancel()
            try:
                await runner._execution_task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_incomplete_message_ignored(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        await runner.handle_new_task("new_task", {"tool": "nmap"})
        # Pas de crash, pas d'envoi
        assert client.send.call_count == 0


# ── Tests échecs et timeout ──────────────────────────────────────────


class TestTaskFailure:
    """Tests des cas d'échec."""

    @pytest.mark.asyncio
    async def test_tool_exception_sends_failed(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        runner.register_tool(FailingTool())

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })
        await asyncio.sleep(0.1)

        calls = client.send.call_args_list
        failed_calls = [
            c for c in calls
            if c[0][0] == "task_status" and c[0][1]["status"] == "failed"
        ]
        assert len(failed_calls) == 1
        assert "Erreur inattendue" in failed_calls[0][0][1]["error_message"]

    @pytest.mark.asyncio
    async def test_tool_returning_failure(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        runner.register_tool(FakeTool(
            "nmap",
            result=ToolResult(success=False, error="Permission denied"),
        ))

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })
        await asyncio.sleep(0.1)

        calls = client.send.call_args_list
        failed_calls = [
            c for c in calls
            if c[0][0] == "task_status" and c[0][1]["status"] == "failed"
        ]
        assert len(failed_calls) == 1
        assert "Permission denied" in failed_calls[0][0][1]["error_message"]

    @pytest.mark.asyncio
    async def test_timeout_kills_and_fails(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        slow = SlowTool("nmap")
        runner.register_tool(slow)

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })

        # Attendre au-delà du timeout (1s) + marge
        await asyncio.sleep(1.5)

        calls = client.send.call_args_list
        failed_calls = [
            c for c in calls
            if c[0][0] == "task_status" and c[0][1]["status"] == "failed"
        ]
        assert len(failed_calls) == 1
        assert "Timeout" in failed_calls[0][0][1]["error_message"]
        assert not runner.is_busy


# ── Tests annulation ─────────────────────────────────────────────────


class TestTaskCancel:
    """Tests de l'annulation des tâches."""

    @pytest.mark.asyncio
    async def test_cancel_running_task(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        slow = SlowTool("nmap")
        runner.register_tool(slow)

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })
        await asyncio.sleep(0.05)
        assert runner.is_busy

        await runner.handle_cancel("task_cancel", {"task_uuid": "task-1"})
        await asyncio.sleep(0.1)

        calls = client.send.call_args_list
        cancel_calls = [
            c for c in calls
            if c[0][0] == "task_status" and c[0][1]["status"] == "cancelled"
        ]
        assert len(cancel_calls) == 1
        assert not runner.is_busy
        assert slow._cancelled

    @pytest.mark.asyncio
    async def test_cancel_unknown_task_ignored(
        self, runner: TaskRunner, client: AgentWebSocketClient, caplog
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="task_runner"):
            await runner.handle_cancel("task_cancel", {"task_uuid": "unknown"})
        assert "inconnue" in caplog.text


# ── Tests progression ────────────────────────────────────────────────


class TestTaskProgress:
    """Tests des mises à jour de progression."""

    @pytest.mark.asyncio
    async def test_progress_sent_during_execution(
        self, runner: TaskRunner, client: AgentWebSocketClient
    ) -> None:
        """Le callback on_progress doit envoyer des updates au serveur."""
        # Outil qui appelle on_progress immédiatement
        runner.register_tool(FakeTool("nmap"))

        # Le throttle est 5s, donc le premier appel passe toujours (last=0)
        await runner.handle_new_task("new_task", {
            "task_uuid": "task-1", "tool": "nmap", "parameters": {},
        })
        await asyncio.sleep(0.1)

        progress_calls = [
            c for c in client.send.call_args_list
            if c[0][0] == "task_progress"
        ]
        assert len(progress_calls) >= 1
        assert progress_calls[0][0][1]["progress"] == 50


# ── Tests setup ──────────────────────────────────────────────────────


class TestSetupTaskRunner:
    """Tests de la fonction setup_task_runner."""

    def test_registers_handlers(self, client: AgentWebSocketClient) -> None:
        setup_task_runner(client, ["nmap"])

        assert "new_task" in client._message_handlers
        assert "task_cancel" in client._message_handlers

    @pytest.mark.asyncio
    async def test_heartbeat_integration(
        self, client: AgentWebSocketClient
    ) -> None:
        """Le heartbeat doit refléter la tâche en cours."""
        heartbeat = MagicMock()
        heartbeat.set_current_task = MagicMock()

        runner = TaskRunner(client, ["nmap"], heartbeat=heartbeat)
        runner.register_tool(FakeTool("nmap"))

        await runner.handle_new_task("new_task", {
            "task_uuid": "task-42", "tool": "nmap", "parameters": {},
        })
        await asyncio.sleep(0.1)

        # set_current_task appelé avec task-42 puis None
        calls = heartbeat.set_current_task.call_args_list
        assert calls[0][0][0] == "task-42"
        assert calls[-1][0][0] is None

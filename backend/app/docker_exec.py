"""Thin async wrapper over the Docker Engine API, reached through docker-socket-proxy.

Only three capabilities are used, matching what the proxy allows:
list containers, exec (attached or detached), and inspect an exec's exit code.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass

import docker
from docker.errors import APIError, NotFound

log = logging.getLogger(__name__)

OutputCallback = Callable[[str], None]


@dataclass
class ExecResult:
    rc: int
    output: str


class DockerExec:
    def __init__(self, project: str):
        self.project = project
        self._client: docker.DockerClient | None = None

    @property
    def client(self) -> docker.DockerClient:
        # Lazy: the API must start (and report "stack stopped") even when the
        # socket proxy is not up yet. DOCKER_HOST=tcp://socket-proxy:2375
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------ discovery --
    def _running_sync(self) -> set[str]:
        cs = self.client.containers.list(filters={"label": f"com.docker.compose.project={self.project}",
                                                  "status": "running"})
        return {c.name for c in cs}

    async def running(self) -> set[str]:
        try:
            return await asyncio.to_thread(self._running_sync)
        except Exception as exc:  # proxy down, daemon unreachable...
            log.error("cannot list containers: %s", exc)
            return set()

    # ------------------------------------------------------------------ exec --
    def _exec_sync(self, container: str, argv: list[str], env: dict[str, str] | None,
                   on_output: OutputCallback | None, loop: asyncio.AbstractEventLoop | None) -> ExecResult:
        api = self.client.api
        try:
            ex = api.exec_create(container, argv, stdout=True, stderr=True, tty=False, environment=env or None)
        except NotFound as exc:
            return ExecResult(rc=127, output=f"container {container} not found: {exc}")
        except APIError as exc:
            return ExecResult(rc=126, output=f"exec create failed: {exc.explanation}")
        chunks: list[str] = []
        for out, err in api.exec_start(ex["Id"], stream=True, demux=True):
            for part in (out, err):
                if not part:
                    continue
                text = part.decode(errors="replace")
                chunks.append(text)
                if on_output and loop:
                    loop.call_soon_threadsafe(on_output, text)
        rc = api.exec_inspect(ex["Id"]).get("ExitCode")
        return ExecResult(rc=rc if rc is not None else -1, output="".join(chunks))

    async def exec(self, container: str, argv: list[str], env: dict[str, str] | None = None,
                   on_output: OutputCallback | None = None) -> ExecResult:
        loop = asyncio.get_running_loop()
        log.debug("exec %s: %s", container, argv)
        return await asyncio.to_thread(self._exec_sync, container, argv, env, on_output, loop)

    def _detach_sync(self, container: str, argv: list[str], env: dict[str, str] | None) -> ExecResult:
        api = self.client.api
        try:
            ex = api.exec_create(container, argv, stdout=False, stderr=False, tty=False, environment=env or None)
            api.exec_start(ex["Id"], detach=True)
            return ExecResult(rc=0, output=f"started in background: {' '.join(argv)}")
        except (NotFound, APIError) as exc:
            return ExecResult(rc=126, output=f"detached exec failed: {exc}")

    async def exec_detached(self, container: str, argv: list[str], env: dict[str, str] | None = None) -> ExecResult:
        return await asyncio.to_thread(self._detach_sync, container, argv, env)

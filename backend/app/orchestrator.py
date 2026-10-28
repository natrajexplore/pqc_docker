"""Run a scenario end to end: exec steps, live capture, analysis, verdict.

Event types published on the RunBus (and forwarded verbatim to the UI WebSocket):
    run.status     {status, error?}
    step.status    {step: StepState}
    step.output    {step_id, text}
    packet         {packet: NormalizedPacket}
    run.result     {metrics, verdict, assertions}
"""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from pathlib import Path

from .analyzer import deep
from .analyzer.normalize import Endpoint, Normalizer
from .analyzer.verdict import compute_metrics, compute_verdict, evaluate
from .bus import RunBus
from .capture_client import CaptureClient
from .config import Settings
from .docker_exec import DockerExec
from .models import Run, Scenario, Step, StepState
from .scenarios import ScenarioStore

log = logging.getLogger(__name__)
VAR_RE = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class StepFailed(Exception):
    pass


def render(value, variables: dict[str, str]):
    if isinstance(value, str):
        return VAR_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), value)
    if isinstance(value, list):
        return [render(v, variables) for v in value]
    return value


class Orchestrator:
    def __init__(self, store: ScenarioStore, docker: DockerExec, bus: RunBus, settings: Settings):
        self.store, self.docker, self.bus, self.settings = store, docker, bus, settings
        self.runs: dict[str, Run] = {}
        self.locks: dict[str, asyncio.Lock] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.abort_flags: set[str] = set()

    # ------------------------------------------------------------- public --
    def new_run_id(self, sc: Scenario) -> str:
        return f"{time.strftime('%Y%m%d-%H%M%S')}-{sc.id[:24]}-{secrets.token_hex(2)}"

    async def start(self, sc: Scenario) -> Run:
        lock = self.locks.setdefault(sc.stack, asyncio.Lock())
        if lock.locked():
            raise RuntimeError(f"stack '{sc.stack}' is busy with another run")
        run = Run(run_id=self.new_run_id(sc), scenario_id=sc.id, scenario_title=sc.title,
                  protocol=sc.protocol, group=sc.group,
                  steps=[StepState(id=s.id, title=s.title, narration=s.narration) for s in sc.steps])
        run.vars = {"run_id": run.run_id}
        self.runs[run.run_id] = run
        self.tasks[run.run_id] = asyncio.create_task(self._guarded(run, sc, lock))
        log.info("run %s started: scenario=%s stack=%s", run.run_id, sc.id, sc.stack)
        return run

    def abort(self, run_id: str) -> None:
        log.info("run %s: abort requested", run_id)
        self.abort_flags.add(run_id)

    # ----------------------------------------------------------- execution --
    async def _guarded(self, run: Run, sc: Scenario, lock: asyncio.Lock) -> None:
        async with lock:
            try:
                await asyncio.wait_for(self._execute(run, sc), timeout=self.settings.run_timeout_s)
            except TimeoutError:
                run.status, run.error = "failed", f"run exceeded {self.settings.run_timeout_s}s"
                self._status(run)
            except Exception as exc:  # last-resort guard so a bug never wedges the stack lock
                log.exception("run %s crashed", run.run_id)
                run.status, run.error = "failed", f"internal error: {exc}"
                self._status(run)
            finally:
                run.finished_at = time.time()
                self._persist(run)
                log.info("run %s finished: status=%s packets=%d duration=%.1fs%s", run.run_id, run.status,
                         len(run.packets), run.finished_at - run.created_at, f" error={run.error}" if run.error else "")

    def _status(self, run: Run) -> None:
        self.bus.publish(run.run_id, {"type": "run.status", "status": run.status, "error": run.error})

    def _step_event(self, run: Run, st: StepState) -> None:
        self.bus.publish(run.run_id, {"type": "step.status", "step": st.model_dump()})

    async def _execute(self, run: Run, sc: Scenario) -> None:
        run.status = "running"
        self._status(run)
        agent = CaptureClient(sc.capture.host, self.settings.agent_port, self.settings.agent_token)
        stream_task: asyncio.Task | None = None
        capturing = False
        outputs: dict[str, str] = {}
        failed: str | None = None

        async def on_packet(msg: dict) -> None:
            pkt = normalizer(msg["agent"], msg["layers"])
            pkt.n = len(run.packets) + 1
            run.packets.append(pkt)
            self.bus.publish(run.run_id, {"type": "packet", "packet": pkt.model_dump()})

        normalizer = Normalizer()
        try:
            for step, st in zip(sc.steps, run.steps):
                if run.run_id in self.abort_flags:
                    run.status, run.error = "aborted", "aborted by user"
                    break
                st.status, st.started_at = "running", time.time()
                self._step_event(run, st)
                try:
                    if step.action == "capture_start":
                        normalizer = Normalizer(*self._endpoints(sc, run))
                        info = await agent.start(run.run_id, sc.capture.bpf)
                        capturing = True
                        stream_task = asyncio.create_task(agent.stream(run.run_id, on_packet))
                        st.output = f"capturing on {info['iface']} ({sc.capture.agent}) filter: {sc.capture.bpf or 'none'}"
                    elif step.action == "capture_stop":
                        res = await agent.stop(run.run_id)
                        capturing = False
                        if stream_task:
                            await asyncio.wait_for(stream_task, timeout=10)
                        run.pcap_files.append(res["pcap"])
                        st.output = f"{res['packets']} packets, {res['pcap_bytes']} bytes -> {Path(res['pcap']).name}"
                    elif step.action == "sleep":
                        await asyncio.sleep(step.seconds)
                    elif step.action == "wait_for":
                        st.output = await self._wait_for(run, sc, step)
                    elif step.action == "resolve":
                        res = await self._exec_one(run, sc, step, step.exec[0], st)
                        run.vars[step.var] = res.strip().splitlines()[-1].strip() if res.strip() else ""  # type: ignore[index]
                    else:
                        st.output = await self._exec_step(run, sc, step, st)
                    outputs[step.id] = st.output
                    st.status = "ok"
                except StepFailed as exc:
                    st.status, st.message = "failed", str(exc)
                    outputs[step.id] = st.output
                    failed = f"step '{step.id}' failed: {exc}"
                except Exception as exc:
                    st.status, st.message = "failed", f"{type(exc).__name__}: {exc}"
                    failed = f"step '{step.id}' failed: {exc}"
                st.duration_ms = round((time.time() - (st.started_at or time.time())) * 1000, 1)
                self._step_event(run, st)
                if failed:
                    log.warning("run %s: %s", run.run_id, failed)
                    break
            for st in run.steps:
                if st.status == "pending":
                    st.status = "skipped"
                    self._step_event(run, st)
        finally:
            if capturing:
                try:
                    res = await agent.stop(run.run_id)
                    run.pcap_files.append(res["pcap"])
                except Exception as exc:
                    log.warning("could not stop capture for %s: %s", run.run_id, exc)
                if stream_task:
                    # drain what the agent already captured so a failed run still shows its packets
                    try:
                        await asyncio.wait_for(stream_task, timeout=5)
                    except (TimeoutError, Exception):
                        stream_task.cancel()
            await self._cleanup(run, sc)

        # keep the TLS key log (lab only) next to the pcap so the UI can decrypt
        if self.settings.allow_tls_keylog:
            await self._collect_keylog(run, sc)

        run.status = "analyzing"
        self._status(run)
        await self._analyze(run, sc, outputs)
        if run.status != "aborted":
            run.status = "failed" if failed else "completed"
        run.error = run.error or failed
        self._status(run)

    def _endpoints(self, sc: Scenario, run: Run) -> tuple[Endpoint, Endpoint]:
        left, right = sc.endpoints["left"], sc.endpoints["right"]
        return (Endpoint(name=left.name, ip=render(left.ip, run.vars), mac=render(left.mac, run.vars)),
                Endpoint(name=right.name, ip=render(right.ip, run.vars), mac=render(right.mac, run.vars)))

    async def _exec_one(self, run: Run, sc: Scenario, step: Step, spec, st: StepState) -> str:
        container = sc.nodes[spec.node]
        argv = render(spec.argv(), run.vars)
        env = {k: render(v, run.vars) for k, v in spec.env.items()} if spec.env else None
        shown = render(spec.cmd if isinstance(spec.cmd, str) else " ".join(spec.cmd), run.vars)
        header = f"$ [{spec.node}]{' (background)' if spec.detach else ''} {shown}\n"
        self.bus.publish(run.run_id, {"type": "step.output", "step_id": step.id, "text": header})
        if spec.detach:
            res = await self.docker.exec_detached(container, argv, env)
        else:
            res = await self.docker.exec(container, argv, env,
                                         on_output=lambda t: self.bus.publish(run.run_id, {"type": "step.output", "step_id": step.id, "text": t}))
        st.output += header + res.output
        if res.rc == 124:
            raise StepFailed(f"{spec.node}: timed out after {spec.timeout}s")
        if res.rc != 0 and not spec.allow_fail:
            raise StepFailed(f"{spec.node}: exit code {res.rc}")
        return res.output

    async def _exec_step(self, run: Run, sc: Scenario, step: Step, st: StepState) -> str:
        for spec in step.exec:
            await self._exec_one(run, sc, step, spec, st)
        if step.expect and step.expect.regex:
            found = re.search(render(step.expect.regex, run.vars), st.output, re.MULTILINE) is not None
            if found == step.expect.absent:
                raise StepFailed(f"output {'contains' if step.expect.absent else 'lacks'} /{step.expect.regex}/")
        return st.output

    async def _wait_for(self, run: Run, sc: Scenario, step: Step) -> str:
        wf = step.wait_for
        assert wf
        container = sc.nodes[wf.node]
        argv = render(wf.cmd if isinstance(wf.cmd, list) else ["sh", "-c", wf.cmd], run.vars)
        deadline = time.monotonic() + wf.timeout
        last = ""
        while time.monotonic() < deadline:
            res = await self.docker.exec(container, argv)
            last = res.output
            if re.search(wf.regex, last, re.MULTILINE):
                self.bus.publish(run.run_id, {"type": "step.output", "step_id": step.id, "text": last[-4000:]})
                return last
            await asyncio.sleep(wf.interval)
        raise StepFailed(f"/{wf.regex}/ not seen on {wf.node} within {wf.timeout}s; last output: {last[-300:]}")

    async def _cleanup(self, run: Run, sc: Scenario) -> None:
        for step in sc.cleanup:
            for spec in step.exec:
                try:
                    await self.docker.exec(sc.nodes[spec.node], render(spec.argv(), run.vars))
                except Exception as exc:
                    log.debug("cleanup %s/%s ignored: %s", step.id, spec.node, exc)

    async def _collect_keylog(self, run: Run, sc: Scenario) -> None:
        """Copy the TLS key log a scenario declared (Scenario.keylog) next to the pcap."""
        if not sc.keylog:
            return
        res = await self.docker.exec(sc.nodes[sc.keylog.node], ["cat", sc.keylog.path])
        if res.rc == 0 and res.output.strip():
            dest = self.settings.capture_dir / run.run_id / "tls.keylog"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(res.output)
            dest.chmod(0o600)
            run.keylog_file = str(dest)

    async def _analyze(self, run: Run, sc: Scenario, outputs: dict[str, str]) -> None:
        metrics = compute_metrics(run.packets)
        if run.keylog_file and run.pcap_files and "tls" in metrics.protocol:
            ev = await deep.tls_certificate_evidence(Path(run.pcap_files[0]), Path(run.keylog_file))
            if ev:
                metrics.protocol["tls"]["decrypted"] = ev
        run.metrics = metrics
        run.assertions = evaluate([a.model_dump() for a in sc.assertions], run.packets, metrics, outputs)
        run.verdict = compute_verdict(metrics, sc.declared, run.assertions)
        self.bus.publish(run.run_id, {"type": "run.result", "metrics": metrics.model_dump(),
                                      "verdict": run.verdict.model_dump(),
                                      "assertions": [a.model_dump() for a in run.assertions]})

    # --------------------------------------------------------- persistence --
    def _persist(self, run: Run) -> None:
        d = self.settings.capture_dir / run.run_id
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / "run.json").write_text(run.model_dump_json())
        except OSError as exc:
            log.warning("could not persist run %s: %s", run.run_id, exc)

    def load_history(self) -> None:
        for f in sorted(self.settings.capture_dir.glob("*/run.json")):
            try:
                run = Run.model_validate_json(f.read_text())
                self.runs[run.run_id] = run
            except Exception as exc:
                log.warning("skipping unreadable %s: %s", f, exc)
        log.info("loaded %d past runs", len(self.runs))

    def store_imported(self, run: Run) -> None:
        self.runs[run.run_id] = run
        self._persist(run)

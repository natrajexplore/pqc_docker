"""Scenario schema (what lives in scenarios/*.yaml) and run state (what the UI sees).

The YAML schema is documented for humans in docs/SCENARIOS.md. Keep the two in sync.
"""
from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .analyzer.normalize import NormalizedPacket
from .analyzer.verdict import AssertionResult, Metrics, Verdict


# ---------------------------------------------------------------- scenario --
class ExecSpec(BaseModel):
    node: str                                   # logical node name from Scenario.nodes
    cmd: list[str] | str                        # list = argv; str = run with sh -c
    detach: bool = False                        # start a daemon and return immediately
    timeout: int = 30                           # seconds; wrapped with coreutils `timeout`
    allow_fail: bool = False
    env: dict[str, str] = Field(default_factory=dict)

    def argv(self) -> list[str]:
        base = self.cmd if isinstance(self.cmd, list) else ["sh", "-c", self.cmd]
        if self.detach:
            return base
        return ["timeout", "--kill-after=5", str(self.timeout), *base]


class Expect(BaseModel):
    regex: str | None = None                    # searched in stdout+stderr
    absent: bool = False                        # pass when the regex does NOT match
    rc: int | None = 0


class WaitFor(BaseModel):
    node: str
    cmd: list[str] | str
    regex: str
    timeout: int = 20
    interval: float = 0.5


class Step(BaseModel):
    id: str
    title: str
    narration: str = ""                         # what the presenter says / the UI shows while it runs
    action: Literal["exec", "capture_start", "capture_stop", "sleep", "wait_for", "resolve"] = "exec"
    exec: list[ExecSpec] = Field(default_factory=list)
    expect: Expect | None = None
    wait_for: WaitFor | None = None
    seconds: float = 0
    # resolve: run exec[0] and store stripped stdout into run vars under `var`
    var: str | None = None

    @model_validator(mode="after")
    def _check(self) -> Step:
        if self.action == "exec" and not self.exec:
            raise ValueError(f"step {self.id}: action exec needs exec entries")
        if self.action == "wait_for" and not self.wait_for:
            raise ValueError(f"step {self.id}: action wait_for needs wait_for")
        if self.action == "resolve" and (not self.exec or not self.var):
            raise ValueError(f"step {self.id}: resolve needs exec[0] and var")
        return self


class EndpointSpec(BaseModel):
    name: str
    ip: str | None = None
    mac: str | None = None                      # may be a template like ${sup_mac}


class CaptureSpec(BaseModel):
    agent: str                                  # agent container name, e.g. pqcw-cap-ipsec
    host: str                                   # mgmt DNS name of the node whose netns it shares
    bpf: str = ""


class KeylogSpec(BaseModel):
    """Where a TLS endpoint wrote its NSS key log (openssl s_client -keylogfile). LAB ONLY:
    lets the analyzer decrypt TLS 1.3's encrypted Certificate message for wire evidence."""
    node: str
    path: str


class AssertionSpec(BaseModel):
    id: str
    kind: str
    expect: dict[str, Any] = Field(default_factory=dict)
    description: str = ""


class Scenario(BaseModel):
    id: str
    title: str
    protocol: Literal["ipsec", "tls", "ssh", "macsec"]
    stack: str                                  # compose profile that must be running
    pillar: Literal["key-exchange", "authentication", "both"]
    group: str                                  # scenarios in one group are comparable side by side
    order: int = 100
    summary: str
    upstream_lab: str | None = None             # path in vendor/juliogomez-pqc
    learn_more: list[str] = Field(default_factory=list)
    nodes: dict[str, str]                       # logical name -> container name
    endpoints: dict[Literal["left", "right"], EndpointSpec]
    capture: CaptureSpec
    keylog: KeylogSpec | None = None
    declared: dict[str, str] = Field(default_factory=dict)   # key_exchange/authentication fallbacks
    steps: list[Step]
    cleanup: list[Step] = Field(default_factory=list)
    assertions: list[AssertionSpec] = Field(default_factory=list)
    expected_numbers: dict[str, Any] = Field(default_factory=dict)  # reference values for the UI

    @field_validator("steps")
    @classmethod
    def _needs_capture(cls, steps: list[Step]) -> list[Step]:
        actions = [s.action for s in steps]
        if "capture_start" not in actions or "capture_stop" not in actions:
            raise ValueError("a scenario must start and stop a capture")
        if actions.index("capture_start") > actions.index("capture_stop"):
            raise ValueError("capture_start must come before capture_stop")
        return steps

    @model_validator(mode="after")
    def _nodes_exist(self) -> Scenario:
        for s in self.steps + self.cleanup:
            for e in s.exec:
                if e.node not in self.nodes:
                    raise ValueError(f"step {s.id}: unknown node '{e.node}'")
            if s.wait_for and s.wait_for.node not in self.nodes:
                raise ValueError(f"step {s.id}: unknown node '{s.wait_for.node}'")
        if self.keylog and self.keylog.node not in self.nodes:
            raise ValueError(f"keylog: unknown node '{self.keylog.node}'")
        return self


class ScenarioInfo(BaseModel):
    """What GET /api/scenarios returns (no step internals)."""
    id: str
    title: str
    protocol: str
    stack: str
    pillar: str
    group: str
    order: int
    summary: str
    upstream_lab: str | None
    learn_more: list[str]
    available: bool
    missing: list[str] = Field(default_factory=list)
    steps: list[dict[str, str]] = Field(default_factory=list)
    expected_numbers: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------- run --
RunStatus = Literal["queued", "running", "analyzing", "completed", "failed", "aborted"]
StepStatus = Literal["pending", "running", "ok", "failed", "skipped"]


class StepState(BaseModel):
    id: str
    title: str
    narration: str = ""
    status: StepStatus = "pending"
    started_at: float | None = None
    duration_ms: float | None = None
    output: str = ""
    message: str = ""


class Run(BaseModel):
    run_id: str
    scenario_id: str
    scenario_title: str
    protocol: str
    group: str
    status: RunStatus = "queued"
    created_at: float = Field(default_factory=time.time)
    finished_at: float | None = None
    steps: list[StepState] = Field(default_factory=list)
    vars: dict[str, str] = Field(default_factory=dict)
    packets: list[NormalizedPacket] = Field(default_factory=list)
    metrics: Metrics | None = None
    verdict: Verdict | None = None
    assertions: list[AssertionResult] = Field(default_factory=list)
    pcap_files: list[str] = Field(default_factory=list)
    keylog_file: str | None = None
    error: str | None = None
    imported: bool = False

    def summary(self) -> dict:
        d = self.model_dump(exclude={"packets"})
        d["packet_count"] = len(self.packets)
        return d


class RunRequest(BaseModel):
    scenario_id: str

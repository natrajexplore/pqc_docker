"""Load and validate scenarios/*.yaml; report which ones can run right now."""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from .models import Scenario, ScenarioInfo

log = logging.getLogger(__name__)


class ScenarioStore:
    def __init__(self, directory: Path):
        self.directory = directory
        self._items: dict[str, Scenario] = {}
        self.errors: dict[str, str] = {}

    def load(self) -> None:
        items: dict[str, Scenario] = {}
        errors: dict[str, str] = {}
        for path in sorted(self.directory.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text())
                sc = Scenario.model_validate(data)
                if sc.id in items:
                    raise ValueError(f"duplicate scenario id {sc.id}")
                if path.stem != sc.id:
                    raise ValueError(f"file name {path.name} must match id '{sc.id}'")
                items[sc.id] = sc
            except Exception as exc:
                errors[path.name] = str(exc)
                log.error("scenario %s rejected: %s", path.name, exc)
        self._items, self.errors = items, errors
        log.info("loaded %d scenarios (%d rejected)", len(items), len(errors))

    def get(self, sid: str) -> Scenario | None:
        return self._items.get(sid)

    def all(self) -> list[Scenario]:
        return sorted(self._items.values(), key=lambda s: (s.protocol, s.order, s.id))

    def info(self, sc: Scenario, running: set[str]) -> ScenarioInfo:
        needed = set(sc.nodes.values()) | {sc.capture.agent}
        missing = sorted(needed - running)
        return ScenarioInfo(
            id=sc.id, title=sc.title, protocol=sc.protocol, stack=sc.stack, pillar=sc.pillar,
            group=sc.group, order=sc.order, summary=sc.summary, upstream_lab=sc.upstream_lab,
            learn_more=sc.learn_more, available=not missing, missing=missing,
            steps=[{"id": s.id, "title": s.title, "narration": s.narration} for s in sc.steps],
            expected_numbers=sc.expected_numbers,
        )

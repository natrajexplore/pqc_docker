from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    scenario_dir: Path = Path(os.getenv("PQCW_SCENARIO_DIR", "/app/scenarios"))
    capture_dir: Path = Path(os.getenv("PQCW_CAPTURE_DIR", "/captures"))
    project: str = os.getenv("PQCW_PROJECT", "pqcw")
    agent_token: str = os.getenv("PQCW_AGENT_TOKEN", "")
    agent_port: int = int(os.getenv("PQCW_AGENT_PORT", "9100"))
    run_timeout_s: int = int(os.getenv("PQCW_RUN_TIMEOUT_S", "120"))
    allow_tls_keylog: bool = os.getenv("PQCW_ALLOW_TLS_KEYLOG", "true").lower() == "true"
    log_level: str = os.getenv("PQCW_LOG_LEVEL", "INFO")
    log_format: str = os.getenv("PQCW_LOG_FORMAT", "text")  # text | json
    # Host names the UI may be reached by (DNS-rebinding guard). Add yours if you
    # put the UI behind a reverse proxy; "*" disables the check.
    allowed_hosts: frozenset[str] = frozenset(os.getenv("PQCW_ALLOWED_HOSTS", "127.0.0.1,localhost,::1").split(","))


settings = Settings()

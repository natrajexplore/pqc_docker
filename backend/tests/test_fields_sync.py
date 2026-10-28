import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _live_fields(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "LIVE_FIELDS":
            return ast.literal_eval(node.value)
    raise AssertionError(f"LIVE_FIELDS not found in {path}")


def test_backend_field_list_matches_agent():
    agent = ROOT / "capture-agent" / "agent" / "fields.py"
    backend = ROOT / "backend" / "app" / "analyzer" / "fields.py"
    assert _live_fields(agent) == _live_fields(backend), \
        "backend/app/analyzer/fields.py drifted from capture-agent/agent/fields.py - regenerate the copy"

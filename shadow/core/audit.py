"""Append-only audit logger for engagement events."""

import json
import os
from datetime import datetime, timezone


class AuditLogger:
    def __init__(self, workspace_dir: str, filename: str = "events.jsonl"):
        self.filepath = os.path.join(workspace_dir, filename)

    def log(self, event: str, **kwargs) -> None:
        entry = {"event": event, "timestamp": datetime.now(timezone.utc).isoformat(), **kwargs}
        self._write_event(entry)

    def _write_event(self, entry: dict) -> None:
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.filepath):
            return []
        events = []
        with open(self.filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events

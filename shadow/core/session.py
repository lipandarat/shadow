"""Session manager — checkpoint/resume for long-running hunt sessions."""

import json
import os
from datetime import datetime, timezone
from typing import Optional


class SessionManager:
    def __init__(self, workspace_dir: str, filename: str = "session.jsonl"):
        self.filepath = os.path.join(workspace_dir, filename)
        self._steps: list[dict] = []
        self._loaded = False

    def checkpoint(self, step: str, state: dict = None) -> None:
        """Record a step as pending before executing it."""
        self._ensure_loaded()
        entry = {
            "step": step,
            "state": state or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
        }
        self._steps.append(entry)
        self._persist()

    def mark_done(self, step: str) -> None:
        """Mark a step as done after successful execution."""
        self._ensure_loaded()
        for entry in reversed(self._steps):
            if entry["step"] == step and entry["status"] == "pending":
                entry["status"] = "done"
                break
        self._persist()

    def get_resume_point(self) -> Optional[str]:
        """Return the first pending step name, or None if all done."""
        self._ensure_loaded()
        for entry in self._steps:
            if entry["status"] == "pending":
                return entry["step"]
        return None

    def is_done(self, step: str) -> bool:
        """Return True if step has been marked done."""
        self._ensure_loaded()
        for entry in reversed(self._steps):
            if entry["step"] == step:
                return entry["status"] == "done"
        return False

    def all_steps(self) -> list[dict]:
        """Return all recorded steps."""
        self._ensure_loaded()
        return list(self._steps)

    def reset(self) -> None:
        """Clear all session state."""
        self._steps = []
        self._loaded = True
        self._persist()

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load()
            self._loaded = True

    def _load(self) -> None:
        self._steps = []
        if not os.path.exists(self.filepath):
            return
        with open(self.filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self._steps.append(json.loads(line))

    def _persist(self) -> None:
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        with open(self.filepath, "w", encoding="utf-8") as f:
            for entry in self._steps:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())

import json, os, tempfile
import pytest
from shadow.core.audit import AuditLogger


class TestAuditLogger:
    @pytest.fixture
    def tmpdir(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    def test_log_writes_event(self, tmpdir):
        log = AuditLogger(tmpdir)
        log.log("test_event", key="value")
        path = os.path.join(tmpdir, "events.jsonl")
        assert os.path.exists(path)
        with open(path) as f:
            events = [json.loads(line) for line in f if line.strip()]
        assert len(events) == 1
        assert events[0]["event"] == "test_event"
        assert events[0]["key"] == "value"
        assert "timestamp" in events[0]

    def test_log_multiple_events_append(self, tmpdir):
        log = AuditLogger(tmpdir)
        log.log("first")
        log.log("second")
        path = os.path.join(tmpdir, "events.jsonl")
        with open(path) as f:
            events = [json.loads(line) for line in f if line.strip()]
        assert len(events) == 2
        assert events[0]["event"] == "first"
        assert events[1]["event"] == "second"

    def test_log_safe_from_crash(self, tmpdir):
        log = AuditLogger(tmpdir)
        log._write_event({"event": "pre-existing", "timestamp": "2024-01-01T00:00:00Z"})
        log.log("after_crash")
        path = os.path.join(tmpdir, "events.jsonl")
        with open(path) as f:
            events = [json.loads(line) for line in f if line.strip()]
        assert any(e["event"] == "pre-existing" for e in events)
        assert any(e["event"] == "after_crash" for e in events)

    def test_read_all_returns_events(self, tmpdir):
        log = AuditLogger(tmpdir)
        log.log("a")
        log.log("b")
        events = log.read_all()
        assert len(events) == 2

    def test_read_all_empty_when_no_file(self, tmpdir):
        log = AuditLogger(tmpdir)
        assert log.read_all() == []

    def test_log_unicode(self, tmpdir):
        log = AuditLogger(tmpdir)
        log.log("unicode_event", message="temuan: SQL injection di /login")
        events = log.read_all()
        assert events[0]["message"] == "temuan: SQL injection di /login"

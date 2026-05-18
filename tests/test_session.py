import os, tempfile
import pytest
from shadow.core.session import SessionManager


class TestSessionManager:
    @pytest.fixture
    def workspace(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    def test_checkpoint_writes_pending(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon", {"target": "example.com"})
        steps = sm.all_steps()
        assert len(steps) == 1
        assert steps[0]["step"] == "recon"
        assert steps[0]["status"] == "pending"
        assert steps[0]["state"] == {"target": "example.com"}

    def test_mark_done_updates_status(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        sm.mark_done("recon")
        steps = sm.all_steps()
        assert steps[0]["status"] == "done"

    def test_get_resume_point_returns_first_pending(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        sm.checkpoint("hunt")
        sm.mark_done("recon")
        assert sm.get_resume_point() == "hunt"

    def test_get_resume_point_none_when_all_done(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        sm.mark_done("recon")
        assert sm.get_resume_point() is None

    def test_get_resume_point_none_when_empty(self, workspace):
        sm = SessionManager(workspace)
        assert sm.get_resume_point() is None

    def test_is_done_true_after_mark(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        sm.mark_done("recon")
        assert sm.is_done("recon")

    def test_is_done_false_before_mark(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        assert not sm.is_done("recon")

    def test_is_done_false_for_unknown_step(self, workspace):
        sm = SessionManager(workspace)
        assert not sm.is_done("nonexistent")

    def test_persists_across_instances(self, workspace):
        sm1 = SessionManager(workspace)
        sm1.checkpoint("recon")
        sm1.mark_done("recon")
        sm1.checkpoint("hunt")

        sm2 = SessionManager(workspace)
        assert sm2.is_done("recon")
        assert not sm2.is_done("hunt")
        assert sm2.get_resume_point() == "hunt"

    def test_reset_clears_all(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        sm.reset()
        assert sm.all_steps() == []
        assert sm.get_resume_point() is None

    def test_session_file_created(self, workspace):
        sm = SessionManager(workspace)
        sm.checkpoint("recon")
        assert os.path.exists(os.path.join(workspace, "session.jsonl"))

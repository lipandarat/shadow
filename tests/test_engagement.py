import os, tempfile
import pytest
from shadow.core.engagement import EngagementManager
from shadow.core.models import Scope, ScopeEntry


class TestEngagementManager:
    @pytest.fixture
    def base_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield d

    def test_create_workspace_dirs(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        assert os.path.isdir(eng.workspace_path)
        assert os.path.isdir(os.path.join(eng.workspace_path, "findings"))

    def test_create_workspace_files(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        assert os.path.isfile(os.path.join(eng.workspace_path, "scope.yaml"))
        assert os.path.isfile(os.path.join(eng.workspace_path, "brain.md"))
        assert os.path.isfile(os.path.join(eng.workspace_path, "endpoints.jsonl"))

    def test_create_returns_engagement(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        assert eng.platform == "hackerone"
        assert eng.program == "tesla"

    def test_workspace_naming_contains_platform_program(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        name = os.path.basename(eng.workspace_path)
        assert "hackerone" in name
        assert "tesla" in name

    def test_load_workspace(self, base_dir):
        mgr = EngagementManager(base_dir)
        created = mgr.create("hackerone", "tesla")
        loaded = mgr.load(created.workspace_path)
        assert loaded is not None
        assert loaded.platform == "hackerone"
        assert loaded.program == "tesla"

    def test_load_nonexistent_returns_none(self, base_dir):
        mgr = EngagementManager(base_dir)
        assert mgr.load(os.path.join(base_dir, "nonexistent")) is None

    def test_write_and_load_scope(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        scope = Scope(entries=[ScopeEntry(domain="tesla.com")])
        mgr.write_scope(eng, scope)
        reloaded = mgr.load(eng.workspace_path)
        assert len(reloaded.scope.entries) == 1
        assert reloaded.scope.entries[0].domain == "tesla.com"

    def test_write_scope_with_exclusions(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        scope = Scope(
            entries=[ScopeEntry(domain="tesla.com")],
            excluded=["admin.tesla.com"],
        )
        mgr.write_scope(eng, scope)
        reloaded = mgr.load(eng.workspace_path)
        assert reloaded.scope.excluded == ["admin.tesla.com"]

    def test_brain_md_contains_program_name(self, base_dir):
        mgr = EngagementManager(base_dir)
        eng = mgr.create("hackerone", "tesla")
        brain_path = os.path.join(eng.workspace_path, "brain.md")
        content = open(brain_path).read()
        assert "tesla" in content

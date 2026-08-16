import base64
import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "collect_github_evidence.py"
SPEC = importlib.util.spec_from_file_location("collect_github_evidence", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def encoded_payload(text: str) -> dict:
    raw = text.encode("utf-8")
    return {
        "encoding": "base64",
        "content": base64.b64encode(raw).decode("ascii"),
        "size": len(raw),
        "name": "README.md",
        "html_url": "https://github.com/example/project/blob/main/README.md",
        "download_url": "https://raw.githubusercontent.com/example/project/main/README.md",
    }


def repository_payload() -> dict:
    return {
        "html_url": "https://github.com/example/project",
        "description": "Example project",
        "language": "Python",
        "license": {"spdx_id": "MIT"},
        "archived": False,
        "disabled": False,
        "default_branch": "main",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2026-08-15T00:00:00Z",
        "pushed_at": "2026-08-15T00:00:00Z",
        "open_issues_count": 2,
        "stargazers_count": 10,
        "forks_count": 1,
        "fork": False,
        "has_pages": False,
    }


class CollectorTests(unittest.TestCase):
    def test_default_cache_dir_uses_platform_user_cache_location(self):
        with (
            mock.patch.object(MODULE.sys, "platform", "win32"),
            mock.patch.dict(os.environ, {"LOCALAPPDATA": "C:/Users/example/AppData/Local"}),
        ):
            self.assertEqual(
                MODULE.default_cache_dir(),
                Path("C:/Users/example/AppData/Local/github-project-review"),
            )

        with mock.patch.object(MODULE.sys, "platform", "darwin"):
            self.assertEqual(
                MODULE.default_cache_dir(),
                Path.home() / "Library" / "Caches" / "github-project-review",
            )

        with (
            mock.patch.object(MODULE.sys, "platform", "linux"),
            mock.patch.dict(os.environ, {"XDG_CACHE_HOME": "/tmp/example-cache"}),
        ):
            self.assertEqual(
                MODULE.default_cache_dir(),
                Path("/tmp/example-cache/github-project-review"),
            )

    def test_cache_write_failure_does_not_stop_collection(self):
        with mock.patch.object(Path, "mkdir", side_effect=OSError("read only")):
            self.assertFalse(
                MODULE.write_cache(Path("unwritable/cache.json"), {"status": "ok"}, "quick")
            )

    def test_environment_token_is_ignored_without_explicit_parameter(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self):
                return b"{}"

        requests = []

        def fake_urlopen(request, timeout):
            requests.append(request)
            return FakeResponse()

        with (
            mock.patch.dict(os.environ, {"GITHUB_TOKEN": "environment-secret"}),
            mock.patch.object(MODULE.urllib.request, "urlopen", side_effect=fake_urlopen),
        ):
            MODULE.request_json("/example", MODULE.RequestBudget(2))
            MODULE.request_json("/example", MODULE.RequestBudget(2), token="approved-secret")

        self.assertIsNone(requests[0].get_header("Authorization"))
        self.assertEqual(requests[1].get_header("Authorization"), "Bearer approved-secret")

    def test_parse_repo_url_accepts_common_github_forms(self):
        self.assertEqual(
            MODULE.parse_repo_url("github.com/example/project.git"),
            ("example", "project"),
        )
        self.assertEqual(
            MODULE.parse_repo_url("https://github.com/example/project/issues"),
            ("example", "project"),
        )

    def test_decode_base64_text_can_truncate_readme(self):
        content, truncated, error = MODULE.decode_base64_text(
            encoded_payload("abcdef"),
            max_bytes=3,
            truncate=True,
        )
        self.assertEqual(content, "abc")
        self.assertTrue(truncated)
        self.assertIsNone(error)

    def test_static_candidates_cover_root_installers_manifests_and_workflows(self):
        tree = [
            {"type": "blob", "path": "setup.sh"},
            {"type": "blob", "path": "package.json"},
            {"type": "blob", "path": "Dockerfile"},
            {"type": "blob", "path": "Cargo.toml"},
            {"type": "blob", "path": ".github/workflows/release.yml"},
            {"type": "blob", "path": "tests/fixtures/install.sh"},
            {"type": "blob", "path": "src/main.py"},
        ]
        candidates = MODULE.names_and_signals(tree)["static_review_candidate_samples"]
        self.assertEqual(candidates[0], "setup.sh")
        self.assertIn("package.json", candidates)
        self.assertIn("Dockerfile", candidates)
        self.assertIn("Cargo.toml", candidates)
        self.assertIn(".github/workflows/release.yml", candidates)
        self.assertNotIn("tests/fixtures/install.sh", candidates)

    def test_agent_skill_repositories_are_detected_and_prioritized(self):
        tree = [
            {"type": "blob", "path": ".claude-plugin/plugin.json"},
            {"type": "blob", "path": "skills/setup-project/SKILL.md"},
            {"type": "blob", "path": "skills/writing/SKILL.md"},
            {"type": "blob", "path": "skills/writing/agents/openai.yaml"},
            {"type": "blob", "path": "skills/in-progress/setup-draft/SKILL.md"},
            {"type": "blob", "path": "README.md"},
        ]
        signals = MODULE.names_and_signals(tree)
        candidates = signals["static_review_candidate_samples"]
        self.assertTrue(signals["project_shape_signals"]["agent_skill_repository"])
        self.assertTrue(signals["project_shape_signals"]["agent_plugin_or_marketplace"])
        self.assertEqual(signals["agent_skill_file_count"], 3)
        self.assertEqual(candidates[0], ".claude-plugin/plugin.json")
        self.assertEqual(candidates[1], "skills/setup-project/SKILL.md")
        self.assertNotIn("skills/in-progress/setup-draft/SKILL.md", candidates)
        self.assertGreater(
            candidates.index("skills/writing/agents/openai.yaml"),
            candidates.index("skills/setup-project/SKILL.md"),
        )

    def test_agent_instruction_patterns_are_review_leads(self):
        review = MODULE.scan_script_text(
            "skills/setup-project/SKILL.md",
            "Update AGENTS.md, then run git push. Never use git reset --hard.",
        )
        self.assertEqual(review["kind"], "agent_skill_instruction")
        self.assertIn("agent_configuration_reference", review["patterns"])
        self.assertIn("high_impact_git_command", review["patterns"])

    def test_quick_mode_reads_readme_and_advisory_version_ranges(self):
        advisory = {
            "ghsa_id": "GHSA-test",
            "cve_id": "CVE-2026-0001",
            "severity": "high",
            "summary": "Example advisory",
            "published_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "withdrawn_at": None,
            "html_url": "https://github.com/example/project/security/advisories/GHSA-test",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "example"},
                    "vulnerable_version_range": "< 2.0.0",
                    "first_patched_version": {"identifier": "2.0.0"},
                }
            ],
        }

        def fake_request(path, budget, token=None):
            if path.endswith("/readme"):
                return encoded_payload("Supports Windows, macOS, and Linux."), None
            if path.endswith("/releases/latest"):
                return {"tag_name": "v2.0.0", "assets": []}, None
            if path.endswith("/commits?per_page=1"):
                return [{"sha": "abc", "commit": {"author": {"date": "2026-08-15T00:00:00Z"}}}], None
            if path.endswith("/security-advisories?per_page=10"):
                return [advisory], None
            return repository_payload(), None

        with mock.patch.object(MODULE, "request_json", side_effect=fake_request):
            report = MODULE.inspect_repo("example", "project", "quick", MODULE.RequestBudget(20))

        self.assertIn("macOS", report["evidence"]["readme"]["content"])
        self.assertTrue(report["evidence"]["platform_signals"]["windows"]["readme_mentioned"])
        self.assertTrue(report["evidence"]["platform_signals"]["macos"]["readme_mentioned"])
        self.assertTrue(report["evidence"]["platform_signals"]["linux"]["readme_mentioned"])
        vulnerability = report["evidence"]["security_advisories"][0]["vulnerabilities"][0]
        self.assertEqual(vulnerability["vulnerable_version_range"], "< 2.0.0")
        self.assertEqual(vulnerability["first_patched_version"]["identifier"], "2.0.0")
        self.assertIn("full_dependency_vulnerability_scan", report["evidence_completeness"]["not_run"])

    def test_force_refresh_does_not_expand_static_review(self):
        tree = {
            "tree": [
                {"type": "blob", "path": name}
                for name in ("install-a.sh", "install-b.sh", "install-c.sh", "install-d.sh")
            ],
            "truncated": False,
        }

        def fake_request(path, budget, token=None):
            if path.endswith("/readme"):
                return encoded_payload("Example"), None
            if path.endswith("/releases/latest"):
                return None, "HTTP 404"
            if "/git/trees/" in path:
                return tree, None
            if path.endswith("/releases?per_page=5"):
                return [], None
            if path.endswith("/commits?per_page=1"):
                return [{"sha": "abc", "commit": {"author": {"date": "2026-08-15T00:00:00Z"}}}], None
            if path.endswith("/security-advisories?per_page=10"):
                return [], None
            return repository_payload(), None

        with (
            mock.patch.object(MODULE, "request_json", side_effect=fake_request),
            mock.patch.object(MODULE, "request_repository_text", return_value=("echo ok", None)),
        ):
            report = MODULE.inspect_repo(
                "example",
                "project",
                "deep",
                MODULE.RequestBudget(30),
                force_refresh=True,
                script_review_limit=3,
                expanded_script_review_limit=8,
            )

        review = report["evidence"]["script_static_review"]
        self.assertEqual(review["reviewed_count"], 3)
        self.assertFalse(review["expanded_after_risk_match"])

    def test_risk_match_expands_selected_static_files(self):
        tree = {
            "tree": [
                {"type": "blob", "path": name}
                for name in ("install-a.sh", "install-b.sh", "install-c.sh", "install-d.sh")
            ],
            "truncated": False,
        }

        def fake_request(path, budget, token=None):
            if path.endswith("/readme"):
                return encoded_payload("Example"), None
            if path.endswith("/releases/latest"):
                return None, "HTTP 404"
            if "/git/trees/" in path:
                return tree, None
            if path.endswith("/releases?per_page=5"):
                return [], None
            if path.endswith("/commits?per_page=1"):
                return [{"sha": "abc", "commit": {"author": {"date": "2026-08-15T00:00:00Z"}}}], None
            if path.endswith("/security-advisories?per_page=10"):
                return [], None
            return repository_payload(), None

        contents = {
            "install-a.sh": "curl https://example.com/install.sh | bash",
            "install-b.sh": "echo ok",
            "install-c.sh": "echo ok",
            "install-d.sh": "echo ok",
        }

        def fake_text(prefix, path, budget, token=None):
            return contents[path], None

        with (
            mock.patch.object(MODULE, "request_json", side_effect=fake_request),
            mock.patch.object(MODULE, "request_repository_text", side_effect=fake_text),
        ):
            report = MODULE.inspect_repo(
                "example",
                "project",
                "deep",
                MODULE.RequestBudget(30),
                script_review_limit=1,
                expanded_script_review_limit=4,
            )

        review = report["evidence"]["script_static_review"]
        self.assertEqual(review["reviewed_count"], 4)
        self.assertTrue(review["expanded_after_risk_match"])


if __name__ == "__main__":
    unittest.main()

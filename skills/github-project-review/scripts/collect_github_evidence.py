"""Collect read-only evidence about public GitHub repositories.

This script never clones, installs, builds, downloads release assets, or executes
repository code. It uses only Python's standard library and public GitHub REST
endpoints. Authentication is opt-in.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import copy
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


API_ROOT = "https://api.github.com"
IMPLEMENTATION_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".rb", ".php", ".swift", ".lua",
}
TEST_MARKERS = ("test", "tests", "spec", "__tests__", "pytest", "jest")
IMPLEMENTATION_DIRS = ("src/", "app/", "lib/", "cmd/", "packages/", "server/")
SECURITY_SENSITIVE_NAMES = {
    "install.ps1", "install.bat", "install.cmd", "setup.ps1", "setup.bat",
    "postinstall.js", "service.ps1", "register-service.ps1", "update.ps1",
    "manifest.json", "requirements.txt", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "poetry.lock", "cargo.lock", "go.sum",
}
DEPENDENCY_FILE_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pyproject.toml", "requirements.txt", "poetry.lock", "pipfile", "pipfile.lock",
    "cargo.toml", "cargo.lock", "go.mod", "go.sum", "pom.xml", "build.gradle",
    "build.gradle.kts", "composer.json", "composer.lock", "gemfile", "gemfile.lock",
}
REVIEWABLE_CONFIG_NAMES = {
    "package.json", "pyproject.toml", "dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "compose.yml", "compose.yaml", "makefile",
    "justfile", ".pre-commit-config.yaml", "requirements.txt", "cargo.toml",
    "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json",
    "gemfile", "pipfile",
}
AGENT_SKILL_FILE_NAMES = {"skill.md"}
AGENT_PLUGIN_MANIFEST_NAMES = {"plugin.json", "marketplace.json"}
AGENT_INTERFACE_MANIFEST_NAMES = {"openai.yaml"}
AGENT_MANIFEST_NAMES = AGENT_PLUGIN_MANIFEST_NAMES | AGENT_INTERFACE_MANIFEST_NAMES
AGENT_SETUP_PATH_MARKERS = ("setup", "install", "bootstrap")
AGENT_HIGH_IMPACT_PATH_MARKERS = (
    "implement", "merge", "git", "deploy", "credential",
    "secret", "wizard", "triage", "issue", "hook", "migration", "migrate",
)
IGNORED_REVIEW_SEGMENTS = {
    "test", "tests", "testing", "fixtures", "fixture", "examples", "example",
    "vendor", "node_modules", "target", "dist", "build", "snapshots", "snapshot",
    "in-progress", "draft", "drafts",
}
PERSISTENCE_SEGMENTS = {
    "startup", "autorun", "launchagents", "systemd", "scheduled-tasks",
    "scheduledtasks",
}
PERSISTENCE_NAME_MARKERS = (
    "register-service", "install-service", "windows-service",
    "scheduled-task", "startup", "autorun", "launchagent", "systemd",
)
SENSITIVE_ACCESS_SEGMENTS = {
    ".ssh", "cookies", "credentials", "wallets", "keychain",
    "browser-data", "browserdata", "password-store",
}
SENSITIVE_ACCESS_NAME_MARKERS = (
    "cookie", "credential", "wallet", "keychain", "login-data",
    "browser-data", "password-store",
)
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".sh", ".bash", ".zsh"}
INSTALL_NAME_MARKERS = (
    "install", "setup", "bootstrap", "update", "updater", "service", "start", "launch",
)
INSTALL_PATH_SEGMENTS = {
    "install", "installer", "installers", "setup", "scripts", "updater",
    "bootstrap",
}
DEFAULT_SCRIPT_REVIEW_LIMIT = 3
EXPANDED_SCRIPT_REVIEW_LIMIT = 8
SCRIPT_REVIEW_MAX_BYTES = 200_000
README_REVIEW_MAX_BYTES = 80_000
DEFAULT_MAX_WORKERS = 3
DEFAULT_REQUEST_BUDGET = 35
DEFAULT_CACHE_HOURS = 24
CACHE_SCHEMA_VERSION = 3
SCRIPT_PATTERNS = {
    "remote_download_or_pipe_execution": re.compile(
        r"(?:invoke-webrequest|\biwr\b|curl(?:\.exe)?|wget).{0,240}"
        r"(?:invoke-expression|\biex\b|\|\s*(?:powershell|pwsh|cmd|bash|sh)\b)",
        re.I | re.S,
    ),
    "encoded_or_obfuscated_execution": re.compile(
        r"(?:-encodedcommand\b|frombase64string\s*\(|invoke-expression|\biex\b)",
        re.I,
    ),
    "security_controls_modified": re.compile(
        r"(?:set-mppreference.{0,120}disable|disableantispyware|"
        r"netsh.{0,80}firewall.{0,80}(?:off|disable)|"
        r"(?:defender|antivirus).{0,80}(?:disable|exclusion))",
        re.I | re.S,
    ),
    "elevation_requested": re.compile(
        r"(?:#requires\s+-runasadministrator|start-process.{0,160}-verb\s+runas|\bsudo\b)",
        re.I | re.S,
    ),
    "persistence_created": re.compile(
        r"(?:new-service\b|sc(?:\.exe)?\s+create\b|schtasks(?:\.exe)?.{0,80}/create\b|"
        r"new-scheduledtask\b|currentversion[\\/]+run\b)",
        re.I | re.S,
    ),
    "sensitive_data_reference": re.compile(
        r"(?:browser.{0,30}cookies?|login data|\.ssh[\\/]|wallet|credential manager|keychain)",
        re.I | re.S,
    ),
    "package_install_hook": re.compile(
        r"[\"'](?:preinstall|install|postinstall|prepare)[\"']\s*:",
        re.I,
    ),
    "remote_binary_download": re.compile(
        r"(?:invoke-webrequest|\biwr\b|curl(?:\.exe)?|wget).{0,240}"
        r"(?:\.exe|\.msi|\.dll|\.sys|\.pkg|\.dmg|\.appimage)\b",
        re.I | re.S,
    ),
    "agent_configuration_reference": re.compile(
        r"(?:AGENTS\.md|CLAUDE\.md|\.codex[\\/]|\.claude[\\/])",
        re.I,
    ),
    "destructive_filesystem_command": re.compile(
        r"(?:\brm\s+-[a-z]*r[a-z]*f\b|remove-item.{0,120}-recurse|shutil\.rmtree\s*\()",
        re.I | re.S,
    ),
    "high_impact_git_command": re.compile(
        r"\bgit\s+(?:push|reset\s+--hard|clean\b|branch\s+-D\b|rebase\b|checkout\s+--)",
        re.I,
    ),
    "external_account_or_secret_reference": re.compile(
        r"(?:api[ _-]?key|access token|secret|credential|cookie|gh\s+auth|linear\b)",
        re.I,
    ),
}
PLATFORM_PATTERNS = {
    "windows": re.compile(r"\bwindows\b|\bwin(?:32|64)\b", re.I),
    "macos": re.compile(r"\bmacos\b|\bmac os\b|\bos x\b|\bdarwin\b", re.I),
    "linux": re.compile(r"\blinux\b|\bubuntu\b|\bdebian\b|\bfedora\b|\barch linux\b", re.I),
}
PLATFORM_ASSET_PATTERNS = {
    "windows": re.compile(r"windows|win(?:32|64)?|\.exe$|\.msi$", re.I),
    "macos": re.compile(r"macos|darwin|osx|\.dmg$|\.pkg$", re.I),
    "linux": re.compile(r"linux|appimage|\.deb$|\.rpm$", re.I),
}


class RequestBudget:
    def __init__(self, limit: int) -> None:
        self.limit = max(1, limit)
        self.used = 0
        self._lock = threading.Lock()

    def claim(self) -> bool:
        with self._lock:
            if self.used >= self.limit:
                return False
            self.used += 1
            return True


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def safe_cache_name(owner: str, repo: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", f"{owner}__{repo}")


def default_cache_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "github-project-review"


def quick_cache_path(cache_dir: Path, owner: str, repo: str) -> Path:
    return cache_dir / f"{safe_cache_name(owner, repo)}.quick.json"


def deep_cache_path(
    cache_dir: Path,
    owner: str,
    repo: str,
    commit_sha: str,
    script_review_limit: int,
    expanded_script_review_limit: int,
) -> Path:
    safe_sha = re.sub(r"[^a-fA-F0-9]+", "", commit_sha)[:40] or "unknown"
    return cache_dir / (
        f"{safe_cache_name(owner, repo)}.deep.{safe_sha}."
        f"s{max(0, script_review_limit)}-e{max(script_review_limit, expanded_script_review_limit)}.json"
    )


def latest_commit_sha(report: dict | None) -> str | None:
    if not isinstance(report, dict):
        return None
    value = (((report.get("evidence") or {}).get("latest_commit") or {}).get("sha"))
    return value if isinstance(value, str) and value else None


def quick_projection(report: dict) -> dict:
    projected = copy.deepcopy(report)
    evidence = projected.get("evidence") or {}
    for key in ("tree", "tree_truncated", "script_static_review", "releases"):
        evidence.pop(key, None)
    projected["evidence"] = evidence
    projected["evidence_completeness"] = evidence_completeness(projected, "quick")
    projected["cache"] = {"hit": False, "mode": "quick"}
    return projected


def read_cache(path: Path, mode: str, max_age_hours: int | None = None) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != CACHE_SCHEMA_VERSION:
            return None
        if max_age_hours is not None:
            cached_at = datetime.fromisoformat(payload["cached_at_utc"])
            if utc_now() - cached_at > timedelta(hours=max_age_hours):
                return None
        if payload.get("mode") != mode:
            return None
        report = payload.get("report")
        return report if isinstance(report, dict) else None
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None


def write_cache(path: Path, report: dict, mode: str) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": CACHE_SCHEMA_VERSION,
            "cached_at_utc": utc_now().isoformat(),
            "mode": mode,
            "report": report,
        }
        temp = path.with_suffix(path.suffix + f".{threading.get_ident()}.tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(path)
        return True
    except OSError:
        return False


def parse_repo_url(value: str) -> tuple[str, str]:
    value = value.strip()
    if not value:
        raise ValueError("empty URL")
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urllib.parse.urlparse(value)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        raise ValueError("not a github.com URL")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("URL does not contain owner/repository")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        raise ValueError("missing owner or repository")
    return owner, repo


def request_json(
    path: str,
    budget: RequestBudget,
    token: str | None = None,
) -> tuple[object | None, str | None]:
    if not budget.claim():
        return None, "request budget exhausted"
    url = path if path.startswith("http") else API_ROOT + path
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "github-repo-screening-readonly/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        message = f"HTTP {exc.code}"
        if exc.code == 403:
            message += " (rate limit or access denied)"
        return None, message
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return None, str(exc)


def decode_base64_text(
    payload: dict,
    max_bytes: int,
    truncate: bool = False,
) -> tuple[str | None, bool, str | None]:
    if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        return None, False, "unsupported content encoding"
    try:
        raw = base64.b64decode(payload["content"], validate=False)
    except (ValueError, TypeError) as exc:
        return None, False, str(exc)
    if len(raw) > max_bytes:
        if not truncate:
            return None, False, "file exceeds static review size limit"
        raw = raw[:max_bytes]
        was_truncated = True
    else:
        was_truncated = False
    return raw.decode("utf-8", errors="replace"), was_truncated, None


def request_repository_text(
    prefix: str,
    path: str,
    budget: RequestBudget,
    token: str | None = None,
) -> tuple[str | None, str | None]:
    encoded_path = urllib.parse.quote(path, safe="/")
    payload, error = request_json(prefix + "/contents/" + encoded_path, budget, token)
    if error or not isinstance(payload, dict):
        return None, error or "file content unavailable"
    content, _, decode_error = decode_base64_text(payload, SCRIPT_REVIEW_MAX_BYTES)
    return content, decode_error


def scan_script_text(path: str, content: str) -> dict:
    matches = [name for name, pattern in SCRIPT_PATTERNS.items() if pattern.search(content)]
    return {
        "path": path,
        "kind": review_file_kind(path),
        "patterns": matches,
        "note": "Pattern matches are review leads, not proof of malicious behavior.",
    }


def review_file_kind(path: str) -> str:
    normalized = path.lower().replace("\\", "/")
    filename = normalized.rsplit("/", 1)[-1]
    suffix = Path(filename).suffix.lower()
    if filename in AGENT_SKILL_FILE_NAMES:
        return "agent_skill_instruction"
    if filename in AGENT_MANIFEST_NAMES:
        return "agent_plugin_manifest"
    if normalized.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
        return "github_workflow"
    if suffix in SCRIPT_EXTENSIONS:
        return "script"
    return "configuration_or_manifest"


def summarize_release(release: dict) -> dict:
    assets = []
    for asset in release.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        assets.append(
            {
                "name": asset.get("name"),
                "content_type": asset.get("content_type"),
                "size": asset.get("size"),
                "download_count": asset.get("download_count"),
                "browser_download_url": asset.get("browser_download_url"),
            }
        )
    return {
        "tag": release.get("tag_name"),
        "name": release.get("name"),
        "draft": release.get("draft"),
        "prerelease": release.get("prerelease"),
        "published_at": release.get("published_at"),
        "html_url": release.get("html_url"),
        "assets": assets,
    }


def platform_signals(readme_content: str | None, latest_release: dict | None) -> dict:
    text = readme_content or ""
    asset_names = [
        str(asset.get("name") or "")
        for asset in ((latest_release or {}).get("assets") or [])
        if isinstance(asset, dict)
    ]
    return {
        platform: {
            "readme_mentioned": bool(pattern.search(text)),
            "matching_release_assets": [
                name for name in asset_names if PLATFORM_ASSET_PATTERNS[platform].search(name)
            ],
        }
        for platform, pattern in PLATFORM_PATTERNS.items()
    } | {
        "note": "Mentions and asset names are evidence leads, not proof of full platform support."
    }


def evidence_completeness(result: dict, mode: str) -> dict:
    evidence = result.get("evidence") or {}
    completed = ["repository_metadata"]
    partial = []
    not_run = []

    if (evidence.get("readme") or {}).get("content"):
        completed.append("readme_content")
    else:
        partial.append("readme_content")
    if "latest_release" in evidence:
        completed.append("latest_release")
    else:
        partial.append("latest_release")
    if "latest_commit" in evidence:
        completed.append("latest_commit")
    else:
        partial.append("latest_commit")
    if evidence.get("security_advisories_status") == "available":
        completed.append("repository_security_advisories")
    else:
        partial.append("repository_security_advisories")

    if mode == "deep":
        if "tree" in evidence:
            completed.append("repository_tree")
        else:
            partial.append("repository_tree")
        review = evidence.get("script_static_review") or {}
        if review.get("reviewed_count", 0) > 0 or review.get("candidate_count") == 0:
            completed.append("selected_static_files")
        else:
            partial.append("selected_static_files")
        if "releases" in evidence:
            completed.append("release_assets")
        else:
            partial.append("release_assets")
    else:
        not_run.extend(["repository_tree", "selected_static_files", "release_assets"])

    not_run.extend(["full_dependency_vulnerability_scan", "ownership_change_audit", "runtime_validation"])
    return {
        "mode": mode,
        "completed": completed,
        "partial_or_unavailable": partial,
        "not_run": not_run,
    }


def names_and_signals(tree: list[dict]) -> dict:
    paths = [item.get("path", "") for item in tree if item.get("type") == "blob"]
    lower = [p.lower() for p in paths]
    implementation = [
        p for p in paths if Path(p).suffix.lower() in IMPLEMENTATION_EXTENSIONS
    ]
    implementation_dirs = [
        p for p in paths if any(p.lower().startswith(prefix) for prefix in IMPLEMENTATION_DIRS)
    ]
    tests = [p for p in paths if any(marker in p.lower().split("/") for marker in TEST_MARKERS)]
    package_files = [p for p in paths if Path(p).name.lower() in DEPENDENCY_FILE_NAMES]
    workflows = [p for p in paths if p.lower().startswith(".github/workflows/")]
    agent_skill_files = [
        p for p in paths if Path(p).name.lower() in AGENT_SKILL_FILE_NAMES
    ]
    agent_manifest_files = [
        p for p in paths if Path(p).name.lower() in AGENT_MANIFEST_NAMES
    ]
    placeholders = [
        p for p in paths if Path(p).name.lower() in {"todo", "coming-soon", "placeholder"}
    ]
    security_sensitive_files = [
        p for p in paths if Path(p).name.lower() in SECURITY_SENSITIVE_NAMES
    ]
    persistence_review_candidates = []
    sensitive_access_review_candidates = []
    installation_script_candidates = []
    static_review_candidates: list[tuple[int, str]] = []
    for path in paths:
        normalized = path.lower().replace("\\", "/")
        segments = [part for part in normalized.split("/") if part]
        filename = segments[-1] if segments else ""
        suffix = Path(filename).suffix.lower()
        is_fixture_or_generated = any(part in IGNORED_REVIEW_SEGMENTS for part in segments[:-1])
        if (
            any(part in PERSISTENCE_SEGMENTS for part in segments)
            or any(marker in filename for marker in PERSISTENCE_NAME_MARKERS)
        ):
            persistence_review_candidates.append(path)
        if (
            any(part in SENSITIVE_ACCESS_SEGMENTS for part in segments)
            or any(marker in filename for marker in SENSITIVE_ACCESS_NAME_MARKERS)
        ):
            sensitive_access_review_candidates.append(path)
        if (
            suffix in SCRIPT_EXTENSIONS
            and any(part in INSTALL_PATH_SEGMENTS for part in segments)
        ):
            installation_script_candidates.append(path)
        if is_fixture_or_generated:
            continue
        if filename in AGENT_PLUGIN_MANIFEST_NAMES:
            static_review_candidates.append((0, path))
        elif filename in AGENT_SKILL_FILE_NAMES and any(
            marker in normalized for marker in AGENT_SETUP_PATH_MARKERS
        ):
            static_review_candidates.append((0, path))
        elif filename in AGENT_SKILL_FILE_NAMES and any(
            marker in normalized for marker in AGENT_HIGH_IMPACT_PATH_MARKERS
        ):
            static_review_candidates.append((1, path))
        elif suffix in SCRIPT_EXTENSIONS and any(marker in filename for marker in INSTALL_NAME_MARKERS):
            static_review_candidates.append((0, path))
        elif filename in REVIEWABLE_CONFIG_NAMES:
            static_review_candidates.append((1, path))
        elif normalized.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
            static_review_candidates.append((2, path))
        elif filename in AGENT_INTERFACE_MANIFEST_NAMES:
            static_review_candidates.append((3, path))
        elif suffix in SCRIPT_EXTENSIONS and (
            any(part in PERSISTENCE_SEGMENTS for part in segments)
            or any(part in SENSITIVE_ACCESS_SEGMENTS for part in segments)
            or any(part in INSTALL_PATH_SEGMENTS for part in segments)
        ):
            static_review_candidates.append((3, path))
        elif filename in AGENT_SKILL_FILE_NAMES:
            static_review_candidates.append((4, path))
    binary_files = [
        p for p in paths if Path(p).suffix.lower() in {".exe", ".msi", ".dll", ".sys", ".dmg", ".pkg", ".appimage"}
    ]
    ordered_review_candidates = []
    for _, path in sorted(
        static_review_candidates,
        key=lambda item: (item[0], item[1].count("/"), item[1].lower()),
    ):
        if path not in ordered_review_candidates:
            ordered_review_candidates.append(path)
    return {
        "file_count": len(paths),
        "implementation_file_count": len(implementation),
        "implementation_samples": implementation[:30],
        "implementation_directory_samples": implementation_dirs[:30],
        "test_file_count": len(tests),
        "test_samples": tests[:30],
        "package_and_runtime_file_count": len(package_files),
        "package_and_runtime_files": package_files[:30],
        "workflow_file_count": len(workflows),
        "workflow_samples": workflows[:20],
        "agent_skill_file_count": len(agent_skill_files),
        "agent_skill_samples": agent_skill_files[:30],
        "agent_manifest_file_count": len(agent_manifest_files),
        "agent_manifest_files": agent_manifest_files[:20],
        "agent_plugin_manifest_count": sum(
            1 for path in agent_manifest_files
            if Path(path).name.lower() in AGENT_PLUGIN_MANIFEST_NAMES
        ),
        "agent_interface_manifest_count": sum(
            1 for path in agent_manifest_files
            if Path(path).name.lower() in AGENT_INTERFACE_MANIFEST_NAMES
        ),
        "project_shape_signals": {
            "agent_skill_repository": bool(agent_skill_files),
            "agent_plugin_or_marketplace": bool(agent_manifest_files),
            "note": "Shape signals classify repository contents; they do not prove usefulness or safety.",
        },
        "placeholder_samples": placeholders[:20],
        "security_sensitive_file_samples": security_sensitive_files[:30],
        "persistence_review_candidate_samples": persistence_review_candidates[:30],
        "sensitive_access_review_candidate_samples": sensitive_access_review_candidates[:30],
        "installation_script_candidate_samples": installation_script_candidates[:30],
        "static_review_candidate_samples": ordered_review_candidates[:50],
        "binary_file_samples": binary_files[:30],
        "has_readme": any(name in {"readme", "readme.md", "readme.rst"} for name in lower),
    }


def inspect_repo(
    owner: str,
    repo: str,
    mode: str,
    budget: RequestBudget,
    cache_dir: Path | None = None,
    cache_hours: int = DEFAULT_CACHE_HOURS,
    force_refresh: bool = False,
    token: str | None = None,
    script_review_limit: int = DEFAULT_SCRIPT_REVIEW_LIMIT,
    expanded_script_review_limit: int = EXPANDED_SCRIPT_REVIEW_LIMIT,
) -> dict:
    cache_path = None
    cached = None
    quick_cached = None
    if cache_dir:
        quick_path = quick_cache_path(cache_dir, owner, repo)
        if not force_refresh:
            quick_cached = read_cache(quick_path, "quick", cache_hours)
        if mode == "quick":
            cache_path = quick_path
            cached = quick_cached
        else:
            cached_sha = latest_commit_sha(quick_cached)
            if cached_sha:
                cache_path = deep_cache_path(
                    cache_dir,
                    owner,
                    repo,
                    cached_sha,
                    script_review_limit,
                    expanded_script_review_limit,
                )
                cached = read_cache(cache_path, "deep", None)
    if cached is not None:
        cached.setdefault("cache", {})
        cached["cache"].update({"hit": True, "path": str(cache_path), "mode": mode})
        return cached
    prefix = f"/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    metadata, error = request_json(prefix, budget, token)
    if error or not isinstance(metadata, dict):
        return {
            "repository": f"{owner}/{repo}",
            "url": f"https://github.com/{owner}/{repo}",
            "status": "unavailable",
            "errors": [error or "repository metadata unavailable"],
        }

    result = {
        "repository": f"{owner}/{repo}",
        "url": metadata.get("html_url"),
        "status": "ok",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "description": metadata.get("description"),
            "language": metadata.get("language"),
            "license": (metadata.get("license") or {}).get("spdx_id"),
            "archived": metadata.get("archived"),
            "disabled": metadata.get("disabled"),
            "default_branch": metadata.get("default_branch"),
            "created_at": metadata.get("created_at"),
            "updated_at": metadata.get("updated_at"),
            "pushed_at": metadata.get("pushed_at"),
            "open_issues": metadata.get("open_issues_count"),
            "stars": metadata.get("stargazers_count"),
            "forks": metadata.get("forks_count"),
            "is_fork": metadata.get("fork"),
            "has_pages": metadata.get("has_pages"),
        },
        "evidence": {},
        "errors": [],
    }

    readme, readme_error = request_json(prefix + "/readme", budget, token)
    if isinstance(readme, dict):
        readme_content, readme_truncated, readme_decode_error = decode_base64_text(
            readme,
            README_REVIEW_MAX_BYTES,
            truncate=True,
        )
        result["evidence"]["readme"] = {
            "name": readme.get("name"),
            "size": readme.get("size"),
            "html_url": readme.get("html_url"),
            "download_url": readme.get("download_url"),
            "content": readme_content,
            "content_truncated": readme_truncated,
        }
        if readme_decode_error:
            result["errors"].append(f"README content: {readme_decode_error}")
    elif readme_error:
        result["errors"].append(f"README: {readme_error}")

    latest_release, latest_release_error = request_json(prefix + "/releases/latest", budget, token)
    if isinstance(latest_release, dict):
        result["evidence"]["latest_release"] = summarize_release(latest_release)
    elif latest_release_error and latest_release_error.startswith("HTTP 404"):
        result["evidence"]["latest_release"] = None
    elif latest_release_error:
        result["errors"].append(f"latest release: {latest_release_error}")

    result["evidence"]["platform_signals"] = platform_signals(
        (result["evidence"].get("readme") or {}).get("content"),
        result["evidence"].get("latest_release"),
    )

    if mode == "deep":
        branch = metadata.get("default_branch") or "main"
        tree_path = prefix + "/git/trees/" + urllib.parse.quote(str(branch), safe="") + "?recursive=1"
        tree, tree_error = request_json(tree_path, budget, token)
        if isinstance(tree, dict):
            entries = tree.get("tree", [])
            tree_signals = names_and_signals(entries)
            result["evidence"]["tree"] = tree_signals
            result["evidence"]["tree_truncated"] = tree.get("truncated", False)
            script_candidates = tree_signals.get("static_review_candidate_samples", [])
            initial_limit = max(0, script_review_limit)
            expanded_limit = max(initial_limit, expanded_script_review_limit)
            script_reviews = []

            def review_paths(paths: list[str]) -> None:
                for path in paths:
                    content, content_error = request_repository_text(prefix, path, budget, token)
                    if content is not None:
                        script_reviews.append(scan_script_text(path, content))
                    else:
                        script_reviews.append({"path": path, "patterns": [], "error": content_error})

            review_paths(script_candidates[:initial_limit])
            risk_pattern_detected = any(item.get("patterns") for item in script_reviews)
            effective_limit = expanded_limit if risk_pattern_detected else initial_limit
            if effective_limit > initial_limit:
                review_paths(script_candidates[initial_limit:effective_limit])
            result["evidence"]["script_static_review"] = {
                "reviewed_count": len(script_reviews),
                "candidate_count": len(script_candidates),
                "initial_limit": initial_limit,
                "effective_limit": effective_limit,
                "expanded_after_risk_match": risk_pattern_detected and effective_limit > initial_limit,
                "truncated": len(script_candidates) > effective_limit,
                "files": script_reviews,
            }
        elif tree_error:
            result["errors"].append(f"file tree: {tree_error}")

        releases, releases_error = request_json(prefix + "/releases?per_page=5", budget, token)
        if isinstance(releases, list):
            result["evidence"]["releases"] = [summarize_release(r) for r in releases]
        elif releases_error and not releases_error.startswith("HTTP 404"):
            result["errors"].append(f"releases: {releases_error}")

    commits, commits_error = request_json(prefix + "/commits?per_page=1", budget, token)
    if isinstance(commits, list):
        if commits:
            commit = commits[0]
            details = commit.get("commit") or {}
            author = details.get("author") or {}
            result["evidence"]["latest_commit"] = {
                "sha": commit.get("sha"),
                "date": author.get("date"),
                "message": details.get("message"),
                "html_url": commit.get("html_url"),
            }
        else:
            result["evidence"]["latest_commit"] = None
    elif commits_error:
        result["errors"].append(f"commits: {commits_error}")

    advisories, advisories_error = request_json(prefix + "/security-advisories?per_page=10", budget, token)
    if isinstance(advisories, list):
        result["evidence"]["security_advisories_status"] = "available"
        result["evidence"]["security_advisories"] = [
            {
                "ghsa_id": item.get("ghsa_id"),
                "cve_id": item.get("cve_id"),
                "severity": item.get("severity"),
                "summary": item.get("summary"),
                "published_at": item.get("published_at"),
                "updated_at": item.get("updated_at"),
                "withdrawn_at": item.get("withdrawn_at"),
                "html_url": item.get("html_url"),
                "vulnerabilities": [
                    {
                        "package": vulnerability.get("package"),
                        "vulnerable_version_range": vulnerability.get("vulnerable_version_range"),
                        "first_patched_version": vulnerability.get("first_patched_version"),
                    }
                    for vulnerability in (item.get("vulnerabilities") or [])
                    if isinstance(vulnerability, dict)
                ],
            }
            for item in advisories
        ]
    elif advisories_error:
        result["evidence"]["security_advisories_status"] = "unavailable"
        if not advisories_error.startswith("HTTP 404"):
            result["errors"].append(f"security advisories: {advisories_error}")

    result["evidence_completeness"] = evidence_completeness(result, mode)
    result["cache"] = {"hit": False, "mode": mode}
    if cache_dir:
        current_sha = latest_commit_sha(result)
        if mode == "quick":
            write_cache(quick_cache_path(cache_dir, owner, repo), result, "quick")
        else:
            if current_sha:
                write_cache(
                    deep_cache_path(
                        cache_dir,
                        owner,
                        repo,
                        current_sha,
                        script_review_limit,
                        expanded_script_review_limit,
                    ),
                    result,
                    "deep",
                )
            write_cache(quick_cache_path(cache_dir, owner, repo), quick_projection(result), "quick")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect read-only GitHub repository evidence")
    parser.add_argument("--url", action="append", default=[], help="Public GitHub repository URL; repeatable")
    parser.add_argument("--input", type=Path, help="UTF-8 text file with one GitHub URL per line")
    parser.add_argument("--out", type=Path, default=Path("github-evidence.json"))
    parser.add_argument("--mode", choices=("quick", "deep"), default="quick")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS)
    parser.add_argument("--request-budget", type=int, default=DEFAULT_REQUEST_BUDGET)
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=default_cache_dir(),
        help="Cache directory; defaults to the operating system's user cache directory",
    )
    parser.add_argument("--cache-hours", type=int, default=DEFAULT_CACHE_HOURS)
    parser.add_argument("--force-refresh", action="store_true")
    parser.add_argument(
        "--use-token",
        action="store_true",
        help="Use GITHUB_TOKEN from the environment; requires explicit user approval",
    )
    parser.add_argument("--script-limit", type=int, default=DEFAULT_SCRIPT_REVIEW_LIMIT)
    parser.add_argument(
        "--expanded-script-limit",
        type=int,
        default=EXPANDED_SCRIPT_REVIEW_LIMIT,
        help="Maximum selected files after an initial risk-pattern match",
    )
    args = parser.parse_args()

    token = None
    if args.use_token:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            parser.error("--use-token requires GITHUB_TOKEN in the environment")

    urls = list(args.url)
    if args.input:
        urls.extend(line.strip() for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))
    if not urls:
        parser.error("provide at least one --url or --input")

    budget = RequestBudget(args.request_budget)
    jobs: list[tuple[str, str, str]] = []
    reports: list[dict] = []
    for raw_url in urls:
        try:
            owner, repo = parse_repo_url(raw_url)
            jobs.append((raw_url, owner, repo))
        except ValueError as exc:
            reports.append({"url": raw_url, "status": "invalid", "errors": [str(exc)]})

    def run_job(job: tuple[str, str, str]) -> dict:
        raw_url, owner, repo = job
        report = inspect_repo(
            owner,
            repo,
            args.mode,
            budget,
            cache_dir=args.cache_dir,
            cache_hours=args.cache_hours,
            force_refresh=args.force_refresh,
            token=token,
            script_review_limit=args.script_limit,
            expanded_script_review_limit=args.expanded_script_limit,
        )
        report.setdefault("input_url", raw_url)
        return report

    worker_count = max(1, min(args.max_workers, len(jobs) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        reports.extend(executor.map(run_job, jobs))

    payload = {
        "tool": "github-repo-screening",
        "read_only": True,
        "mode": args.mode,
        "request_budget": {"limit": budget.limit, "used": budget.used},
        "max_workers": worker_count,
        "authentication": "github_token" if token else "anonymous",
        "script_review_limit": max(0, args.script_limit),
        "expanded_script_review_limit": max(args.script_limit, args.expanded_script_limit),
        "cache_dir": str(args.cache_dir) if args.cache_dir else None,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repositories": reports,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {len(reports)} repository report(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

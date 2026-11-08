"""Builds the site with the pinned Hugo and checks pages, bundle templates and the forecast table.

Run: py -3 scripts/test_site_build.py -v
Hugo is found through HUGO_BIN, then ../tools/hugo/hugo(.exe) next to this repository, then PATH.
Test posts and test forecasts are created in a temporary copy, never in the repository.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HUGO_VERSION = "0.169.0"


def hugo_binary() -> str:
    configured = os.environ.get("HUGO_BIN")
    if configured:
        return configured
    local = ROOT.parent / "tools" / "hugo" / ("hugo.exe" if os.name == "nt" else "hugo")
    if local.is_file():
        return str(local)
    found = shutil.which("hugo")
    if found:
        return found
    raise unittest.SkipTest("hugo not found; set HUGO_BIN")


def run_hugo(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([hugo_binary(), *args], capture_output=True, text=True, encoding="utf-8")


def copy_site(parent: Path) -> Path:
    target = parent / "site"
    shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(".git", "public", "resources", ".hugo_build.lock"))
    return target


def build(source: Path, destination: Path, drafts: bool = False) -> None:
    args = ["--source", str(source), "--destination", str(destination), "--quiet"]
    if drafts:
        args.append("--buildDrafts")
    result = run_hugo(*args)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class SiteBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "public"
        build(ROOT, cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_hugo_version_is_pinned(self):
        self.assertIn(f"v{HUGO_VERSION}", run_hugo("version").stdout)

    def test_menu_pages_exist(self):
        for page in ("index.html", "index.xml", "index.json", "analyses/index.html", "techniques/index.html",
                     "archives/index.html", "groups/index.html", "forecasts/index.html", "tags/index.html",
                     "methodology/index.html", "about/index.html", "search/index.html"):
            with self.subTest(page=page):
                self.assertTrue((self.out / page).is_file(), page)

    def test_methodology_pages_exist(self):
        for slug in ("analysis-template", "lab", "attribution-scoring", "adversarial-review",
                     "forecasting", "publishing-policy", "ai-usage"):
            with self.subTest(slug=slug):
                self.assertTrue((self.out / "methodology" / slug / "index.html").is_file(), slug)

    def test_forecasts_page_shows_empty_registry(self):
        html = read(self.out / "forecasts" / "index.html")
        self.assertIn("열린 전망 (0)", html)
        self.assertIn("판정된 전망 (0)", html)

    def test_raw_html_rendering_is_off(self):
        self.assertIn("unsafe: false", read(ROOT / "hugo.yaml"))


FORECAST_SAMPLE = """items:
  - id: "F-TEST-001"
    created: "2026-01-01"
    deadline: "2026-12-31"
    statement: "Open forecast statement"
    probability: 40
    post: ""
    status: "open"
    resolution: ""
  - id: "F-TEST-002"
    created: "2026-01-01"
    deadline: "2026-02-01"
    statement: "Resolved true"
    probability: 80
    post: ""
    status: "resolved_true"
    resolution: "test"
  - id: "F-TEST-003"
    created: "2026-01-01"
    deadline: "2026-03-01"
    statement: "Resolved false"
    probability: 30
    post: ""
    status: "resolved_false"
    resolution: "test"
"""


class ForecastTableTests(unittest.TestCase):
    def test_open_and_resolved_forecasts_and_brier_score(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        site = copy_site(Path(tmp.name))
        (site / "data" / "forecasts.yaml").write_text(FORECAST_SAMPLE, encoding="utf-8")
        out = Path(tmp.name) / "public"
        build(site, out)
        html = read(out / "forecasts" / "index.html")
        self.assertIn("열린 전망 (1)", html)
        self.assertIn("판정된 전망 (2)", html)
        self.assertIn("Open forecast statement", html)
        self.assertIn("브라이어 점수: 0.065", html)


class BundleTemplateTests(unittest.TestCase):
    def new_site_copy(self) -> tuple[Path, Path]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return copy_site(Path(tmp.name)), Path(tmp.name) / "public"

    def new_content(self, site: Path, kind: str, path: str) -> None:
        result = run_hugo("new", "content", "--source", str(site), "--kind", kind, path)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_analysis_bundle_has_files_and_all_sections(self):
        site, out = self.new_site_copy()
        self.new_content(site, "analyses", "analyses/2026/2026-01-01-template-test")
        bundle = site / "content" / "analyses" / "2026" / "2026-01-01-template-test"
        self.assertTrue((bundle / "iocs.csv").is_file())
        self.assertTrue((bundle / "evidence" / "attribution.csv").is_file())
        build(site, out, drafts=True)
        page = out / "analyses" / "2026" / "2026-01-01-template-test"
        html = read(page / "index.html")
        for heading in ("1. English Summary", "2. 개요", "3. 트리아지", "4. 정적 분석", "5. 언패킹·복호화",
                        "6. 동적 분석", "7. 설정 추출", "8. 탐지", "9. IoC", "10. 공격 그룹 유사도",
                        "11. 적대적 검증", "12. 맥락과 전망", "13. 기관 공유", "14. 한계와 남은 질문",
                        "15. 작업 구분과 AI 사용 내역"):
            with self.subTest(heading=heading):
                self.assertIn(heading, html)
        self.assertTrue((page / "iocs.csv").is_file())
        self.assertIn("English summary in two or three sentences", read(out / "analyses" / "index.html"))

    def test_technique_bundle_has_all_sections(self):
        site, out = self.new_site_copy()
        self.new_content(site, "techniques", "techniques/2026/2026-01-01-template-test")
        build(site, out, drafts=True)
        html = read(out / "techniques" / "2026" / "2026-01-01-template-test" / "index.html")
        for heading in ("1. English Summary", "2. 목적", "3. 대상 프로그램", "4. 원리", "5. 재현 절차",
                        "6. 검증", "7. 탐지 관점", "8. 한계", "9. AI 사용 내역"):
            with self.subTest(heading=heading):
                self.assertIn(heading, html)

    def test_draft_posts_are_not_in_a_normal_build(self):
        site, out = self.new_site_copy()
        self.new_content(site, "analyses", "analyses/2026/2026-01-01-template-test")
        build(site, out)
        self.assertFalse((out / "analyses" / "2026" / "2026-01-01-template-test" / "index.html").exists())


if __name__ == "__main__":
    unittest.main()

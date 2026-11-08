"""Unit tests for prepublish_check.py. Run: py -3 scripts/test_prepublish_check.py -v

Sample values that the checker blocks (private IPs, keys, phone numbers) are assembled
at run time so that this file itself passes the check.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import prepublish_check as pc  # noqa: E402


def private_ip() -> str:
    return ".".join(["192", "168", "1", "10"])


def check_text(text: str, path: str = "content/x/index.md", ctx: pc.Context | None = None) -> list:
    return pc.check_content(path, text.encode("utf-8"), ctx or pc.Context())


def rules(findings) -> list[str]:
    return [finding.rule for finding in findings]


class BinaryTests(unittest.TestCase):
    def test_pe_header_is_blocked(self):
        data = b"M" + b"Z" + b"\x90\x00" * 16
        self.assertEqual(rules(pc.check_content("content/x/sample.bin", data, pc.Context())), ["binary"])

    def test_zip_archive_is_blocked(self):
        data = b"P" + b"K\x03\x04" + b"\x00" * 26
        self.assertEqual(rules(pc.check_content("content/x/tools.zip", data, pc.Context())), ["binary"])

    def test_office_document_is_blocked(self):
        data = b"\xd0\xcf" + b"\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8
        self.assertEqual(rules(pc.check_content("content/x/lure.doc", data, pc.Context())), ["binary"])

    def test_plain_markdown_passes(self):
        self.assertEqual(check_text("# 제목\n\n본문 문단.\n"), [])

    def test_finding_format_includes_location(self):
        finding = pc.Finding("content/x/index.md", 3, "private-ip", "detail")
        self.assertEqual(finding.format(), "content/x/index.md:3: [private-ip] detail")


class PrivateIpTests(unittest.TestCase):
    def test_private_ip_is_blocked(self):
        findings = check_text(f"fallback C2 {private_ip()} seen\n")
        self.assertEqual([(f.rule, f.line) for f in findings], [("private-ip", 1)])

    def test_defanged_private_ip_is_blocked(self):
        defanged = private_ip().replace(".", "[.]")
        self.assertEqual(rules(check_text(f"hxxp://{defanged}/gate\n")), ["private-ip"])

    def test_loopback_documentation_and_public_addresses_pass(self):
        parts = (("127", "0", "0", "1"), ("192", "0", "2", "15"), ("203", "0", "113", "9"), ("8", "8", "8", "8"))
        self.assertEqual(check_text(" ".join(".".join(p) for p in parts)), [])

    def test_allowlisted_address_passes(self):
        ctx = pc.Context(allowed_ips={private_ip()})
        self.assertEqual(check_text(private_ip(), ctx=ctx), [])

    def test_version_numbers_are_not_addresses(self):
        self.assertEqual(check_text("Windows 10.0.22621.4249, OID 1.3.6.1.4.1.311\n"), [])


class DenylistTests(unittest.TestCase):
    def test_term_is_blocked_case_insensitively(self):
        ctx = pc.Context(denylist=["acme-internal"])
        self.assertEqual(rules(check_text("see ACME-Internal wiki\n", ctx=ctx)), ["denylist"])

    def test_korean_term_is_blocked(self):
        ctx = pc.Context(denylist=["사내용어"])
        findings = check_text("첫 줄\n여기에 사내용어가 있다\n", ctx=ctx)
        self.assertEqual([(f.rule, f.line) for f in findings], [("denylist", 2)])

    def test_load_denylist_skips_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deny.txt"
            path.write_text("# comment\n\nAcme-Internal\n  사내용어  \n", encoding="utf-8")
            self.assertEqual(pc.load_denylist(path), ["acme-internal", "사내용어"])


def phone_kr() -> str:
    return "010" + "-1234-5678"


class AllowlistTests(unittest.TestCase):
    def test_parse_kinds(self):
        text = "# header\n" + f"ip | {private_ip()} | hardcoded in sample\n" + "secret | tokenvalue | sample config\n"
        allowed, problems = pc.parse_allowlist(text)
        self.assertEqual(problems, [])
        self.assertIn(private_ip(), allowed["ip"])
        self.assertIn("tokenvalue", allowed["secret"])

    def test_pii_entry_needs_evidence_and_report(self):
        allowed, problems = pc.parse_allowlist(f"pii | {phone_kr()} | reported=KISA 2026-11-20\n")
        self.assertEqual(rules(problems), ["allowlist"])
        self.assertNotIn(phone_kr(), allowed["pii"])

    def test_complete_pii_entry_is_accepted(self):
        line = f"pii | {phone_kr()} | evidence=content/analyses/x/index.md | reported=KISA 2026-11-20\n"
        allowed, problems = pc.parse_allowlist(line)
        self.assertEqual(problems, [])
        self.assertIn(phone_kr(), allowed["pii"])

    def test_malformed_line_is_reported(self):
        allowed, problems = pc.parse_allowlist("ip only-two | fields\n")
        self.assertEqual(rules(problems), ["allowlist"])


class SecretTests(unittest.TestCase):
    def test_private_key_header_is_blocked(self):
        self.assertEqual(rules(check_text("-----BEGIN " + "RSA PRIVATE KEY-----\n")), ["secret"])

    def test_aws_access_key_is_blocked(self):
        self.assertEqual(rules(check_text("key AKIA" + "ABCDEFGHIJKLMNOP\n")), ["secret"])

    def test_github_token_is_blocked(self):
        self.assertEqual(rules(check_text("ghp_" + "a" * 36 + "\n")), ["secret"])

    def test_env_file_is_blocked(self):
        self.assertEqual(rules(check_text("X=1\n", path=".env")), ["secret"])

    def test_allowlisted_secret_passes(self):
        value = "AKIA" + "ABCDEFGHIJKLMNOP"
        self.assertEqual(check_text(value, ctx=pc.Context(allowed_secrets={value})), [])


class PiiTests(unittest.TestCase):
    def test_korean_mobile_number_is_blocked(self):
        self.assertEqual(rules(check_text(f"contact {phone_kr()}\n")), ["pii"])

    def test_international_number_is_blocked(self):
        self.assertEqual(rules(check_text("call +1 " + "202 555 0143\n")), ["pii"])

    def test_resident_registration_number_is_blocked(self):
        self.assertEqual(rules(check_text("id " + "900101" + "-1234567\n")), ["pii"])

    def test_same_number_reported_once(self):
        number = "+82" + "-10-1234-5678"
        self.assertEqual(rules(check_text(f"call {number}\n")), ["pii"])

    def test_digits_inside_hashes_and_dates_pass(self):
        self.assertEqual(check_text("sha a" + "0101" + "2345678" + "b, date 2026-11-08\n"), [])

    def test_allowlisted_pii_passes(self):
        self.assertEqual(check_text(phone_kr(), ctx=pc.Context(allowed_pii={phone_kr()})), [])


def jpeg(app_marker: int, payload: bytes) -> bytes:
    segment = bytes([0xFF, app_marker]) + (len(payload) + 2).to_bytes(2, "big") + payload
    return b"\xff\xd8" + segment + b"\xff\xda\x00\x02" + b"\x00" * 4


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + kind + payload + b"\x00\x00\x00\x00"


def png(*chunks: bytes) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"".join(chunks) + png_chunk(b"IEND", b"")


class ImageMetadataTests(unittest.TestCase):
    def test_jpeg_exif_is_blocked(self):
        data = jpeg(0xE1, b"Exif\x00\x00" + b"\x00" * 10)
        self.assertEqual(rules(pc.check_content("content/x/images/a.jpg", data, pc.Context())), ["image-metadata"])

    def test_jpeg_without_exif_passes(self):
        data = jpeg(0xE0, b"JFIF\x00" + b"\x00" * 9)
        self.assertEqual(pc.check_content("content/x/images/a.jpg", data, pc.Context()), [])

    def test_png_exif_chunk_is_blocked(self):
        data = png(png_chunk(b"IHDR", b"\x00" * 13), png_chunk(b"eXIf", b"MM\x00\x2a"))
        self.assertEqual(rules(pc.check_content("content/x/images/a.png", data, pc.Context())), ["image-metadata"])

    def test_png_without_exif_passes(self):
        data = png(png_chunk(b"IHDR", b"\x00" * 13))
        self.assertEqual(pc.check_content("content/x/images/a.png", data, pc.Context()), [])


class UncalibratedLabelTests(unittest.TestCase):
    FRONT = "---\ntitle: t\nattribution:\n  - group: G\n    score: 40\n    calibrated: false\n---\n"

    def test_missing_label_is_blocked(self):
        findings = check_text(self.FRONT + "\n본문\n")
        self.assertEqual([(f.rule, f.line) for f in findings], [("uncalibrated-label", 6)])

    def test_label_in_body_passes(self):
        self.assertEqual(check_text(self.FRONT + "\nG 40% (미교정)\n"), [])

    def test_commented_example_is_ignored(self):
        self.assertEqual(check_text("---\ntitle: t\n#    calibrated: false\n---\n본문\n"), [])

    def test_non_markdown_files_are_ignored(self):
        self.assertEqual(check_text(self.FRONT, path="content/x/notes.txt"), [])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.root, check=True)

    def write(self, relative: str, text: str) -> None:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def git_add(self, relative: str) -> None:
        subprocess.run(["git", "add", relative], cwd=self.root, check=True)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        return subprocess.run([sys.executable, str(HERE / "prepublish_check.py"), "--root", str(self.root), *args],
                              capture_output=True, text=True, encoding="utf-8", env=env)

    def test_clean_repository_passes(self):
        self.write("content/a.md", "clean text\n")
        result = self.run_cli("--all")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_untracked_new_file_is_checked(self):
        self.write("content/a.md", f"addr {private_ip()}\n")
        result = self.run_cli("--all")
        self.assertEqual(result.returncode, 1)
        self.assertIn("content/a.md:1: [private-ip]", result.stdout)

    def test_themes_directory_is_skipped(self):
        self.write("themes/x/readme.md", f"addr {private_ip()}\n")
        self.assertEqual(self.run_cli("--all").returncode, 0)

    def test_ignored_build_output_is_skipped(self):
        self.write(".gitignore", "public/\n")
        self.write("public/index.html", f"addr {private_ip()}\n")
        self.assertEqual(self.run_cli("--all").returncode, 0)

    def test_staged_mode_checks_the_index_version(self):
        self.write("content/a.md", "clean\n")
        self.git_add("content/a.md")
        self.write("content/a.md", f"addr {private_ip()}\n")
        self.assertEqual(self.run_cli("--staged").returncode, 0)
        self.git_add("content/a.md")
        self.assertEqual(self.run_cli("--staged").returncode, 1)

    def test_missing_denylist_fails_closed(self):
        missing = Path(self.tmp.name) / "missing.txt"
        result = self.run_cli("--all", "--require-denylist", "--denylist", str(missing))
        self.assertEqual(result.returncode, 2)

    def test_denylist_terms_are_applied(self):
        deny = Path(self.tmp.name) / "deny.txt"
        deny.write_text("acme-internal\n", encoding="utf-8")
        self.write("content/a.md", "see Acme-Internal wiki\n")
        result = self.run_cli("--all", "--require-denylist", "--denylist", str(deny))
        self.assertEqual(result.returncode, 1)
        self.assertIn("[denylist]", result.stdout)

    def test_allowlist_file_is_read_from_root(self):
        self.write(".prepublish-allow.txt", f"ip | {private_ip()} | hardcoded in sample\n")
        self.write("content/a.md", f"addr {private_ip()}\n")
        self.assertEqual(self.run_cli("--all").returncode, 0)


if __name__ == "__main__":
    unittest.main()

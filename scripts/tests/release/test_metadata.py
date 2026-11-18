import hashlib
import os
import pathlib
import tempfile
import unittest
import uuid

from scripts.tests.release import load

metadata = load("metadata")

CHANGELOG = (
    "# Changelog\n\n## [Unreleased]\n\n"
    "## v0.7.0 (2026-11-03)\n\nGate flags: migration, breaking\n\n### What's Changed\n- feat: one\n\n"
    "## v0.7.0-rc.1 (2026-11-02)\n\nGate flags: breaking\n\n- feat: candidate\n\n"
    "## [0.6.2-rc.1] - 2026-11-01\n\nGate flags: none\n\n- fix: candidate\n\n"
    "## [0.6.1] - 2026-11-01\n\n- fix: two\n\n"
    "## v0.6.0 (2026-10-30)\n\n"
)


class ChangelogSection(unittest.TestCase):
    def test_reads_only_the_versions_section_in_either_heading_style(self):
        section = metadata.changelog_section(CHANGELOG, "0.7.0")
        self.assertIn("feat: one", section)
        self.assertNotIn("fix: two", section)
        self.assertEqual(metadata.changelog_section(CHANGELOG, "0.6.1"), "- fix: two")
        self.assertIn("fix: candidate", metadata.changelog_section(CHANGELOG, "0.6.2-rc.1"))

    def test_a_release_candidate_has_its_own_section(self):
        candidate = metadata.changelog_section(CHANGELOG, "0.7.0-rc.1")
        self.assertIn("feat: candidate", candidate)
        self.assertNotIn("feat: one", candidate)
        with self.assertRaisesRegex(SystemExit, "no section for 0.6.1-rc.1"):
            metadata.changelog_section(CHANGELOG, "0.6.1-rc.1")

    def test_refuses_a_missing_or_empty_section(self):
        with self.assertRaisesRegex(SystemExit, "no section for 9.9.9"):
            metadata.changelog_section(CHANGELOG, "9.9.9")
        with self.assertRaisesRegex(SystemExit, "is empty"):
            metadata.changelog_section(CHANGELOG, "0.6.0")


class GateFlags(unittest.TestCase):
    def test_reads_sorted_known_flags_or_none(self):
        self.assertEqual(metadata.gate_flags("Gate flags: migration, breaking"), ["breaking", "migration"])
        self.assertEqual(metadata.gate_flags("Gate flags: none"), [])

    def test_a_missing_line_fails_unless_allowed(self):
        with self.assertRaisesRegex(SystemExit, "no 'Gate flags:' line"):
            metadata.gate_flags("- fix: two")
        self.assertEqual(metadata.gate_flags("- fix: two", required=False), [])

    def test_an_empty_line_fails_even_when_the_line_is_optional(self):
        for line in ("Gate flags:", "Gate flags:   ", "Gate flags: ,"):
            with self.assertRaisesRegex(SystemExit, "line is empty"):
                metadata.gate_flags(line, required=False)

    def test_refuses_an_unknown_flag(self):
        with self.assertRaisesRegex(SystemExit, "unknown gate flags"):
            metadata.gate_flags("Gate flags: risky")


class Sbom(unittest.TestCase):
    METADATA = {
        "workspace_members": ["path+file:///w#tenkai@0.7.0", "path+file:///w/crates/tenkai-wire#0.7.0"],
        "packages": [
            {"id": "path+file:///w#tenkai@0.7.0", "name": "tenkai", "version": "0.7.0", "license": "Apache-2.0"},
            {"id": "path+file:///w/crates/tenkai-wire#0.7.0", "name": "tenkai-wire", "version": "0.7.0", "license": "Apache-2.0"},
            {"id": "registry+x#libc@0.2.0", "name": "libc", "version": "0.2.0", "license": "MIT OR Apache-2.0"},
            {"id": "registry+x#memchr@2.0.0", "name": "memchr", "version": "2.0.0", "license": "MIT/Unlicense"},
            {"id": "registry+x#ring@0.17.0", "name": "ring", "version": "0.17.0", "license": None},
        ],
    }

    def setUp(self):
        self.console = metadata.console_component("v0.2.0 " + "e" * 64)
        self.bom = metadata.bom_from_metadata(self.METADATA, self.console)

    def test_same_inputs_give_the_same_serial_number(self):
        self.assertEqual(self.bom, metadata.bom_from_metadata(self.METADATA, self.console))
        uuid.UUID(self.bom["serialNumber"].removeprefix("urn:uuid:"))

    def test_lists_dependencies_and_the_console_but_not_workspace_crates(self):
        self.assertEqual(self.bom["metadata"]["component"]["name"], "tenkai")
        by_name = {c["name"]: c for c in self.bom["components"]}
        self.assertEqual(set(by_name), {"libc", "memchr", "ring", "tenkai-console"})
        self.assertEqual(by_name["tenkai-console"]["hashes"], [{"alg": "SHA-256", "content": "e" * 64}])
        self.assertEqual(by_name["memchr"]["licenses"], [{"expression": "MIT OR Unlicense"}])
        self.assertNotIn("licenses", by_name["ring"])


class BuildManifest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"meta{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.dist = pathlib.Path(tmp.name)
        (self.dist / "tenkaictl-linux-x86_64").write_bytes(b"bin")
        (self.dist / "tenkai-http-v1.schema.json").write_text("{}\n")
        for name in metadata.METADATA_FILES:
            (self.dist / name).write_text("metadata\n")

    def build(self, *, version="0.7.0", git_sha="a" * 40, tag="v0.7.0"):
        return metadata.build_manifest(
            version=version, git_sha=git_sha, tag=tag, dist=self.dist, attestations=[], flags=[]
        )

    def test_lists_every_release_asset_by_digest_but_no_metadata(self):
        manifest = self.build()
        self.assertEqual(
            [item["name"] for item in manifest["binaries"]],
            ["tenkai-http-v1.schema.json", "tenkaictl-linux-x86_64"],
        )
        self.assertEqual(manifest["binaries"][1]["digest"], "sha256:" + hashlib.sha256(b"bin").hexdigest())

    def test_refuses_a_short_sha(self):
        with self.assertRaisesRegex(SystemExit, "full lowercase SHA"):
            self.build(git_sha="abc")

    def test_tag_must_equal_the_version_exactly(self):
        candidate = self.build(version="0.7.1-rc.1", tag="v0.7.1-rc.1")
        self.assertEqual((candidate["version"], candidate["tag"]), ("0.7.1-rc.1", "v0.7.1-rc.1"))
        for tag in ("v0.7.1", "v0.7.0-rc.1"):
            with self.subTest(tag=tag), self.assertRaisesRegex(SystemExit, "does not match version"):
                self.build(tag=tag)


class Formula(unittest.TestCase):
    """Formula/tenkai.rb pins every download to the release's SHA256SUMS."""

    def setUp(self):
        self.sums = {
            f"{host}-{platform}": hashlib.sha256(f"{host}-{platform}".encode()).hexdigest()
            for host in metadata.FORMULA_HOSTS
            for platform in metadata.FORMULA_PLATFORMS.values()
        }

    def test_downloads_each_host_of_each_platform_at_its_digest(self):
        text = metadata.formula("0.9.2", self.sums)
        base = "https://github.com/Sannrox/tenkai/releases/download/v0.9.2/"
        for name, digest in self.sums.items():
            with self.subTest(name=name):
                self.assertRegex(text, f'url "{base}{name}", using: :nounzip\\n +sha256 "{digest}"\\n')
        self.assertEqual(text.count('url "'), len(self.sums))
        self.assertIn('version "0.9.2"', text)

    def test_refuses_a_missing_asset_or_a_bad_version(self):
        del self.sums["tenkai-executor-guard-linux-aarch64"]
        with self.assertRaisesRegex(SystemExit, "no tenkai-executor-guard-linux-aarch64"):
            metadata.formula("0.9.2", self.sums)
        with self.assertRaisesRegex(SystemExit, "not a release version"):
            metadata.formula("v0.9.2", self.sums)

    def test_reads_sha256sums_strictly(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"meta{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name) / "SHA256SUMS"
        path.write_text(f"{'a' * 64}  tenkaictl-linux-x86_64\n")
        self.assertEqual(metadata.checksums(path), {"tenkaictl-linux-x86_64": "a" * 64})
        path.write_text(f"{'a' * 63}  tenkaictl-linux-x86_64\n")
        with self.assertRaisesRegex(SystemExit, "not a SHA256SUMS line"):
            metadata.checksums(path)


if __name__ == "__main__":
    unittest.main()

"""verify-tag.sh against real annotated, signed, and lightweight tags in scratch repositories."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from scripts.tests.release import RELEASE

SCRIPT = RELEASE / "verify-tag.sh"
MALFORMED = ("v1.0.3-rc", "v1.0.3-rc.0", "v1.0.3-rc.01", "v1.0.3-beta.1", "v1.0.3-rc.1.2", "v1.0.3rc.1", "v01.0.3", "1.0.3")
UNKNOWN_KEY = "AEDA618886BF0331105B9CFCE4DC1F4A579505FB\n"


def cargo(version: str) -> str:
    # A dependency's version line must not be read as the package version.
    return f'[package]\nname = "fixture"\nversion = "{version}"\n\n[dependencies]\nversion = "9.9.9"\n'


class Repo:
    """A scratch Git repository driven with the test's environment."""

    def __init__(self, path: pathlib.Path, env: dict):
        self.path, self.env = path, env

    def __call__(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.path), *args], env=self.env, check=True, capture_output=True, text=True,
        ).stdout.strip()

    @classmethod
    def init(cls, path: pathlib.Path, env: dict, signing_key: str = "") -> "Repo":
        subprocess.run(["git", "init", "-q", "-b", "main", str(path)], env=env, check=True)
        repo = cls(path, env)
        for key, value in {
            "user.name": "Release test", "user.email": "release-test@example.invalid",
            "commit.gpgsign": "false", "tag.gpgSign": "false",
            "user.signingkey": signing_key, "gpg.program": shutil.which("gpg") or "gpg",
        }.items():
            repo("config", key, value)
        return repo

    def commit(self, version: str, message: str) -> str:
        (self.path / "Cargo.toml").write_text(cargo(version))
        self("add", "Cargo.toml")
        self("commit", "-q", "--allow-empty", "-m", message)
        return self("rev-parse", "HEAD")


def run(*args: str, cwd: pathlib.Path, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), *args], cwd=cwd, env=env, capture_output=True, text=True)


class TagPattern(unittest.TestCase):
    def test_maintenance_line_is_release_major_minor(self):
        for tag, line in (
            ("v0.5.1", "release-0.5"), ("v0.5.1-rc.2", "release-0.5"), ("v0.0.1", "release-0.0"),
            ("v1.2.3", "release-1.2"), ("v1.0.0-rc.1", "release-1.0"),
        ):
            with self.subTest(tag=tag):
                result = run("maintenance-line", tag, cwd=RELEASE, env=os.environ)
                self.assertEqual(result.stdout.strip(), line, result.stderr)

    def test_refuses_malformed_tags(self):
        for tag in MALFORMED:
            for command in (("maintenance-line", tag), ("verify-signed", tag, "a" * 40), ("verify", tag, "a" * 40)):
                with self.subTest(command=command):
                    result = run(*command, cwd=RELEASE, env=os.environ)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("invalid release tag", result.stderr)


class Ancestry(unittest.TestCase):
    """require-ancestry against injected origin refs: only main or the matching line releases."""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix=f"anc{os.getpid()}-")
        cls.addClassCleanup(tmp.cleanup)
        repo = Repo.init(pathlib.Path(tmp.name), os.environ)
        cls.repo = repo
        cls.fork = repo.commit("0.1.0", "A")
        cls.main = repo.commit("0.2.0", "main")
        cls.tips = {}
        for branch in ("release-0.5", "release-0.4", "other", "release-1.2"):
            repo("checkout", "-q", "-b", branch, cls.fork)
            cls.tips[branch] = repo.commit(branch, branch)
        repo("update-ref", "refs/remotes/origin/main", cls.main)
        for branch, sha in cls.tips.items():
            repo("update-ref", f"refs/remotes/origin/{branch}", sha)

    def ancestry(self, tag: str, sha: str) -> subprocess.CompletedProcess:
        return run("require-ancestry", tag, sha, cwd=self.repo.path, env=os.environ)

    def test_main_wins_when_the_commit_is_on_main(self):
        for tag, sha in (("v0.5.1", self.main), ("v0.5.1", self.fork), ("v1.2.3", self.main), ("v0.5.1-rc.1", self.main)):
            with self.subTest(tag=tag, sha=sha):
                self.assertEqual(self.ancestry(tag, sha).stdout.strip(), "main")

    def test_accepts_the_matching_maintenance_line(self):
        for tag, branch in (("v0.5.2", "release-0.5"), ("v0.5.2-rc.1", "release-0.5"), ("v1.2.3", "release-1.2")):
            with self.subTest(tag=tag):
                self.assertEqual(self.ancestry(tag, self.tips[branch]).stdout.strip(), branch)

    def test_refuses_another_line_or_branch(self):
        for tag, branch, line in (
            ("v0.5.1", "release-0.4", "release-0.5"), ("v0.5.1", "release-1.2", "release-0.5"),
            ("v1.2.3", "release-0.5", "release-1.2"), ("v0.5.1", "other", "release-0.5"),
            ("v1.3.1", "release-1.2", "release-1.3"),
        ):
            with self.subTest(tag=tag, branch=branch):
                result = self.ancestry(tag, self.tips[branch])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"is not on main or {line}", result.stderr)


class RemoteTag(unittest.TestCase):
    """verify: the live remote tag still resolves to the release commit."""

    def test_follows_the_live_remote_tag(self):
        with tempfile.TemporaryDirectory(prefix=f"rt{os.getpid()}-") as tmp:
            remote = pathlib.Path(tmp) / "remote.git"
            subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
            repo = Repo.init(pathlib.Path(tmp) / "work", os.environ)
            first = repo.commit("1.0.0", "first")
            repo("tag", "v1.0.0", first)
            repo("tag", "-a", "v1.0.1", "-m", "annotated", first)
            repo("push", "-q", str(remote), "refs/tags/v1.0.0", "refs/tags/v1.0.1")
            verify = lambda tag, sha: run("verify", tag, sha, str(remote), cwd=repo.path, env=os.environ)
            for tag in ("v1.0.0", "v1.0.1"):
                self.assertEqual(verify(tag, first).returncode, 0)
            second = repo.commit("1.0.1", "second")
            repo("tag", "--force", "v1.0.0", second)
            repo("push", "-q", "--force", str(remote), "refs/tags/v1.0.0")
            moved = verify("v1.0.0", first)
            self.assertNotEqual(moved.returncode, 0)
            self.assertIn(f"expected {first}", moved.stderr)
            self.assertEqual(verify("v1.0.0", second).returncode, 0)
            self.assertIn("was not found", verify("v1.0.2", second).stderr)


@unittest.skipUnless(shutil.which("gpg"), "gpg is required")
class SignedTag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Short base path: gpg-agent socket paths have a length limit.
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"vt{os.getpid()}-", dir="/tmp"))
        cls.addClassCleanup(shutil.rmtree, cls.tmp, ignore_errors=True)
        gnupg = cls.tmp / "g"
        gnupg.mkdir(mode=0o700)
        cls.env = {**os.environ, "GNUPGHOME": str(gnupg)}
        cls.addClassCleanup(subprocess.run, ["gpgconf", "--kill", "gpg-agent"], env=cls.env, capture_output=True)
        subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", "Release test <release-test@example.invalid>", "ed25519", "sign", "never"],
            env=cls.env, check=True, capture_output=True,
        )
        listing = subprocess.run(
            ["gpg", "--batch", "--list-secret-keys", "--with-colons"],
            env=cls.env, check=True, capture_output=True, text=True,
        ).stdout
        cls.fpr = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.key = cls.tmp / "key.asc"
        cls.key.write_bytes(subprocess.run(
            ["gpg", "--batch", "--armor", "--export", cls.fpr], env=cls.env, check=True, capture_output=True,
        ).stdout)
        cls.fingerprints = cls.tmp / "fingerprints"
        cls.env.update(RELEASE_TAG_KEY=str(cls.key), RELEASE_TAG_FINGERPRINTS=str(cls.fingerprints))

        # main: first (1.2.3) -> rc (1.2.3-rc.1). release-1.1: line (1.1.4) off first.
        cls.repo = repo = Repo.init(cls.tmp / "w", cls.env, cls.fpr)
        cls.first = repo.commit("1.2.3", "first")
        repo("tag", "v1.2.0", cls.first)
        repo("tag", "-a", "v1.2.1", "-m", "unsigned", cls.first)
        repo("tag", "-s", "v1.2.3", "-m", "signed", cls.first)
        repo("tag", "-s", "v1.2.4", "-m", "wrong version", cls.first)
        repo("tag", "-s", "v1.2.3-rc.1", "-m", "rc at the final version", cls.first)
        cls.rc = repo.commit("1.2.3-rc.2", "rc")
        repo("tag", "-s", "v1.2.3-rc.2", "-m", "candidate", cls.rc)
        repo("tag", "-s", "v1.2.3-rc.3", "-m", "next candidate", cls.rc)
        repo("checkout", "-q", "-b", "release-1.1", cls.first)
        cls.line = repo.commit("1.1.4", "maintenance")
        repo("tag", "-s", "v1.1.4", "-m", "maintenance", cls.line)
        repo("checkout", "-q", "-b", "elsewhere", cls.first)
        cls.elsewhere = repo.commit("1.2.5", "not released")
        repo("tag", "-s", "v1.2.5", "-m", "off main", cls.elsewhere)
        repo("checkout", "-q", "main")
        cls.origin = cls.tmp / "o.git"
        subprocess.run(["git", "init", "--bare", "-q", str(cls.origin)], check=True)
        repo("push", "-q", str(cls.origin), "main", "release-1.1", "--tags")

    def setUp(self):
        self.fingerprints.write_text(f"# test key\n{self.fpr}\n")

    def signed(self, tag: str, sha: str, env: dict | None = None) -> subprocess.CompletedProcess:
        env = {**(env or self.env), "RELEASE_ROOT": str(self.repo.path)}
        self.repo("checkout", "-q", f"{tag}^{{commit}}")
        self.addCleanup(self.repo, "checkout", "-q", "main")
        return run("verify-signed", tag, sha, cwd=self.repo.path, env=env)

    def assertRefused(self, result: subprocess.CompletedProcess, message: str):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_accepts_a_signed_tag_at_the_workspace_version(self):
        for tag, sha in (("v1.2.3", self.first), ("v1.2.3-rc.2", self.rc)):
            with self.subTest(tag=tag):
                result = self.signed(tag, sha)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_lightweight_and_unsigned_tags(self):
        self.assertRefused(self.signed("v1.2.0", self.first), "is lightweight")
        self.assertRefused(self.signed("v1.2.1", self.first), "is unsigned")

    def test_refuses_a_tag_for_another_commit(self):
        self.assertRefused(self.signed("v1.2.3", "0" * 40), f"expected {'0' * 40}")

    def test_tag_and_workspace_version_match_exactly(self):
        self.assertRefused(self.signed("v1.2.4", self.first), "does not match workspace version 1.2.3")
        self.assertRefused(self.signed("v1.2.3-rc.1", self.first), "does not match workspace version 1.2.3")
        self.assertRefused(self.signed("v1.2.3-rc.3", self.rc), "does not match workspace version 1.2.3-rc.2")

    def test_refuses_a_key_that_is_not_listed(self):
        self.fingerprints.write_text(UNKNOWN_KEY)
        self.assertRefused(self.signed("v1.2.3", self.first), "not listed")

    def test_refuses_a_revoked_key(self):
        # Revoke in a copy of the keyring so the other tests keep a valid key.
        gnupg = self.tmp / "r"
        shutil.copytree(self.env["GNUPGHOME"], gnupg, ignore=shutil.ignore_patterns("S.*"))
        key = self.tmp / "revoked.asc"
        env = {**self.env, "GNUPGHOME": str(gnupg), "RELEASE_TAG_KEY": str(key)}
        self.addCleanup(subprocess.run, ["gpgconf", "--kill", "gpg-agent"], env=env, capture_output=True)
        # gpg writes the revocation certificate at key generation, armored
        # with a leading ':' so it is not imported by accident.
        cert = (gnupg / "openpgp-revocs.d" / f"{self.fpr}.rev").read_text().replace(":-----", "-----")
        subprocess.run(["gpg", "--batch", "--import"], input=cert, env=env, check=True, capture_output=True, text=True)
        key.write_bytes(subprocess.run(
            ["gpg", "--batch", "--armor", "--export", self.fpr], env=env, check=True, capture_output=True,
        ).stdout)
        self.assertRefused(self.signed("v1.2.3", self.first, env), "revoked or expired")

    def release_commit(self, tag: str, workflow_ref: str = "refs/heads/main") -> subprocess.CompletedProcess:
        """release-commit from a fresh checkout of the tag, as the workflow runs it."""
        source = pathlib.Path(tempfile.mkdtemp(prefix="src", dir=self.tmp))
        subprocess.run(["git", "clone", "-q", str(self.origin), str(source)], env=self.env, check=True)
        subprocess.run(["git", "-C", str(source), "checkout", "-q", f"{tag}^{{commit}}"], env=self.env, check=True)
        return run("release-commit", tag, workflow_ref, cwd=source, env={**self.env, "RELEASE_ROOT": str(source)})

    def test_release_commit_accepts_main_and_the_matching_line(self):
        for tag, line in (("v1.2.3", "main"), ("v1.2.3-rc.2", "main"), ("v1.1.4", "release-1.1")):
            with self.subTest(tag=tag):
                result = self.release_commit(tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"line={line}\n")

    def test_release_commit_refuses_a_run_not_from_main(self):
        self.assertRefused(self.release_commit("v1.2.3", "refs/heads/feature"), "must start from refs/heads/main")

    def test_release_commit_refuses_a_commit_off_main_and_its_line(self):
        self.assertRefused(self.release_commit("v1.2.5"), "is not on main or release-1.2")

    def test_release_commit_refuses_an_unsigned_tag(self):
        self.assertRefused(self.release_commit("v1.2.1"), "is unsigned")


if __name__ == "__main__":
    unittest.main()

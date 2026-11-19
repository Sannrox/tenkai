"""Release invariants no workflow linter expresses, asserted on the parsed YAML.

The scripts enforce these at run time; these tests keep the workflows from
bypassing them. Assert on structure (triggers, permissions, job graph, step
order, which script a step runs), never on the wording of a step.
"""

import unittest

import yaml

from scripts.tests.release import ROOT

WORKFLOWS = ROOT / ".github" / "workflows"
VERIFIED_SHA = "${{ needs.verify-tag.outputs.sha }}"
TAGGED = "needs.verify-tag.outputs.tag != ''"
MAIN_TREE = "${{ github.workspace }}/main-tree"


def load(name: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS / name).read_text())
    doc["on"] = doc.pop(True, doc.get("on"))  # YAML 1.1 reads a bare `on` key as True.
    return doc


def runs(step: dict) -> str:
    return step.get("run", "")


def uses(step: dict) -> str:
    return step.get("uses", "")


def is_mutation(step: dict) -> bool:
    return (
        uses(step).startswith("actions/attest")
        or "github-release.sh draft" in runs(step)
        or "github-release.sh publish" in runs(step)
    )


def is_guard(step: dict) -> bool:
    return "github-release.sh guard" in runs(step)


def index(steps: list, predicate) -> int:
    return next(i for i, step in enumerate(steps) if predicate(step))


def needs(job: dict) -> set:
    value = job.get("needs", [])
    return {value} if isinstance(value, str) else set(value)


def strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)
    elif isinstance(node, str):
        yield node


class Dispatcher(unittest.TestCase):
    """A v* tag push only starts release-binaries.yml from main; it can do nothing else."""

    def setUp(self):
        self.wf = load("release-dispatch.yml")

    def test_triggers_only_on_v_tags(self):
        self.assertEqual(self.wf["on"], {"push": {"tags": ["v*"]}})

    def test_can_only_dispatch_workflows(self):
        self.assertEqual(self.wf["permissions"], {"actions": "write", "contents": "read"})

    def test_runs_one_step_that_dispatches_the_release_on_main(self):
        [job] = self.wf["jobs"].values()
        self.assertNotIn("permissions", job)
        [step] = job["steps"]
        self.assertNotIn("uses", step)
        self.assertEqual(step["run"].strip(), 'gh workflow run release-binaries.yml --ref main -f tag="$TAG"')


class Release(unittest.TestCase):
    def setUp(self):
        self.wf = load("release-binaries.yml")
        self.jobs = self.wf["jobs"]

    def test_runs_only_when_dispatched(self):
        self.assertEqual(set(self.wf["on"]), {"workflow_dispatch"})
        self.assertIn("tag", self.wf["on"]["workflow_dispatch"]["inputs"])

    def test_one_run_per_tag(self):
        self.assertIn("inputs.tag", self.wf["concurrency"]["group"])
        self.assertFalse(self.wf["concurrency"]["cancel-in-progress"])

    def test_verifies_the_tag_with_mains_verifier_and_keys(self):
        steps = self.jobs["verify-tag"]["steps"]
        main_checkout = next(s for s in steps if s.get("with", {}).get("path") == "main-tree")
        self.assertNotIn("ref", main_checkout["with"], "main's verifier must come from the workflow ref")
        verify = steps[index(steps, lambda s: "release-commit" in runs(s))]
        self.assertIn('"${MAIN_TREE}/scripts/release/verify-tag.sh" release-commit', verify["run"])
        env = verify["env"]
        self.assertEqual(env["MAIN_TREE"], MAIN_TREE)
        self.assertEqual(env["WORKFLOW_REF"], "${{ github.ref }}")
        self.assertEqual(env["RELEASE_TAG_KEY"], f"{MAIN_TREE}/security/release-tag-key.asc")
        self.assertEqual(env["RELEASE_TAG_FINGERPRINTS"], f"{MAIN_TREE}/security/release-tag-fingerprints")
        self.assertEqual(self.jobs["verify-tag"]["outputs"]["line"], f"${{{{ steps.{verify['id']}.outputs.line }}}}")

    def test_guards_with_mains_script_before_any_later_job(self):
        steps = self.jobs["verify-tag"]["steps"]
        guard = steps[index(steps, is_guard)]
        self.assertIn("main-tree/scripts/release/github-release.sh guard", guard["run"])
        self.assertLess(index(steps, lambda s: "release-commit" in runs(s)), steps.index(guard))

    def test_every_later_job_builds_the_verified_commit(self):
        for name, job in self.jobs.items():
            if name == "verify-tag":
                continue
            with self.subTest(job=name):
                self.assertIn("verify-tag", needs(job))
                steps = job["steps"]
                checkouts = [i for i, s in enumerate(steps) if uses(s).startswith("actions/checkout@")]
                self.assertTrue(checkouts)
                for i in checkouts:
                    self.assertEqual(steps[i].get("with", {}).get("ref"), VERIFIED_SHA)
                    self.assertIn('test "$(git rev-parse HEAD)" = "$SHA"', runs(steps[i + 1]))
                    self.assertEqual(steps[i + 1]["env"]["SHA"], VERIFIED_SHA)

    def test_only_the_dry_run_runs_without_a_tag(self):
        gates = {name: job.get("if") for name, job in self.jobs.items() if name != "verify-tag"}
        for dry_run in ("dry-run", "dry-run-macos"):
            self.assertEqual(gates.pop(dry_run), "needs.verify-tag.outputs.tag == ''")
        self.assertEqual(set(gates.values()), {TAGGED})

    def test_never_uses_the_event_commit_or_ref_name(self):
        for value in strings(self.jobs):
            for banned in ("github.sha", "github.ref_name", "GITHUB_SHA", "GITHUB_REF_NAME", "github.event_name"):
                self.assertNotIn(banned, value)

    def test_release_changes_go_through_the_release_script(self):
        for value in strings(self.jobs):
            self.assertNotIn("gh release ", value)

    def test_every_mutating_job_refuses_a_published_release_first(self):
        mutating = set()
        for name, job in self.jobs.items():
            steps = job["steps"]
            first = next((i for i, s in enumerate(steps) if is_mutation(s)), None)
            if first is None:
                continue
            mutating.add(name)
            with self.subTest(job=name):
                guards = [s for s in steps[:first] if is_guard(s)]
                self.assertTrue(guards, f"{name} mutates before the guard")
                self.assertTrue(all("if" not in s for s in guards), f"{name} guard must always run")
        self.assertEqual(mutating, {"attest", "publish"})

    def test_publish_checks_the_live_tag_before_each_change(self):
        steps = self.jobs["publish"]["steps"]
        for i, step in enumerate(steps):
            if is_mutation(step):
                with self.subTest(step=runs(step)):
                    self.assertIn("verify-tag.sh verify", runs(steps[i - 1]))

    def test_publish_runs_last_after_every_asset_job(self):
        publish = self.jobs["publish"]
        self.assertIn("attest", needs(publish))
        self.assertLessEqual({"package", "package-linux", "sbom"}, needs(self.jobs["attest"]))
        after_publish = {name for name, job in self.jobs.items() if "publish" in needs(job)}
        self.assertEqual(after_publish, {"tap"})

    def test_the_tap_gets_the_attested_formula_after_the_install_check(self):
        steps = self.jobs["tap"]["steps"]
        download = index(steps, lambda s: uses(s).startswith("actions/download-artifact"))
        self.assertEqual(steps[download]["with"]["name"], "release-assets")
        install = index(steps, lambda s: "test-macos-install.sh" in runs(s))
        push = index(steps, lambda s: "git -C" in runs(s) and " push " in runs(s))
        self.assertLess(download, install)
        self.assertLess(install, push)
        self.assertFalse(any("secrets." in v for s in steps[:push] for v in strings(s)))

    def test_attest_writes_the_formula_from_the_final_checksums(self):
        steps = self.jobs["attest"]["steps"]
        packages = index(steps, lambda s: "system-packages" in runs(s))
        checksums = index(steps, lambda s: "package-release-binaries.sh checksums" in runs(s))
        formula = index(steps, lambda s: "metadata.py formula" in runs(s))
        first_attest = index(steps, lambda s: uses(s).startswith("actions/attest"))
        self.assertLess(packages, checksums)
        self.assertLess(checksums, formula)
        self.assertLess(formula, first_attest)

    def test_publishes_the_line_verify_tag_accepted(self):
        steps = self.jobs["publish"]["steps"]
        publish = steps[index(steps, lambda s: "github-release.sh publish" in runs(s))]
        self.assertEqual(publish["env"]["LINE"], "${{ needs.verify-tag.outputs.line }}")

    def test_attests_the_checked_assets_and_then_the_final_manifest(self):
        steps = self.jobs["attest"]["steps"]
        glibc = index(steps, lambda s: "check-glibc" in runs(s))
        checksums = index(steps, lambda s: "package-release-binaries.sh checksums" in runs(s))
        first_attest = index(steps, lambda s: uses(s).startswith("actions/attest"))
        manifest = index(steps, lambda s: "metadata.py manifest" in runs(s))
        last_attest = max(i for i, s in enumerate(steps) if uses(s).startswith("actions/attest"))
        self.assertLess(glibc, checksums)
        self.assertLess(checksums, first_attest)
        self.assertLess(manifest, last_attest)
        self.assertEqual(steps[last_attest]["with"]["subject-path"], "dist/tenkai-release.json")
        self.assertFalse(any("metadata.py manifest" in runs(s) for s in self.jobs["publish"]["steps"]))

    def test_write_permissions_are_job_scoped(self):
        self.assertEqual(self.wf["permissions"], {"contents": "read"})
        writers = {
            name: {k for k, v in job.get("permissions", {}).items() if v == "write"}
            for name, job in self.jobs.items()
        }
        self.assertEqual(
            {name: perms for name, perms in writers.items() if perms},
            {"attest": {"attestations", "artifact-metadata", "id-token"}, "publish": {"contents"}},
        )


class Ci(unittest.TestCase):
    def test_maintenance_lines_get_ci_on_push(self):
        ci = load("ci.yml")
        self.assertIn("release-*", ci["on"]["push"]["branches"])

    def test_a_cold_rebuild_must_match_the_dry_run_hosts(self):
        jobs = load("ci.yml")["jobs"]
        dry_run, rebuild = jobs["release-dry-run"], jobs["release-reproducible"]
        self.assertEqual(rebuild["needs"], "release-dry-run")
        self.assertIn("needs.release-dry-run.outputs.run", rebuild["if"])
        self.assertIn("steps.scope.outputs.run", dry_run["outputs"]["run"])
        # The rebuild restores no build state, so it is an independent build.
        self.assertFalse([s for s in rebuild["steps"] if "cache" in uses(s)])
        commands = [runs(s) for s in rebuild["steps"]]
        build = next(i for i, c in enumerate(commands) if "scripts/build-linux-release-hosts.sh" in c)
        compare = next(
            i for i, c in enumerate(commands) if "scripts/package-release-binaries.sh compare" in c
        )
        self.assertLess(build, compare)


if __name__ == "__main__":
    unittest.main()

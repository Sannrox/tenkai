#!/usr/bin/env python3
"""Release metadata for the v* workflow: CHANGELOG notes, SBOM, family manifest.

Usage:
  scripts/release-metadata.py notes VERSION
      Print the CHANGELOG.md section for VERSION (the GitHub Release body).
  scripts/release-metadata.py sbom OUT
      Write a CycloneDX 1.5 SBOM of the locked Cargo dependency graph and the
      pinned web-console bundle the release hosts embed.
  scripts/release-metadata.py check-sbom PATH
      Validate PATH against the CycloneDX 1.5 JSON schema and SPDX license
      expressions. Needs cyclonedx-python-lib[json-validation]; the release
      workflow runs it in a job without attestation permissions.
  scripts/release-metadata.py manifest --version V --git-sha SHA --tag TAG
      --dist DIR --out PATH [--attestation URL]...
      Write the tenkai.family-release-manifest.v1 (docs/family-release-manifests.md)
      for the release assets in DIR, with gate flags from the CHANGELOG section.
  scripts/release-metadata.py self-test

Everything except check-sbom uses only the standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPONENT = "tenkai"
MANIFEST_SCHEMA = "tenkai.family-release-manifest.v1"
GATE_FLAGS = ("breaking", "migration", "realm")
# Generated release metadata. Every other file in dist is a release asset
# whose digest the manifest lists.
METADATA_FILES = {"SHA256SUMS", "tenkai.cdx.json", "tenkai-release.json"}

_HEADING = re.compile(r"^## +\[?v?([^\]\s]+)\]?.*$", re.M)
_GATE_LINE = re.compile(r"^Gate flags: *(.*)$", re.M)


def changelog_section(text: str, version: str) -> str:
    """Body of the `## [X.Y.Z]` or `## vX.Y.Z (date)` section for version."""
    headings = list(_HEADING.finditer(text))
    for index, heading in enumerate(headings):
        if heading.group(1) != version:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[heading.end() : end].strip()
        if not body:
            raise SystemExit(f"CHANGELOG.md section for {version} is empty")
        return body
    raise SystemExit(f"CHANGELOG.md has no section for {version}")


def gate_flags(section: str) -> list[str]:
    """Flags from the section's optional `Gate flags: a, b` line (`none` allowed)."""
    lines = _GATE_LINE.findall(section)
    if len(lines) > 1:
        raise SystemExit("CHANGELOG section has more than one 'Gate flags:' line")
    if not lines or lines[0].strip().lower() == "none":
        return []
    flags = {flag.strip().lower() for flag in lines[0].split(",") if flag.strip()}
    unknown = sorted(flags - set(GATE_FLAGS))
    if unknown:
        raise SystemExit(f"unknown gate flags {unknown}; allowed: {', '.join(GATE_FLAGS)}")
    return sorted(flags)


# Cargo license fields are SPDX expressions or the legacy `A/B` form. They go
# in CycloneDX `expression`: a compound value under `license.id` makes the
# document invalid.
def license_expression(raw: str) -> str:
    return " OR ".join(part.strip() for part in raw.split("/"))


def console_component(pin: str) -> dict:
    """The web-console bundle the `ui` feature embeds, from ui/console.pin."""
    tag, sha256 = pin.split()
    return {
        "type": "file",
        "bom-ref": f"tenkai-console@{tag}",
        "name": "tenkai-console",
        "version": tag.removeprefix("v"),
        "hashes": [{"alg": "SHA-256", "content": sha256}],
        "externalReferences": [
            {
                "type": "distribution",
                "url": f"https://github.com/Sannrox/tenkai-console/releases/download/{tag}/tenkai-console-{tag}.zip",
            }
        ],
    }


def bom_from_metadata(metadata: dict, console: dict) -> dict:
    workspace = set(metadata["workspace_members"])
    root = None
    components = []
    for package in metadata["packages"]:
        purl = f"pkg:cargo/{package['name']}@{package['version']}"
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": package["name"],
            "version": package["version"],
            "purl": purl,
        }
        if package.get("license"):
            component["licenses"] = [{"expression": license_expression(package["license"])}]
        if package["id"] not in workspace:
            components.append(component)
        elif package["name"] == COMPONENT:
            root = component | {"type": "application"}
    if root is None:
        raise SystemExit(f"cargo metadata has no workspace package {COMPONENT}")
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": root},
        "components": sorted([*components, console], key=lambda item: item["bom-ref"]),
    }
    # Same locked inputs, same serial number: a rebuild yields the same document.
    canonical = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    bom["serialNumber"] = uuid.uuid5(uuid.NAMESPACE_URL, canonical).urn
    return bom


def check_sbom(path: Path) -> None:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator
    from license_expression import get_spdx_licensing

    raw = path.read_text()
    error = JsonStrictValidator(SchemaVersion.V1_5).validate_str(raw)
    if error is not None:
        detail = getattr(error.data, "message", str(error))
        where = "/".join(str(part) for part in getattr(error.data, "absolute_path", []))
        raise SystemExit(f"{path} is not valid CycloneDX 1.5 at /{where}: {detail}")
    bom = json.loads(raw)
    if not re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", bom.get("serialNumber", "")):
        raise SystemExit(f"{path} has no urn:uuid serialNumber")
    licensing = get_spdx_licensing()
    for component in [bom["metadata"]["component"], *bom["components"]]:
        for entry in component.get("licenses", []):
            if "expression" not in entry:
                raise SystemExit(f"{component['bom-ref']} license is not an SPDX expression")
            info = licensing.validate(entry["expression"], strict=True)
            if info.errors:
                raise SystemExit(f"{component['bom-ref']}: {'; '.join(info.errors)}")
    print(f"{path}: valid CycloneDX 1.5, {len(bom['components'])} components")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def build_manifest(
    *,
    version: str,
    git_sha: str,
    tag: str,
    dist: Path,
    attestations: list[str],
    flags: list[str],
) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise SystemExit("git sha must be a full lowercase SHA")
    if tag != f"v{version}":
        raise SystemExit(f"tag {tag} does not match version {version}")
    binaries = [
        {"name": path.name, "digest": sha256_file(path)}
        for path in sorted(dist.iterdir())
        if path.is_file() and path.name not in METADATA_FILES
    ]
    if not binaries:
        raise SystemExit(f"no release assets in {dist}")
    return {
        "schema": MANIFEST_SCHEMA,
        "component": COMPONENT,
        "version": version,
        "git_sha": git_sha,
        "tag": tag,
        "binaries": binaries,
        # Tenkai ships no images. Images, when added, are listed by digest only.
        "images": [],
        "attestations": attestations,
        "gate_flags": flags,
    }


def expect_exit(message: str, call) -> None:
    try:
        call()
    except SystemExit as error:
        if message not in str(error):
            raise SystemExit(f"expected failure mentioning {message!r}, got {error}") from error
    else:
        raise SystemExit(f"expected failure mentioning {message!r}")


def self_test() -> None:
    changelog = (
        "# Changelog\n\n## [Unreleased]\n\n"
        "## v0.7.0 (2026-11-03)\n\nGate flags: migration, breaking\n\n### What's Changed\n- feat: one\n\n"
        "## [0.6.1] - 2026-11-01\n\n- fix: two\n\n"
        "## v0.6.0 (2026-10-30)\n\n"
    )
    section = changelog_section(changelog, "0.7.0")
    assert "feat: one" in section and "fix: two" not in section, section
    assert changelog_section(changelog, "0.6.1") == "- fix: two"
    assert gate_flags(section) == ["breaking", "migration"]
    assert gate_flags("- fix: two") == []
    assert gate_flags("Gate flags: none") == []
    expect_exit("unknown gate flags", lambda: gate_flags("Gate flags: risky"))
    expect_exit("no section for 9.9.9", lambda: changelog_section(changelog, "9.9.9"))
    expect_exit("is empty", lambda: changelog_section(changelog, "0.6.0"))

    metadata = {
        "workspace_members": ["path+file:///w#tenkai@0.7.0", "path+file:///w/crates/tenkai-wire#0.7.0"],
        "packages": [
            {"id": "path+file:///w#tenkai@0.7.0", "name": "tenkai", "version": "0.7.0", "license": "Apache-2.0"},
            {"id": "path+file:///w/crates/tenkai-wire#0.7.0", "name": "tenkai-wire", "version": "0.7.0", "license": "Apache-2.0"},
            {"id": "registry+x#libc@0.2.0", "name": "libc", "version": "0.2.0", "license": "MIT OR Apache-2.0"},
            {"id": "registry+x#memchr@2.0.0", "name": "memchr", "version": "2.0.0", "license": "MIT/Unlicense"},
            {"id": "registry+x#ring@0.17.0", "name": "ring", "version": "0.17.0", "license": None},
        ],
    }
    console = console_component("v0.2.0 " + "e" * 64)
    bom = bom_from_metadata(metadata, console)
    assert bom == bom_from_metadata(metadata, console), "serial number must be stable"
    uuid.UUID(bom["serialNumber"].removeprefix("urn:uuid:"))
    assert bom["metadata"]["component"]["name"] == "tenkai"
    by_name = {component["name"]: component for component in bom["components"]}
    assert set(by_name) == {"libc", "memchr", "ring", "tenkai-console"}, by_name
    assert by_name["tenkai-console"]["hashes"] == [{"alg": "SHA-256", "content": "e" * 64}]
    assert by_name["memchr"]["licenses"] == [{"expression": "MIT OR Unlicense"}]
    assert "licenses" not in by_name["ring"]

    with tempfile.TemporaryDirectory(prefix="tenkai-release-metadata.") as tmp:
        dist = Path(tmp)
        (dist / "tenkaictl-linux-x86_64").write_bytes(b"bin")
        (dist / "tenkai-http-v1.schema.json").write_text("{}\n")
        for name in METADATA_FILES:
            (dist / name).write_text("metadata\n")
        common = {"version": "0.7.0", "dist": dist, "attestations": [], "flags": []}
        manifest = build_manifest(git_sha="a" * 40, tag="v0.7.0", **common)
        assert [item["name"] for item in manifest["binaries"]] == [
            "tenkai-http-v1.schema.json",
            "tenkaictl-linux-x86_64",
        ], manifest
        assert manifest["binaries"][1]["digest"] == "sha256:" + hashlib.sha256(b"bin").hexdigest()
        expect_exit("full lowercase SHA", lambda: build_manifest(git_sha="abc", tag="v0.7.0", **common))
        expect_exit("does not match version", lambda: build_manifest(git_sha="a" * 40, tag="v0.7.1", **common))
    print("release-metadata self-test passed")


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    notes = commands.add_parser("notes")
    notes.add_argument("version")
    sbom = commands.add_parser("sbom")
    sbom.add_argument("out", type=Path)
    check = commands.add_parser("check-sbom")
    check.add_argument("path", type=Path)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--version", required=True)
    manifest.add_argument("--git-sha", required=True)
    manifest.add_argument("--tag", required=True)
    manifest.add_argument("--dist", required=True, type=Path)
    manifest.add_argument("--out", required=True, type=Path)
    manifest.add_argument("--attestation", action="append", default=[])
    commands.add_parser("self-test")
    args = parser.parse_args(argv)

    if args.command == "self-test":
        self_test()
    elif args.command == "notes":
        print(changelog_section((ROOT / "CHANGELOG.md").read_text(), args.version))
    elif args.command == "sbom":
        raw = subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT, text=True
        )
        console = console_component((ROOT / "ui" / "console.pin").read_text())
        bom = bom_from_metadata(json.loads(raw), console)
        args.out.write_text(json.dumps(bom, indent=2) + "\n")
    elif args.command == "check-sbom":
        check_sbom(args.path)
    elif args.command == "manifest":
        section = changelog_section((ROOT / "CHANGELOG.md").read_text(), args.version)
        document = build_manifest(
            version=args.version,
            git_sha=args.git_sha,
            tag=args.tag,
            dist=args.dist,
            attestations=[url for url in args.attestation if url],
            flags=gate_flags(section),
        )
        args.out.write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])

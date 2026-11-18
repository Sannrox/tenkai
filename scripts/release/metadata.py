#!/usr/bin/env python3
"""Release metadata for the v* workflow: CHANGELOG notes, SBOM, family manifest.

Usage:
  scripts/release/metadata.py notes VERSION
      Print the CHANGELOG.md section for VERSION (the GitHub Release body).
  scripts/release/metadata.py sbom OUT
      Write a CycloneDX 1.5 SBOM of the locked Cargo dependency graph and the
      pinned web-console bundle the release hosts embed.
  scripts/release/metadata.py check-sbom PATH
      Validate PATH against the CycloneDX 1.5 JSON schema and SPDX license
      expressions. Needs cyclonedx-python-lib[json-validation]; the release
      workflow runs it in a job without attestation permissions.
  scripts/release/metadata.py gate-flags VERSION
      Print the gate flags of the VERSION section; fail when its
      `Gate flags:` line is missing.
  scripts/release/metadata.py manifest --version V --git-sha SHA --tag TAG
      --dist DIR --out PATH [--attestation URL]... [--allow-missing-gate-flags]
      Write the tenkai.family-release-manifest.v1 (docs/family-release-manifests.md)
      for the release assets in DIR, with gate flags from the CHANGELOG section.
      Only the dry run of an already released version allows a missing line.
  scripts/release/metadata.py formula --version V --dist DIR --out PATH [--base-url URL]
      Write the Homebrew formula Formula/tenkai.rb (tenkaictl, tenkai-server and
      tenkai-executor-guard, plus a `brew services` entry for the server) from
      DIR/SHA256SUMS. The release workflow attaches it and pushes it to the tap.
      --base-url replaces the GitHub Release download URL, for the dry run's
      install from local files.

Everything except check-sbom uses only the standard library.
scripts/tests/release/test_metadata.py tests it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPONENT = "tenkai"
MANIFEST_SCHEMA = "tenkai.family-release-manifest.v1"
GATE_FLAGS = ("breaking", "migration", "realm")
# Generated release metadata. Every other file in dist is a release asset
# whose digest the manifest lists.
METADATA_FILES = {"SHA256SUMS", "tenkai.cdx.json", "tenkai-release.json", "tenkai.rb"}
REPOSITORY = "Sannrox/tenkai"
# The hosts the formula installs, the first as its main download, and the
# platforms it covers, as Homebrew names them.
FORMULA_HOSTS = ("tenkaictl", "tenkai-server", "tenkai-executor-guard")
FORMULA_PLATFORMS = {
    ("macos", "arm"): "darwin-aarch64",
    ("linux", "intel"): "linux-x86_64",
    ("linux", "arm"): "linux-aarch64",
}

_HEADING = re.compile(r"^## +\[?v?([^\]\s]+)\]?.*$", re.M)
_GATE_LINE = re.compile(r"^Gate flags: *(.*)$", re.M)


def changelog_section(text: str, version: str) -> str:
    """Body of the `## [X.Y.Z]` or `## vX.Y.Z (date)` section for version.

    Versions match exactly, so `X.Y.Z-rc.N` has its own section.
    """
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


def gate_flags(section: str, *, required: bool = True) -> list[str]:
    """Flags from the section's `Gate flags: a, b` (or `none`) line.

    A missing or empty line fails: an empty list would release without a
    channel hold. Only an explicit `none` means no flags.
    """
    lines = _GATE_LINE.findall(section)
    if len(lines) > 1:
        raise SystemExit("CHANGELOG section has more than one 'Gate flags:' line")
    if not lines and required:
        raise SystemExit("CHANGELOG section has no 'Gate flags:' line (list flags or 'none')")
    if not lines or lines[0].strip().lower() == "none":
        return []
    flags = {flag.strip().lower() for flag in lines[0].split(",") if flag.strip()}
    if not flags:
        raise SystemExit("CHANGELOG 'Gate flags:' line is empty (list flags or 'none')")
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


def checksums(path: Path) -> dict[str, str]:
    """The SHA256SUMS lines of PATH as {asset name: hex digest}."""
    sums = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not match:
            raise SystemExit(f"{path}: not a SHA256SUMS line: {line!r}")
        sums[match[2]] = match[1]
    return sums


def formula(version: str, sums: dict[str, str], base_url: str | None = None) -> str:
    """Formula/tenkai.rb for VERSION. Every download is a raw release asset
    pinned by its SHA256SUMS digest, from the GitHub Release unless BASE_URL
    is given. The server and its guard are resources, installed beside
    tenkaictl so the server finds the guard."""
    if not re.fullmatch(r"\d+\.\d+\.\d+(-rc\.\d+)?", version):
        raise SystemExit(f"not a release version: {version}")
    base = base_url or f"https://github.com/{REPOSITORY}/releases/download/v{version}"

    def download(indent: str, platform: str, host: str) -> str:
        name = f"{host}-{platform}"
        if name not in sums:
            raise SystemExit(f"SHA256SUMS has no {name}")
        return (
            f'{indent}url "{base}/{name}", using: :nounzip\n'
            f'{indent}sha256 "{sums[name]}"\n'
        )

    blocks = []
    for os_name in ("macos", "linux"):
        cpus = []
        for (os_key, cpu), platform in FORMULA_PLATFORMS.items():
            if os_key != os_name:
                continue
            body = download("      ", platform, FORMULA_HOSTS[0])
            for host in FORMULA_HOSTS[1:]:
                body += f'\n      resource "{host}" do\n'
                body += download("        ", platform, host)
                body += "      end\n"
            cpus.append(f"    on_{cpu} do\n{body}    end\n")
        # Releases build no Intel macOS hosts.
        requires = "    depends_on arch: :arm64\n\n" if os_name == "macos" else ""
        blocks.append(f"  on_{os_name} do\n{requires}{''.join(cpus)}  end\n")
    installs = (
        f"    %w[{' '.join(FORMULA_HOSTS[1:])}].each do |host|\n"
        '      resource(host).stage { bin.install Dir["#{host}-*"].first => host }\n'
        "    end\n"
    )
    return f"""# Generated by scripts/release/metadata.py formula for tenkai v{version}.
class Tenkai < Formula
  desc "Local-first, constraint-based delivery control plane"
  homepage "https://github.com/{REPOSITORY}"
  version "{version}"
  license "Apache-2.0"

{chr(10).join(blocks)}
  def install
    bin.install Dir["{FORMULA_HOSTS[0]}-*"].first => "{FORMULA_HOSTS[0]}"
{installs}  end

  # A local evaluation server owns one management token, written once.
  def post_install
    (var/"tenkai").mkpath
    token = var/"tenkai/management.token"
    return if token.exist?

    token.write("#{{SecureRandom.hex(32)}}\n")
    token.chmod 0600
  end

  def caveats
    <<~EOS
      `brew services start tenkai` runs tenkai-server for local evaluation on
      http://127.0.0.1:8080 (web console at /ui/), with its store in
      #{{var}}/tenkai. For a server other hosts depend on, see
      https://github.com/{REPOSITORY}/blob/v{version}/docs/run-tenkai-server.md

      Talk to it with its management token:
        tenkaictl --target remote --server-url http://127.0.0.1:8080 \\
          --token-file #{{var}}/tenkai/management.token env list
    EOS
  end

  service do
    run [opt_bin/"tenkai-server", "--listen", "127.0.0.1:8080",
         "--database", var/"tenkai/tenkai.db", "--require-executor"]
    environment_variables TENKAI_MANAGEMENT_TOKEN_FILE: var/"tenkai/management.token"
    working_dir var/"tenkai"
    keep_alive true
    log_path var/"log/tenkai-server.log"
    error_log_path var/"log/tenkai-server.log"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/tenkaictl --version")
    assert_match "--require-executor", shell_output("#{{bin}}/tenkai-server --help")
    assert_path_exists bin/"tenkai-executor-guard"
  end
end
"""


def main(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    notes = commands.add_parser("notes")
    notes.add_argument("version")
    gates = commands.add_parser("gate-flags")
    gates.add_argument("version")
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
    manifest.add_argument("--allow-missing-gate-flags", action="store_true")
    brew = commands.add_parser("formula")
    brew.add_argument("--version", required=True)
    brew.add_argument("--dist", required=True, type=Path)
    brew.add_argument("--out", required=True, type=Path)
    brew.add_argument("--base-url")
    args = parser.parse_args(argv)

    if args.command == "notes":
        print(changelog_section((ROOT / "CHANGELOG.md").read_text(), args.version))
    elif args.command == "gate-flags":
        section = changelog_section((ROOT / "CHANGELOG.md").read_text(), args.version)
        print(", ".join(gate_flags(section)) or "none")
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
            flags=gate_flags(section, required=not args.allow_missing_gate_flags),
        )
        args.out.write_text(json.dumps(document, indent=2) + "\n")
    elif args.command == "formula":
        sums = checksums(args.dist / "SHA256SUMS")
        args.out.write_text(formula(args.version, sums, args.base_url))


if __name__ == "__main__":
    main(sys.argv[1:])

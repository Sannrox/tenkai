#!/usr/bin/env python3
"""Deterministic Apple `container` CLI stand-in for Tenkai host-executor tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "system":
        return handle_system(args[1:])
    state_path = Path(os.environ["TENKAI_DOCKER_FAKE_STATE"])
    state_path.parent.mkdir(parents=True, exist_ok=True)
    argv_log = state_path.parent / "argv.log"
    with argv_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")
    forbidden = os.environ.get("TENKAI_DOCKER_FAKE_FORBID", "")
    joined = " ".join(sys.argv[1:])
    if forbidden and forbidden in joined:
        sys.stderr.write("secret material leaked onto container argv\n")
        return 2
    state = {"containers": {}, "networks": {}, "volumes": {}, "images": []}
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state.setdefault("images", [])
    if not args:
        sys.stderr.write("missing container command\n")
        return 1
    command = args[0]
    rest = args[1:]
    if command == "network":
        return handle_network(state, state_path, rest)
    if command == "volume":
        return handle_volume(state, state_path, rest)
    if command in {"run", "create"}:
        return handle_run(state, state_path, rest, command == "create")
    if command == "inspect":
        return handle_inspect(state, rest)
    if command in {"delete", "rm"}:
        return handle_delete(state, state_path, rest)
    if command in {"stop", "start"}:
        return handle_running(state, state_path, rest, command == "start")
    if command in {"list", "ls"}:
        return handle_list(state, rest)
    if command == "exec":
        return handle_exec(state, rest)
    if command == "image":
        return handle_image(state, state_path, rest)
    if command == "rename":
        sys.stderr.write("unsupported container command rename\n")
        return 1
    if command == "restart":
        sys.stderr.write("unsupported container command restart\n")
        return 1
    sys.stderr.write(f"unsupported container command {command}\n")
    return 1


def save(state_path: Path, state: dict) -> None:
    state_path.write_text(json.dumps(state), encoding="utf-8")


def take_flag(args: list[str], flag: str) -> list[str]:
    values = []
    i = 0
    while i < len(args):
        if args[i] == flag and i + 1 < len(args):
            values.append(args[i + 1])
            i += 2
            continue
        i += 1
    return values


def labeled_resources(state: dict, kind: str) -> dict:
    resources = state.get(kind, {})
    if isinstance(resources, list):
        converted = {name: {"labels": {}} for name in resources}
        state[kind] = converted
        return converted
    return resources


def handle_system(args: list[str]) -> int:
    if not args or args[0] != "status":
        sys.stderr.write("expected system status\n")
        return 1
    if os.environ.get("TENKAI_CONTAINER_FAKE_DOWN") == "1":
        sys.stderr.write("apiserver is not running\n")
        return 1
    sys.stdout.write('{"state":"running"}\n')
    return 0


def handle_network(state: dict, state_path: Path, args: list[str]) -> int:
    if not args:
        sys.stderr.write("expected network create, inspect, or delete\n")
        return 1
    if args[0] == "create":
        return create_labeled_resource(state, state_path, "networks", "network", args)
    if args[0] == "inspect":
        return inspect_labeled_resource(state, "networks", args)
    if args[0] in {"delete", "rm"}:
        name = args[-1]
        labeled_resources(state, "networks").pop(name, None)
        save(state_path, state)
        return 0
    sys.stderr.write("expected network create, inspect, or delete\n")
    return 1


def handle_volume(state: dict, state_path: Path, args: list[str]) -> int:
    if not args:
        sys.stderr.write("expected volume create or inspect\n")
        return 1
    if args[0] == "inspect":
        return inspect_labeled_resource(state, "volumes", args)
    if args[0] != "create":
        sys.stderr.write("expected volume create or inspect\n")
        return 1
    return create_labeled_resource(state, state_path, "volumes", "volume", args)


def inspect_labeled_resource(state: dict, kind: str, args: list[str]) -> int:
    names = [item for item in args[1:] if not item.startswith("-")]
    payload = []
    for name in names:
        resource = labeled_resources(state, kind).get(name)
        if resource is None:
            sys.stderr.write(f"Error: No such {kind[:-1]}: {name}\n")
            return 1
        payload.append(
            {
                "configuration": {"id": name, "labels": resource.get("labels", {})},
                "status": {"state": "available"},
            }
        )
    sys.stdout.write(json.dumps(payload))
    return 0


def create_labeled_resource(
    state: dict, state_path: Path, kind: str, noun: str, args: list[str]
) -> int:
    labels = {}
    for item in take_flag(args, "--label"):
        key, _, value = item.partition("=")
        labels[key] = value
    name = args[-1]
    resources = labeled_resources(state, kind)
    if name in resources:
        sys.stderr.write(f"{noun} with name {name} already exists\n")
        return 1
    resources[name] = {"labels": labels}
    save(state_path, state)
    return 0


def occupied_exact_names(state: dict) -> set[str]:
    occupied = set()
    for name, container in state["containers"].items():
        occupied.add(name)
        for aliases in container.get("networks", {}).values():
            occupied.update(aliases)
    return occupied


def parse_network_flag(value: str) -> tuple[str, list[str]]:
    parts = value.split(",")
    name = parts[0]
    aliases = []
    for part in parts[1:]:
        key, _, field = part.partition("=")
        if key == "alias" and field:
            aliases.append(field)
    return name, aliases


def handle_run(state: dict, state_path: Path, args: list[str], created: bool = False) -> int:
    names = take_flag(args, "--name")
    if len(names) != 1:
        sys.stderr.write("container run requires one --name\n")
        return 1
    name = names[0]
    if name in state["containers"]:
        sys.stderr.write(f"Error: container {name} already exists\n")
        return 1
    labels = {}
    for item in take_flag(args, "--label"):
        key, _, value = item.partition("=")
        labels[key] = value
    image = None
    command: list[str] = []
    skip = False
    flags_with_value = {
        "--name",
        "--label",
        "-l",
        "--network",
        "--publish",
        "-p",
        "--entrypoint",
        "--mount",
        "--env-file",
        "--user",
        "-u",
        "--tmpfs",
    }
    for index, item in enumerate(args):
        if image is not None:
            command.append(item)
            continue
        if skip:
            skip = False
            continue
        if item in flags_with_value:
            skip = True
            continue
        if item in {"-d", "--detach"}:
            continue
        if item.startswith("-"):
            sys.stderr.write(f"unsupported container run flag {item}\n")
            return 1
        image = item
    if not image:
        sys.stderr.write("container run requires an image digest\n")
        return 1
    mounts = []
    for value in take_flag(args, "--mount"):
        fields = {}
        for part in value.split(","):
            key, sep, field = part.partition("=")
            if sep:
                fields[key] = field
        if fields.get("type") == "volume" and (not fields.get("source") or not fields.get("target")):
            return 1
        mounts.append(
            {
                "type": fields.get("type", "volume"),
                "source": fields.get("source", ""),
                "target": fields.get("target", ""),
                "readonly": fields.get("readonly", "") != "" or "readonly" in value.split(","),
            }
        )
    for path in take_flag(args, "--tmpfs"):
        mounts.append({"type": "tmpfs", "source": "", "target": path})
    fail = {
        digest.strip()
        for digest in os.environ.get("TENKAI_DOCKER_FAKE_UNHEALTHY", "").split(",")
        if digest.strip()
    }
    healthy = image not in fail
    detached = "-d" in args or "--detach" in args
    job = labels.get("tenkai.job") == "true"
    running = not created and detached and not job
    networks = {}
    for value in take_flag(args, "--network"):
        network, aliases = parse_network_flag(value)
        networks[network] = aliases
    occupied = occupied_exact_names(state)
    for aliases in networks.values():
        for alias in aliases:
            if alias in occupied:
                sys.stderr.write(f"Error: alias {alias} already exists\n")
                return 1
    if (
        os.environ.get("TENKAI_DOCKER_FAKE_FAIL_ALIAS_CLAIM") == "1"
        and any(networks.values())
        and not name.endswith("-c")
    ):
        sys.stderr.write("Error: alias claim refused\n")
        return 1
    ports = take_flag(args, "--publish") + take_flag(args, "-p")
    volume_sources = {
        mount["source"]
        for mount in mounts
        if mount.get("type") == "volume" and mount.get("source") and not mount.get("readonly")
    }
    for other in state["containers"].values():
        if not other.get("running"):
            continue
        for port in ports:
            if port in other.get("ports", []):
                sys.stderr.write(f"Error: port {port} is already published\n")
                return 1
        for mount in other.get("mounts", []):
            if (
                mount.get("type") == "volume"
                and mount.get("source") in volume_sources
                and not mount.get("readonly")
            ):
                sys.stderr.write(
                    f"Error: volume {mount['source']} is already attached\n"
                )
                return 1
    state["containers"][name] = {
        "id": name,
        "image": image,
        "labels": labels,
        "running": running,
        "status": "created" if created else ("running" if running else "exited"),
        "exit_code": 0 if healthy else 1,
        "health": "healthy" if healthy else "unhealthy",
        "mounts": mounts,
        "ports": ports,
        "entrypoint": take_flag(args, "--entrypoint"),
        "command": command,
        "networks": networks,
        "tmpfs": take_flag(args, "--tmpfs"),
    }
    images = state.setdefault("images", [])
    if image not in images:
        images.append(image)
    save(state_path, state)
    sys.stdout.write(name + "\n")
    return 0


def handle_image(state: dict, state_path: Path, args: list[str]) -> int:
    if not args:
        sys.stderr.write("expected image inspect or pull\n")
        return 1
    if args[0] == "inspect":
        image = args[-1]
        if image in state.get("images", []):
            sys.stdout.write("[]\n")
            return 0
        sys.stderr.write(f"Error: Image not found: {image}\n")
        return 1
    if args[0] == "pull":
        image = args[-1]
        missing = {
            item
            for item in os.environ.get("TENKAI_DOCKER_FAKE_MISSING", "").split(",")
            if item
        }
        if image in missing:
            sys.stderr.write(f"Error: {image} does not exist\n")
            return 1
        images = state.setdefault("images", [])
        if image not in images:
            images.append(image)
        save(state_path, state)
        return 0
    sys.stderr.write("expected image inspect or pull\n")
    return 1


def apple_inspect(name: str, container: dict) -> dict:
    state = "running" if container.get("running") else container.get("status", "stopped")
    if state == "exited":
        state = "stopped"
    image = container.get("image", "")
    payload = {
        "configuration": {
            "id": name,
            "image": {
                "reference": image,
                "descriptor": {"digest": image, "mediaType": "application/vnd.oci.image.index.v1+json"},
            },
            "labels": container.get("labels", {}),
            "networks": [
                {
                    "network": network,
                    "options": {
                        "aliases": [
                            alias if "." in alias else f"{alias}.test" for alias in aliases
                        ]
                    },
                }
                for network, aliases in container.get("networks", {}).items()
            ],
        },
        "status": {
            "state": state,
        },
    }
    if "exit_code" in container:
        payload["status"]["exitCode"] = container["exit_code"]
    return payload


def handle_inspect(state: dict, args: list[str]) -> int:
    names = [item for item in args if not item.startswith("-")]
    payload = []
    for name in names:
        container = state["containers"].get(name)
        if container is not None:
            payload.append(apple_inspect(name, container))
            continue
        network = labeled_resources(state, "networks").get(name)
        if network is not None:
            payload.append({"configuration": {"id": name, "labels": network.get("labels", {})}, "status": {"state": "available"}})
            continue
        volume = labeled_resources(state, "volumes").get(name)
        if volume is not None:
            payload.append({"name": name, "labels": volume.get("labels", {})})
            continue
    sys.stdout.write(json.dumps(payload))
    return 0


def handle_delete(state: dict, state_path: Path, args: list[str]) -> int:
    tokens = [item for item in args if not item.startswith("-")]
    for token in tokens:
        state["containers"].pop(token, None)
    save(state_path, state)
    return 0


def handle_running(state: dict, state_path: Path, args: list[str], running: bool) -> int:
    names = [item for item in args if not item.startswith("-")]
    for name in names:
        if name not in state["containers"]:
            sys.stderr.write(f"Error: No such container: {name}\n")
            return 1
        container = state["containers"][name]
        job = container["labels"].get("tenkai.job") == "true"
        container["running"] = running and not job
        container["status"] = "exited" if job else ("running" if running else "stopped")
    save(state_path, state)
    return 0


def handle_list(state: dict, args: list[str]) -> int:
    if "--format" not in args or "json" not in args:
        for name in state["containers"]:
            sys.stdout.write(name + "\n")
        return 0
    payload = [
        apple_inspect(name, container)
        for name, container in state["containers"].items()
        if "--all" in args or "-a" in args or container.get("running")
    ]
    sys.stdout.write(json.dumps(payload))
    return 0


def handle_exec(state: dict, args: list[str]) -> int:
    names = [item for item in args if not item.startswith("-")]
    if not names:
        sys.stderr.write("container exec requires a container\n")
        return 1
    name = names[0]
    container = state["containers"].get(name)
    if container is None or not container.get("running"):
        sys.stderr.write(f"Error: container {name} is not running\n")
        return 1
    fail = {
        digest.strip()
        for digest in os.environ.get("TENKAI_DOCKER_FAKE_UNHEALTHY", "").split(",")
        if digest.strip()
    }
    if container.get("image") in fail or container.get("health") == "unhealthy":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

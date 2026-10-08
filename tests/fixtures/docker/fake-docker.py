#!/usr/bin/env python3
"""Deterministic docker CLI stand-in for Tenkai host-executor tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    state_path = Path(os.environ["TENKAI_DOCKER_FAKE_STATE"])
    state_path.parent.mkdir(parents=True, exist_ok=True)
    argv_log = state_path.parent / "argv.log"
    with argv_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")
    forbidden = os.environ.get("TENKAI_DOCKER_FAKE_FORBID", "")
    joined = " ".join(sys.argv[1:])
    if forbidden and forbidden in joined:
        sys.stderr.write("secret material leaked onto docker argv\n")
        return 2
    state = {"containers": {}, "networks": [], "volumes": []}
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("missing docker command\n")
        return 1
    command = args[0]
    rest = args[1:]
    if command == "network":
        return handle_network(state, state_path, rest)
    if command == "volume":
        return handle_volume(state, state_path, rest)
    if command == "run":
        return handle_run(state, state_path, rest)
    if command == "inspect":
        return handle_inspect(state, rest)
    if command == "rm":
        return handle_rm(state, state_path, rest)
    if command == "restart":
        return handle_restart(state, rest)
    if command == "ps":
        return handle_ps(state, rest)
    sys.stderr.write(f"unsupported docker command {command}\n")
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


def handle_network(state: dict, state_path: Path, args: list[str]) -> int:
    if not args or args[0] != "create":
        sys.stderr.write("expected network create\n")
        return 1
    name = args[-1]
    if name not in state["networks"]:
        state["networks"].append(name)
        save(state_path, state)
    return 0


def handle_volume(state: dict, state_path: Path, args: list[str]) -> int:
    if not args or args[0] != "create":
        sys.stderr.write("expected volume create\n")
        return 1
    name = args[-1]
    if name not in state["volumes"]:
        state["volumes"].append(name)
        save(state_path, state)
    return 0


def handle_run(state: dict, state_path: Path, args: list[str]) -> int:
    names = take_flag(args, "--name")
    if len(names) != 1:
        sys.stderr.write("docker run requires one --name\n")
        return 1
    name = names[0]
    labels = {}
    for item in take_flag(args, "--label"):
        key, _, value = item.partition("=")
        labels[key] = value
    image = None
    skip = False
    flags_with_value = {
        "--name",
        "--label",
        "--network",
        "--mount",
        "--env-file",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-timeout",
    }
    for index, item in enumerate(args):
        if skip:
            skip = False
            continue
        if item in flags_with_value or item.startswith("--health-"):
            skip = True
            continue
        if item in {"-d", "--detach"}:
            continue
        if item.startswith("-"):
            sys.stderr.write(f"unsupported docker run flag {item}\n")
            return 1
        image = item
    if not image:
        sys.stderr.write("docker run requires an image digest\n")
        return 1
    fail = {
        digest.strip()
        for digest in os.environ.get("TENKAI_DOCKER_FAKE_UNHEALTHY", "").split(",")
        if digest.strip()
    }
    healthy = image not in fail
    state["containers"][name] = {
        "image": image,
        "labels": labels,
        "running": True,
        "health": "healthy" if healthy else "unhealthy",
    }
    save(state_path, state)
    sys.stdout.write(name + "\n")
    return 0


def handle_inspect(state: dict, args: list[str]) -> int:
    names = [item for item in args if not item.startswith("-")]
    payload = []
    for name in names:
        container = state["containers"].get(name)
        if container is None:
            sys.stderr.write(f"Error: No such object: {name}\n")
            return 1
        payload.append(
            {
                "Name": f"/{name}",
                "Config": {
                    "Image": container["image"],
                    "Labels": container["labels"],
                },
                "State": {
                    "Running": container["running"],
                    "Health": {"Status": container["health"]},
                },
            }
        )
    sys.stdout.write(json.dumps(payload))
    return 0


def handle_rm(state: dict, state_path: Path, args: list[str]) -> int:
    names = [item for item in args if not item.startswith("-")]
    for name in names:
        state["containers"].pop(name, None)
    save(state_path, state)
    return 0


def handle_restart(state: dict, args: list[str]) -> int:
    names = [item for item in args if not item.startswith("-")]
    for name in names:
        if name not in state["containers"]:
            sys.stderr.write(f"Error: No such container: {name}\n")
            return 1
        state["containers"][name]["running"] = True
    return 0


def handle_ps(state: dict, args: list[str]) -> int:
    filters = take_flag(args, "--filter")
    wanted = {}
    for item in filters:
        key, _, value = item.partition("=")
        if key == "label":
            label_key, _, label_value = value.partition("=")
            wanted[label_key] = label_value
    for name, container in state["containers"].items():
        labels = container.get("labels", {})
        if all(labels.get(key) == value for key, value in wanted.items()):
            sys.stdout.write(name + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

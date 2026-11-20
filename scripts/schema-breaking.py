#!/usr/bin/env python3
"""Compare two JSON Schema documents for unmarked listed-surface breaks.

Additive properties, routes, enum values, and types pass. Removals and
narrowed types fail. HTTP contracts also compare `routes` by method+path.
"""

from __future__ import annotations

import json
import sys
from typing import Any

# Listed JSON contracts compared to the last final v* tag (#1086).
LISTED_SCHEMAS = (
    "api/tenkai-http-v1.schema.json",
    "api/tenkai-command-result-v1.schema.json",
)


def _types(node: dict) -> set[str] | None:
    value = node.get("type")
    if value is None:
        return None
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    if isinstance(value, str):
        return {value}
    return None


def _resolve(doc: Any, node: Any, stack: tuple[str, ...] = ()) -> Any:
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
        return node
    name = ref[len("#/$defs/") :]
    if "/" in name or name in stack:
        return node
    defs = doc.get("$defs") if isinstance(doc, dict) else None
    if not isinstance(defs, dict) or name not in defs:
        return node
    return _resolve(doc, defs[name], stack + (name,))


def _compare(
    old_doc: Any,
    new_doc: Any,
    old: Any,
    new: Any,
    path: str,
    findings: list[str],
    seen: set[tuple[int, int]],
) -> None:
    old = _resolve(old_doc, old)
    new = _resolve(new_doc, new)
    if not isinstance(old, dict) or not isinstance(new, dict):
        return
    key = (id(old), id(new))
    if key in seen:
        return
    seen.add(key)

    old_props = old.get("properties")
    new_props = new.get("properties") if isinstance(new.get("properties"), dict) else {}
    if isinstance(old_props, dict):
        for name, child in old_props.items():
            here = f"{path}/properties/{name}" if path else f"properties/{name}"
            if name not in new_props:
                findings.append(f"removed field {here}")
                continue
            _compare(old_doc, new_doc, child, new_props[name], here, findings, seen)

        old_required = {item for item in old.get("required", []) if isinstance(item, str)}
        new_required = {item for item in new.get("required", []) if isinstance(item, str)}
        for name in sorted(new_required - old_required):
            if name in old_props:
                here = f"{path}/properties/{name}" if path else f"properties/{name}"
                findings.append(f"newly required field {here}")

    old_enum = old.get("enum")
    new_enum = new.get("enum")
    if isinstance(old_enum, list) and isinstance(new_enum, list):
        missing = [value for value in old_enum if value not in new_enum]
        for value in missing:
            findings.append(f"removed enum value {value!r} at {path or '/'}")

    old_types = _types(old)
    new_types = _types(new)
    if old_types is not None and new_types is not None and not old_types <= new_types:
        findings.append(
            f"removed type {sorted(old_types - new_types)} at {path or '/'}"
        )

    old_const = old.get("const", _missing)
    new_const = new.get("const", _missing)
    if old_const is not _missing and new_const is not _missing and old_const != new_const:
        findings.append(f"changed const at {path or '/'}")

    if "items" in old and "items" in new:
        here = f"{path}/items" if path else "items"
        _compare(old_doc, new_doc, old["items"], new["items"], here, findings, seen)

    old_defs = old.get("$defs")
    new_defs = new.get("$defs") if isinstance(new.get("$defs"), dict) else {}
    if isinstance(old_defs, dict):
        for name, child in old_defs.items():
            if name in new_defs:
                here = f"{path}/$defs/{name}" if path else f"$defs/{name}"
                _compare(old_doc, new_doc, child, new_defs[name], here, findings, seen)

    old_routes = old.get("routes")
    if isinstance(old_routes, list):
        indexed: dict[tuple[str, str], list[Any]] = {}
        for route in old_routes:
            if not isinstance(route, dict):
                continue
            indexed.setdefault(_route_key(route), []).append(route)
        new_by_key: dict[tuple[str, str], list[Any]] = {}
        for route in new.get("routes", []) if isinstance(new.get("routes"), list) else []:
            if isinstance(route, dict):
                new_by_key.setdefault(_route_key(route), []).append(route)
        for key, routes in indexed.items():
            method, route_path = key
            if key not in new_by_key:
                findings.append(f"removed route {method} {route_path}")
                continue
            _compare(
                old_doc,
                new_doc,
                routes[0].get("request"),
                new_by_key[key][0].get("request"),
                f"routes/{method} {route_path}/request",
                findings,
                seen,
            )
            _compare(
                old_doc,
                new_doc,
                routes[0].get("response"),
                new_by_key[key][0].get("response"),
                f"routes/{method} {route_path}/response",
                findings,
                seen,
            )


_missing = object()


def _route_key(route: dict) -> tuple[str, str]:
    return (str(route.get("method", "")), str(route.get("path", "")))


def breaking_changes(old: Any, new: Any) -> list[str]:
    """Return human-readable breaks of `old` relative to `new`."""
    findings: list[str] = []
    _compare(old, new, old, new, "", findings, set())
    return findings


def _self_test() -> None:
    baseline = {
        "$defs": {
            "Item": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
                "required": ["id"],
            }
        },
        "routes": [
            {
                "method": "GET",
                "path": "/v1/items",
                "request": None,
                "response": {"$ref": "#/$defs/Item"},
            }
        ],
        "properties": {
            "schema": {"const": "v1", "type": "string"},
            "command": {"enum": ["plan", "apply"], "type": "string"},
        },
        "required": ["schema", "command"],
    }
    added = json.loads(json.dumps(baseline))
    added["$defs"]["Item"]["properties"]["extra"] = {"type": "integer"}
    added["routes"].append(
        {"method": "POST", "path": "/v1/items", "request": {"$ref": "#/$defs/Item"}}
    )
    added["properties"]["retry"] = {"type": "string"}
    added["properties"]["command"]["enum"].append("status")
    assert breaking_changes(baseline, added) == [], breaking_changes(baseline, added)

    removed_field = json.loads(json.dumps(baseline))
    del removed_field["$defs"]["Item"]["properties"]["name"]
    found = breaking_changes(baseline, removed_field)
    assert any("removed field" in item and "name" in item for item in found), found

    removed_route = json.loads(json.dumps(baseline))
    removed_route["routes"] = []
    found = breaking_changes(baseline, removed_route)
    assert any("removed route GET /v1/items" in item for item in found), found

    removed_enum = json.loads(json.dumps(baseline))
    removed_enum["properties"]["command"]["enum"] = ["plan"]
    found = breaking_changes(baseline, removed_enum)
    assert any("removed enum value 'apply'" in item for item in found), found

    required = json.loads(json.dumps(baseline))
    required["$defs"]["Item"]["required"] = ["id", "name"]
    found = breaking_changes(baseline, required)
    assert any("newly required field" in item and "name" in item for item in found), found

    new_required_field = json.loads(json.dumps(baseline))
    new_required_field["$defs"]["Item"]["properties"]["extra"] = {"type": "string"}
    new_required_field["$defs"]["Item"]["required"] = ["id", "extra"]
    assert breaking_changes(baseline, new_required_field) == []

    print("schema-breaking self-test ok")


def main(argv: list[str]) -> int:
    if argv == ["--listed"]:
        sys.stdout.write("\n".join(LISTED_SCHEMAS) + "\n")
        return 0
    if argv == ["--self-test"]:
        _self_test()
        return 0
    if len(argv) != 2:
        sys.stderr.write(
            "usage: schema-breaking.py <old.json> <new.json>\n"
            "       schema-breaking.py --listed\n"
            "       schema-breaking.py --self-test\n"
        )
        return 2
    with open(argv[0], encoding="utf-8") as old_file:
        old = json.load(old_file)
    with open(argv[1], encoding="utf-8") as new_file:
        new = json.load(new_file)
    findings = breaking_changes(old, new)
    if not findings:
        return 0
    for item in findings:
        sys.stdout.write(f"{item}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

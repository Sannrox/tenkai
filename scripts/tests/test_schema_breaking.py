"""Listed JSON Schema contracts: field removal fails, additive fields pass."""

import importlib.util
import json
import subprocess
import unittest

from scripts.tests.release import ROOT

SCHEMA_BREAKING = ROOT / "scripts" / "schema-breaking.py"


def load_comparer():
    spec = importlib.util.spec_from_file_location("schema_breaking", SCHEMA_BREAKING)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SchemaBreaking(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_comparer()

    def test_removing_a_listed_field_is_breaking(self):
        old = {
            "properties": {"schema": {"type": "string"}, "command": {"type": "string"}},
            "required": ["schema", "command"],
        }
        new = {"properties": {"schema": {"type": "string"}}, "required": ["schema"]}
        found = self.mod.breaking_changes(old, new)
        self.assertTrue(
            any("command" in item and "removed field" in item for item in found), found
        )

    def test_an_additive_field_passes(self):
        old = {"properties": {"schema": {"type": "string"}}, "required": ["schema"]}
        new = {
            "properties": {
                "schema": {"type": "string"},
                "retry": {"type": "string"},
            },
            "required": ["schema"],
        }
        self.assertEqual(self.mod.breaking_changes(old, new), [])

    def test_removing_an_http_route_is_breaking(self):
        old = {
            "routes": [
                {"method": "GET", "path": "/v1/status", "response": {"type": "object"}}
            ]
        }
        new = {"routes": []}
        found = self.mod.breaking_changes(old, new)
        self.assertIn("removed route GET /v1/status", found)

    def test_http_field_removal_follows_defs_refs(self):
        old = {
            "$defs": {
                "Status": {
                    "type": "object",
                    "properties": {
                        "state": {"type": "string"},
                        "age": {"type": "integer"},
                    },
                }
            },
            "routes": [
                {
                    "method": "GET",
                    "path": "/v1/status",
                    "response": {"$ref": "#/$defs/Status"},
                }
            ],
        }
        new = json.loads(json.dumps(old))
        del new["$defs"]["Status"]["properties"]["age"]
        found = self.mod.breaking_changes(old, new)
        self.assertTrue(
            any("age" in item and "removed field" in item for item in found), found
        )

    def test_listed_schema_files_exist(self):
        listed = subprocess.check_output(
            ["python3", str(SCHEMA_BREAKING), "--listed"], text=True
        ).split()
        self.assertTrue(listed)
        for path in listed:
            self.assertTrue(path.endswith(".schema.json"), path)
            self.assertTrue((ROOT / path).is_file(), path)


if __name__ == "__main__":
    unittest.main()

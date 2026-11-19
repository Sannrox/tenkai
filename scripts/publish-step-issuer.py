#!/usr/bin/env python3
"""Loopback OIDC issuer for the publish-release step's CI proof.

Serves discovery, its JWKS, and a client-credentials token endpoint that
issues ES256 access tokens for one client. The signing key is generated per
run with the openssl CLI and never leaves the run's directory. Test-only:
it has no other grant, no refresh, and no TLS.

Usage: publish-step-issuer.py <dir> <client-id> <client-secret> <group>
Writes <dir>/issuer-url once it listens and <dir>/jwks.json.
"""

import base64
import hmac
import json
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

AUDIENCE = "tenkai"
KID = "publish-step"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def der_integer(data: bytes, at: int) -> tuple[int, int]:
    if data[at] != 0x02:
        raise ValueError("not a DER integer")
    length = data[at + 1]
    start = at + 2
    return int.from_bytes(data[start : start + length], "big"), start + length


def raw_signature(der: bytes) -> bytes:
    # SEQUENCE { INTEGER r, INTEGER s } -> r || s, 32 bytes each.
    if der[0] != 0x30:
        raise ValueError("not a DER sequence")
    r, after = der_integer(der, 2)
    s, _ = der_integer(der, after)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class Issuer:
    def __init__(self, root: Path, client_id: str, secret: str, group: str):
        self.root = root
        self.client_id = client_id
        self.secret = secret
        self.group = group
        self.key = root / "issuer-key.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.key)],
            check=True,
        )
        self.key.chmod(0o600)
        spki = subprocess.run(
            ["openssl", "ec", "-in", str(self.key), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        point = spki[-65:]
        if point[0] != 0x04:
            raise ValueError("unexpected public key encoding")
        self.jwks = {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "use": "sig",
                    "alg": "ES256",
                    "kid": KID,
                    "x": b64(point[1:33]),
                    "y": b64(point[33:65]),
                }
            ]
        }
        self.url = ""

    def token(self) -> str:
        now = int(time.time())
        header = {"alg": "ES256", "typ": "JWT", "kid": KID}
        claims = {
            "iss": self.url,
            "aud": AUDIENCE,
            "sub": self.client_id,
            "groups": [self.group],
            "iat": now,
            "exp": now + 300,
        }
        signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
        der = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key)],
            input=signing_input.encode(),
            check=True,
            capture_output=True,
        ).stdout
        return f"{signing_input}.{b64(raw_signature(der))}"


def handler(issuer: Issuer):
    class Handler(BaseHTTPRequestHandler):
        def send_json(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/.well-known/openid-configuration":
                self.send_json(
                    200,
                    {
                        "issuer": issuer.url,
                        "authorization_endpoint": f"{issuer.url}/authorize",
                        "token_endpoint": f"{issuer.url}/token",
                        "jwks_uri": f"{issuer.url}/jwks",
                        "grant_types_supported": ["client_credentials"],
                    },
                )
            elif self.path == "/jwks":
                self.send_json(200, issuer.jwks)
            else:
                self.send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/token":
                self.send_json(404, {"error": "not_found"})
                return
            length = int(self.headers.get("content-length", "0"))
            form = urllib.parse.parse_qs(self.rfile.read(length).decode())
            field = lambda name: (form.get(name) or [""])[0]
            if field("grant_type") != "client_credentials":
                self.send_json(400, {"error": "unsupported_grant_type"})
            elif field("client_id") != issuer.client_id or not hmac.compare_digest(
                field("client_secret"), issuer.secret
            ):
                self.send_json(401, {"error": "invalid_client"})
            else:
                self.send_json(
                    200,
                    {"access_token": issuer.token(), "token_type": "Bearer", "expires_in": 300},
                )

        def log_message(self, format: str, *args) -> None:
            sys.stderr.write(f"issuer: {self.command} {self.path.split('?')[0]}\n")

    return Handler


def main() -> None:
    root, client_id, secret, group = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    issuer = Issuer(root, client_id, secret, group)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(issuer))
    issuer.url = f"http://127.0.0.1:{server.server_address[1]}"
    (root / "jwks.json").write_text(json.dumps(issuer.jwks))
    (root / "issuer-url").write_text(issuer.url)
    server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# Seed-registry rehearsal (#627) with Docker. A fresh Docker daemon with no
# images and no route out pulls an image by digest from
# `tenkaictl registry serve`, trusting only the site CA; a second pull
# changes nothing, and a tag or origin pull fails.
#
# The bundle-to-store half (verify, image closure, import under the seed
# name, rerun) is covered by the Rust tests; this drives the real client.
# Requires: docker with privileged containers (Docker-in-Docker), openssl,
# python3. The build step fetches crates; the rehearsal network has no
# route out.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="tenkai-seed-$$"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tenkai-seed-rehearsal.XXXXXX")"
HOST="seed.registry"
NAME="$HOST:5443"
RUST_IMAGE="rust:1.96.1-bookworm"
DIND_IMAGE="docker:28-dind"
TARGET_VOLUME="tenkai-seed-target-$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$ROOT")"

cleanup() {
  docker rm -f "$RUN-registry" "$RUN-host" >/dev/null 2>&1 || true
  docker network rm "$RUN" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

step "build tenkaictl for Linux"
docker run --rm -v "$ROOT:/src:ro" -v "$TARGET_VOLUME:/target" \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -w /src "$RUST_IMAGE" \
  cargo build --locked --bin tenkaictl
docker run --rm -v "$TARGET_VOLUME:/target:ro" -v "$WORK:/out" "$RUST_IMAGE" \
  cp /target/debug/tenkaictl /out/tenkaictl

step "site CA and a certificate for $HOST"
mkdir -p "$WORK/tls"
cat > "$WORK/tls/ca.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = tenkai-seed-rehearsal-ca
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
CNF
printf 'subjectAltName = DNS:%s\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\n' \
  "$HOST" > "$WORK/tls/server.ext"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -config "$WORK/tls/ca.cnf" \
  -extensions v3_ca -keyout "$WORK/tls/ca.key" -out "$WORK/tls/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -config "$WORK/tls/ca.cnf" -subj "/CN=$HOST" \
  -keyout "$WORK/tls/server.key" -out "$WORK/tls/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$WORK/tls/server.csr" -CA "$WORK/tls/ca.crt" \
  -CAkey "$WORK/tls/ca.key" -CAcreateserial -extfile "$WORK/tls/server.ext" \
  -out "$WORK/tls/server.crt" >/dev/null 2>&1
chmod 644 "$WORK/tls/server.key"

step "an image in the store, laid out as an import writes it"
case "$(docker info --format '{{.Architecture}}')" in
  aarch64 | arm64) ARCH=arm64 ;;
  *) ARCH=amd64 ;;
esac
MANIFEST="$(python3 - "$WORK/store/$NAME/edge/app" "$ARCH" <<'PY'
import hashlib, io, json, os, sys, tarfile
out, arch = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
def put(data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    with open(os.path.join(out, digest.replace(":", "-")), "wb") as f:
        f.write(data)
    return digest
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
    body = b"seeded from a signed bundle\n"
    info = tarfile.TarInfo("seed.txt")
    info.size, info.mtime = len(body), 0
    tar.addfile(info, io.BytesIO(body))
layer = buf.getvalue()
layer_digest = put(layer)
config = json.dumps({
    "architecture": arch, "os": "linux", "config": {},
    "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
}).encode()
config_digest = put(config)
manifest = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
               "digest": config_digest, "size": len(config)},
    "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": layer_digest, "size": len(layer)}],
}).encode()
print(put(manifest))
PY
)"
echo "manifest $MANIFEST"

step "isolated network: the registry and an empty Docker host, no route out"
docker network create --internal "$RUN" >/dev/null
docker run -d --name "$RUN-registry" --network "$RUN" --network-alias "$HOST" \
  -v "$WORK:/work:ro" "$RUST_IMAGE" /work/tenkaictl registry serve \
  --store /work/store --name "$NAME" --listen 0.0.0.0:5443 \
  --tls-cert /work/tls/server.crt --tls-key /work/tls/server.key >/dev/null
docker run -d --privileged --name "$RUN-host" --network "$RUN" -e DOCKER_TLS_CERTDIR= \
  --mount "type=bind,src=$WORK/tls/ca.crt,dst=/etc/docker/certs.d/$NAME/ca.crt,readonly" \
  "$DIND_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$RUN-host" docker info >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$RUN-host" docker info >/dev/null 2>&1 || fail "Docker host did not start"
[ -z "$(docker exec "$RUN-host" docker image ls -q)" ] || fail "Docker host is not empty"

step "pull by digest from the seed registry"
REF="$NAME/edge/app@$MANIFEST"
docker exec "$RUN-host" docker pull "$REF"
DIGESTS="$(docker exec "$RUN-host" docker image inspect --format '{{json .RepoDigests}}' "$REF")"
case "$DIGESTS" in
  *"$REF"*) echo "digest matches: $DIGESTS" ;;
  *) fail "pulled image digests $DIGESTS do not include $REF" ;;
esac

step "a second pull changes nothing"
AGAIN="$(docker exec "$RUN-host" docker pull "$REF")"
case "$AGAIN" in
  *"Image is up to date"*) echo "$AGAIN" ;;
  *) fail "second pull was not a no-op: $AGAIN" ;;
esac

step "tags and origin pulls are refused"
if docker exec "$RUN-host" docker pull "$NAME/edge/app:latest" >/dev/null 2>&1; then
  fail "a tag was served"
fi
if docker exec "$RUN-host" docker pull alpine >/dev/null 2>&1; then
  fail "the Docker host reached an origin registry"
fi
echo "seed registry rehearsal passed"

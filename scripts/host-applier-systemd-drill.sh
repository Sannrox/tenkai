#!/usr/bin/env bash
# Linux proof for the root-side host applier (ADR 0041 §2): installs the
# applier, the template unit, and the polkit rule on a throwaway systemd host,
# then drives them as an unprivileged `tenkai` user. Needs root (via sudo),
# systemd as PID 1, and polkit. Never run it on a host you care about.
#
# Usage: scripts/host-applier-systemd-drill.sh <tenkai-host-applier> <host_apply_drill>
set -euo pipefail

applier=${1:?path to the tenkai-host-applier binary}
fixture=${2:?path to the host_apply_drill example binary}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
spool=/var/lib/tenkai/host-spool
evidence=/var/lib/tenkai-host-drill
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "host applier drill: $*" >&2
  exit 1
}

as_tenkai() {
  sudo -u tenkai -- "$@"
}

result_field() {
  # result_field <instance> <field>
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
    "/var/lib/tenkai-host/instances/$1/result.json" "$2"
}

"$fixture" "$work" "$spool" "$evidence"
# shellcheck disable=SC1091
. "$work/instances.env"

id tenkai >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir /var/lib/tenkai tenkai
sudo install -o root -g root -m 0755 -D "$applier" /usr/local/libexec/tenkai/tenkai-host-applier
sudo install -o root -g root -m 0755 -d /etc/tenkai
sudo install -o root -g root -m 0644 "$work"/etc/* /etc/tenkai/
sudo install -o tenkai -g tenkai -m 0750 -d "$spool"
sudo cp -R "$work/spool/." "$spool/"
sudo chown -R tenkai:tenkai "$spool"
sudo install -o root -g root -m 0644 "$root/examples/host-applier-systemd/tenkai-host-apply@.service" /etc/systemd/system/
sudo install -o root -g root -m 0755 -d /etc/polkit-1/rules.d
sudo install -o root -g root -m 0644 "$root/examples/host-applier-systemd/tenkai-host-apply.rules" \
  /etc/polkit-1/rules.d/50-tenkai-host-apply.rules
# A unit the tenkai user must not be able to start.
printf '[Service]\nType=oneshot\nExecStart=/bin/true\n' |
  sudo tee /etc/systemd/system/tenkai-drill-other.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart polkit

echo "== install runs as root under the unit, started by tenkai"
as_tenkai systemctl start "tenkai-host-apply@$INSTALL.service"
[ "$(result_field "$INSTALL" outcome)" = succeeded ] || fail "install did not succeed"
[ "$(sudo cat "$evidence/uid")" = 0 ] || fail "the command did not run as root"
# CAP_SETUID survives into the command: it may switch to another user.
[ "$(sudo cat "$evidence/dropped-uid")" = 65534 ] || fail "the command could not switch to another user"
[ "$(sudo cat "$evidence/payload")" = "host release payload" ] || fail "payload differs"
if sudo grep -Eq '^(INVOCATION_ID|JOURNAL_STREAM|SYSTEMD_EXEC_PID|LD_PRELOAD)=' "$evidence/env"; then
  fail "the command saw the unit's environment"
fi
[ ! -e "/run/tenkai-host/work/$INSTALL" ] || fail "the root-owned copy was left behind"
sudo -u tenkai test -r "/var/lib/tenkai-host/instances/$INSTALL/result.json" ||
  fail "tenkai cannot read the result"
if sudo -u tenkai test -w "/var/lib/tenkai-host/instances/$INSTALL/result.json"; then
  fail "tenkai can write the result"
fi

echo "== a replayed instance returns its result and runs nothing"
as_tenkai systemctl start "tenkai-host-apply@$INSTALL.service"
[ "$(sudo cat "$evidence/runs")" = run ] || fail "the install ran twice"

echo "== polkit allows start and stop of the template only"
if as_tenkai systemctl restart "tenkai-host-apply@$INSTALL.service" 2>/dev/null; then
  fail "tenkai may restart the unit"
fi
if as_tenkai systemctl start tenkai-drill-other.service 2>/dev/null; then
  fail "tenkai may start another unit"
fi
if as_tenkai systemctl start "tenkai-host-apply@not-an-instance.service" 2>/dev/null; then
  fail "tenkai may start an instance that is not an instance key"
fi
if as_tenkai systemctl daemon-reload 2>/dev/null; then
  fail "tenkai may reload systemd"
fi

echo "== stop kills the command's process group"
as_tenkai systemctl start --no-block "tenkai-host-apply@$SLOW.service"
for _ in $(seq 1 100); do
  sudo test -s "$evidence/child" && break
  sleep 0.2
done
child=$(sudo cat "$evidence/child")
as_tenkai systemctl stop "tenkai-host-apply@$SLOW.service"
[ "$(result_field "$SLOW" outcome)" = stopped ] || fail "the stopped step was not recorded as stopped"
if sudo kill -0 "$child" 2>/dev/null; then
  fail "the command's child outlived the stop"
fi

echo "== a crashed applier: the step resolves as interrupted once nothing of it runs"
as_tenkai systemctl start --no-block "tenkai-host-apply@$CRASH.service"
for _ in $(seq 1 100); do
  sudo test -s "$evidence/crash-child" && break
  sleep 0.2
done
crash_child=$(sudo cat "$evidence/crash-child")
sudo systemctl kill --kill-whom=main --signal=SIGKILL "tenkai-host-apply@$CRASH.service"
for _ in $(seq 1 100); do
  systemctl is-active --quiet "tenkai-host-apply@$CRASH.service" || break
  sleep 0.2
done
if sudo kill -0 "$crash_child" 2>/dev/null; then
  fail "the crashed step's child outlived its unit"
fi
sudo test ! -e "/var/lib/tenkai-host/instances/$CRASH/result.json" || fail "a crash wrote a result"
as_tenkai systemctl start "tenkai-host-apply@$CRASH.service" 2>/dev/null || true
[ "$(result_field "$CRASH" outcome)" = interrupted ] || fail "the crashed step did not resolve as interrupted"

echo "host applier drill passed"

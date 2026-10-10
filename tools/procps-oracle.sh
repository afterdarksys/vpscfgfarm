#!/bin/bash
# procps-oracle.sh — what real procps does with each `ps` form the door may
# see. OPT-IN, local only: needs Docker, pulls two Debian images, never
# touches a fleet host.
#
# Every process in the container carries CANARY=leak123 in its environment
# and a tty is allocated; a form whose output contains the canary printed an
# environment. procps reparses the whole argv as BSD after any UNIX parse
# failure, so this is the only reliable way to know (`ps -ef -o args` once
# leaked on both images and was a door read).
#
#   tools/procps-oracle.sh [FORMS] [OUTDIR]
#     FORMS   one ps argument string per line (shell-quoted, without `ps`)
#             default tests/data/procps_oracle/forms.txt
#     OUTDIR  default tests/data/procps_oracle
#   writes OUTDIR/buster.out (procps-ng 3.3.15, Debian 10: the compatibility floor) and
#   OUTDIR/bookworm.out (procps-ng 4.0.2), lines `VERDICT  ps FORM` with
#   VERDICT LEAK | ok | err(N).
#
# tests/test_door_device_reads.py (ProcpsOracleTest) pins the recorded
# verdicts: every LEAK form must be REFUSED by the door, and a door read must
# be `ok` on both images. Re-run after changing readpolicy's ps grammar and
# commit the outputs.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
forms="${1:-$here/tests/data/procps_oracle/forms.txt}"
out="${2:-$here/tests/data/procps_oracle}"
[ -f "$forms" ] || { echo "no forms file: $forms" >&2; exit 2; }
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$forms" "$work/forms.txt"
cat > "$work/run.sh" <<'EOF'
#!/bin/bash
sleep 1000 &
sleep 0.5
ps --version 2>&1 | head -1
while IFS= read -r f; do
  [ -z "$f" ] && continue
  out=$(eval "ps $f" 2>&1); rc=$?
  if grep -q leak123 <<<"$out"; then v=LEAK; elif [ $rc -ne 0 ]; then v="err($rc)"; else v=ok; fi
  printf '%-8s ps %s\n' "$v" "$f"
done < /t/forms.txt
EOF
chmod +x "$work/run.sh"

docker run --rm -t -e CANARY=leak123 -v "$work:/t" debian:buster bash -c '
  printf "deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n" > /etc/apt/sources.list
  apt-get -o Acquire::Check-Valid-Until=false update -qq >/dev/null 2>&1
  apt-get install -y -qq procps >/dev/null 2>&1
  /t/run.sh' | tr -d '\r' > "$out/buster.out"

docker run --rm -t -e CANARY=leak123 -v "$work:/t" debian:bookworm bash -c '
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq procps >/dev/null 2>&1
  /t/run.sh' | tr -d '\r' > "$out/bookworm.out"

for f in buster bookworm; do
  printf '%-9s %s: %s LEAK, %s ok, %s err\n' "$f" "$(head -1 "$out/$f.out")" \
    "$(grep -c '^LEAK' "$out/$f.out" || true)" "$(grep -c '^ok' "$out/$f.out" || true)" \
    "$(grep -c '^err' "$out/$f.out" || true)"
done

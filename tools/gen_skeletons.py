#!/usr/bin/env python3
"""Generate contract SKELETONS from inventory probe files — a stub per observed
container, frozen, full of TODOs. Coverage first; precision comes from humans.

Reads <estate>/inventory/*-deep.txt ("== containers ==" sections) and writes
<estate>/contracts/skeletons/. The estate root is the one every door uses
(vpscfg/estate.py: this checkout, or the directory its estate.path names).
Coverage tracks whatever deep probes exist — the summary line names the hosts
covered.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import estate  # noqa: E402

ROOT = estate.root()
OUT = ROOT / "contracts" / "skeletons"

TEMPLATE = """# SKELETON — generated from inventory probe %(date)s. FILL IN AND MOVE UP
# to contracts/ when real. Everything here is a guess except host + name.
service: %(name)s
host: %(host)s
repo: TODO-local-git-checkout-path
deploy_dir: /opt/%(name)s   # TODO verify — guessed from container name
freeze: true                # stays frozen until a human owns this contract
image: %(image)s

sync:
  include: []               # TODO
  never:
    - .env.production       # until proven otherwise, assume host env is load-bearing

build: "docker compose up -d --build --force-recreate"   # TODO verify

verify:
  - container: { name: "%(name)s", state: "running" }
  # TODO add an http check — a contract with no http verify can't catch a
  # crashlooping backend from the outside

blast_radius:
  shares_host_with: "TODO"
  volumes: []               # TODO — run docker inspect and LIST them
"""

def parse_deep(path):
    host = path.name.replace("-deep.txt", "")
    out = []
    in_containers = False
    for line in path.read_text().splitlines():
        if line.startswith("== "):
            in_containers = line.strip() == "== containers =="
            continue
        if in_containers and "\t" in line:
            name, image = line.split("\t")[:2]
            if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", name):
                out.append((host, name, image))
    return out

def main():
    import time
    date = time.strftime("%Y-%m-%d")
    made, skipped = 0, 0
    for deep in sorted((ROOT / "inventory").glob("*-deep.txt")):
        for host, name, image in parse_deep(deep):
            target = OUT / ("%s--%s.yaml" % (host, name))
            if target.exists():
                skipped += 1
                continue
            target.write_text(TEMPLATE % {"date": date, "name": name,
                                          "host": host, "image": image})
            made += 1
    print("skeletons: %d written, %d already existed -> %s" % (made, skipped, OUT))
    covered = sorted(p.name.replace("-deep.txt", "")
                     for p in (ROOT / "inventory").glob("*-deep.txt"))
    print("hosts covered by deep probes: %s" % ", ".join(covered))
    return 0

if __name__ == "__main__":
    sys.exit(main())

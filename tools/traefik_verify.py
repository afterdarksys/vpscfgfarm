#!/usr/bin/env python3
"""Fetch the Traefik file provider the governor names (read-only) and print
suggested http verify entries per backend container. With --apply, inject the
first suggestion into each MATCHING skeleton of that host that still carries
the generated TODO-http comment (real contracts in contracts/ are never
touched — those are reviewed by hand).

The host and file come from the governor (integrations.traefik, see
vpscfg/integrations.py); with none named the mapping is skipped. Skeletons
are read from the estate root (vpscfg/estate.py).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vpscfg import estate, integrations, probe, traefikmap  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

TODO_MARKER = "  # TODO add an http check"


def main(argv):
    apply_mode = "--apply" in argv
    try:
        cfg = integrations.traefik()
        if cfg is None:
            print("traefik mapping skipped: no file provider configured — name one in "
                  "the governor (integrations.traefik.host and .file)")
            return 0
        host = cfg["host"]
        result = probe.run(host, "traefik")
    except Refused as r:
        print("REFUSED: %s" % r, file=sys.stderr)
        return 2
    if result["rc"] != 0 or "NO_TRAEFIK_FILE" in result["stdout"]:
        print("could not fetch traefik file provider:", result["stderr"] or result["stdout"])
        return 1
    routes = traefikmap.parse(result["stdout"])
    sugg = traefikmap.suggestions(routes)
    print("traefik: %d routers -> %d backend containers with suggestions" % (len(routes), len(sugg)))
    skeletons = estate.root() / "contracts" / "skeletons"
    applied = 0
    for name, entries in sorted(sugg.items()):
        print("%s:" % name)
        for e in entries:
            h = e["http"]
            print("  - http: { url: \"%s\", expect: %d }" % (h["url"], h["expect"]))
        skel = skeletons / ("%s--%s.yaml" % (host, name))
        if apply_mode and skel.exists():
            text = skel.read_text()
            if TODO_MARKER in text:
                h = entries[0]["http"]
                line = "  - http: { url: \"%s\", expect: %d }   # from traefik file provider\n" % (h["url"], h["expect"])
                text = text.replace(TODO_MARKER, line.rstrip("\n") + "\n" + TODO_MARKER, 1)
                skel.write_text(text)
                applied += 1
    if apply_mode:
        print("applied to %d skeleton(s) (TODO marker kept — a human still owns promotion)" % applied)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

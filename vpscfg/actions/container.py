"""Container actions: wait_healthy (P0's read-only reference action), recreate
and tag_image.

wait_healthy {container | url, tries, interval}
    A read. Its body is one probe that must classify as a read under the door's
    own classifier (the door checks this at plan time): `docker inspect` of the
    container's health status, or `curl -qfsS` on a 127.0.0.1 URL. The door
    retries the body up to `tries` times, `interval` seconds apart, inside the
    runbook verify_retry bounds (30 tries, 60 s, 600 s in all), and the step
    passes on the first success. A container without a healthcheck never
    reports `healthy`: use the url form for it.

recreate {container, project, service, working_dir, config_files, healthy,
          tries, interval}
    A mutation, NOT idempotent (a recreate is the point; there is no done-check).
    The compose project, service, working directory and files are typed
    parameters pinned in the committed policy, never read from the host, the
    index or free text (S11). The action also emits them as assumes
    (compose_labels with the four com.docker.compose.* labels, compose_files),
    so preflight proves the live container was started from exactly them. The
    body re-checks the same four labels on the host and refuses (exit 3, nothing
    recreated) on any difference, then runs `docker compose -p .. --project-directory
    .. -f .. up -d --no-deps --force-recreate --pull never <service>`: the image
    is unchanged by definition. Verify: the container is running (or, with
    `healthy: true`, reports healthy), retried `tries` x `interval`.

tag_image {image_ref, new_tag}
    A mutation, idempotent. `new_tag` is a full reference (`repo:tag`, no
    digest) and `image_ref` must name a tag or a digest. Body: `docker image tag`.
    Check (a read): the source image's RepoTags already lists `new_tag`, i.e.
    the tag points at the same image ID. Write references in the short form
    docker prints (`postgres:16`, not `docker.io/library/postgres:16`); a long
    form never matches, so the check says NEEDED and the tag is re-applied,
    which is harmless.
"""

from . import types
from .base import Action, Param, register, sq
from .types import ParamError


@register
class WaitHealthy(Action):
    name = "wait_healthy"
    version = 1
    tier = "read"
    why = "wait until a container reports healthy, or a local URL answers 2xx/3xx"
    params = {
        "container": Param(types.CONTAINER, required=False),
        "url": Param(types.LOCAL_URL, required=False),
        "tries": Param(types.int_range(1, 30), required=False, default=10),
        "interval": Param(types.int_range(1, 60), required=False, default=3),
    }
    samples = (
        {"container": "shop-web", "tries": 20, "interval": 3},
        {"url": "http://127.0.0.1:8080/healthz"},
    )

    def build(self, p, host):
        if ("container" in p) == ("url" in p):
            raise ParamError("wait_healthy takes exactly one of container or url")
        if p["tries"] * p["interval"] > 600:
            raise ParamError("tries x interval is %ds; the cap is 600s"
                             % (p["tries"] * p["interval"]))
        if "container" in p:
            body = ("docker inspect --format '{{.State.Health.Status}}' %s | grep -qx healthy"
                    % sq(p["container"]))
            assumes = ({"container": p["container"]},)
        else:
            body = "curl -qfsS --max-time 5 %s" % sq(p["url"])
            assumes = ()
        return {"body": body, "verify_retry": (p["tries"], p["interval"]),
                "assumes": assumes}


# The compose labels recreate pins, in the order its body compares them.
COMPOSE_LABELS = ("com.docker.compose.project", "com.docker.compose.service",
                  "com.docker.compose.project.working_dir",
                  "com.docker.compose.project.config_files")


@register
class Recreate(Action):
    name = "recreate"
    version = 1
    tier = "mutation"
    why = "recreate one compose service's container from its pinned project and files"
    params = {
        "container": Param(types.CONTAINER),
        "project": Param(types.BASENAME),
        "service": Param(types.BASENAME),
        "working_dir": Param(types.ABS_PATH),
        "config_files": Param(types.list_of(types.ABS_PATH, 4)),
        "healthy": Param(types.FLAG, required=False, default=False),
        "tries": Param(types.int_range(1, 30), required=False, default=20),
        "interval": Param(types.int_range(1, 60), required=False, default=3),
    }
    samples = (
        {"container": "shop-web-1", "project": "shopstack", "service": "frontend",
         "working_dir": "/opt/shop", "config_files": ["/srv/compose/shop.yml"]},
        {"container": "shop-api-1", "project": "shopstack", "service": "backend",
         "working_dir": "/opt/shop",
         "config_files": ["/srv/compose/base.yml", "/srv/compose/prod.yml"],
         "healthy": True, "tries": 30, "interval": 5},
    )

    def build(self, p, host):
        if p["tries"] * p["interval"] > 600:
            raise ParamError("tries x interval is %ds; the cap is 600s"
                             % (p["tries"] * p["interval"]))
        files = p["config_files"]
        template = "|".join('{{index .Config.Labels "%s"}}' % k for k in COMPOSE_LABELS)
        lines = ["set -eu",
                 "c=%s" % sq(p["container"]),
                 "project=%s" % sq(p["project"]),
                 "service=%s" % sq(p["service"]),
                 "workdir=%s" % sq(p["working_dir"])]
        lines += ["f%d=%s" % (n, sq(f)) for n, f in enumerate(files, 1)]
        lines += [
            'files="%s"' % ",".join("$f%d" % n for n in range(1, len(files) + 1)),
            "# The four compose labels must equal the pinned values, or nothing is recreated.",
            "have=$(docker inspect --format '%s' \"$c\")" % template,
            'if [ "$have" != "$project|$service|$workdir|$files" ]; then',
            '  echo "recreate: $c was not started from the pinned compose project, service,'
            ' directory and files (found: $have); not recreated" >&2',
            "  exit 3",
            "fi",
            'docker compose -p "$project" --project-directory "$workdir" %s up -d --no-deps '
            '--force-recreate --pull never "$service"'
            % " ".join('-f "$f%d"' % n for n in range(1, len(files) + 1)),
        ]
        if p["healthy"]:
            verify = ("docker inspect --format '{{.State.Health.Status}}' %s | grep -qx healthy"
                      % sq(p["container"]))
        else:
            verify = ("docker inspect --format '{{.State.Running}}' %s | grep -qx true"
                      % sq(p["container"]))
        labels = dict(zip(COMPOSE_LABELS, (p["project"], p["service"], p["working_dir"],
                                           ",".join(files))))
        return {"body": "\n".join(lines), "verify": verify,
                "verify_retry": (p["tries"], p["interval"]),
                "assumes": ({"container": p["container"], "compose_labels": labels,
                             "compose_files": list(files)},),
                "timeout": 300, "idempotent": False}


def _names_tag(ref):
    """True when an image reference names a tag (`repo:tag`, a registry
    port is not a tag)."""
    return ":" in ref.split("@", 1)[0].rsplit("/", 1)[-1]


@register
class TagImage(Action):
    name = "tag_image"
    version = 1
    tier = "mutation"
    why = "point a tag at an image already on the host"
    params = {
        "image_ref": Param(types.IMAGE_REF),
        "new_tag": Param(types.IMAGE_REF),
    }
    samples = (
        {"image_ref": "shop/web:1.5", "new_tag": "shop/web:rollback"},
        {"image_ref": "registry.example.com:5000/shop/web@sha256:" + "a" * 64,
         "new_tag": "registry.example.com:5000/shop/web:1.5"},
    )
    REPO_TAGS = "'{{range .RepoTags}}{{println .}}{{end}}'"

    def build(self, p, host):
        src, new = p["image_ref"], p["new_tag"]
        if "@" in new or not _names_tag(new):
            raise ParamError("new_tag must be a full reference with a tag (repo:tag), "
                             "no digest: %r" % new)
        if "@" not in src and not _names_tag(src):
            raise ParamError("image_ref must name a tag or a digest, not a bare "
                             "repository: %r" % src)
        if src == new:
            raise ParamError("image_ref and new_tag are the same reference")
        points = ("docker inspect --format %s %s | grep -qxF %s"
                  % (self.REPO_TAGS, sq(src), sq(new)))
        return {"body": "docker image tag %s %s" % (sq(src), sq(new)),
                "check": points + " && echo VPSCFG-DONE || echo VPSCFG-NEEDED",
                "verify": points, "timeout": 60, "idempotent": True}

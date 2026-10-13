"""P2: index-backed preflight (docs/PREFLIGHT.md "Index-backed preflight"),
the new `assumes.privileges` fact, the `probe step N` lint rule, and
`policies/actions/` placement enforcement inside `runbookcheck.load_file`.

Hermetic: policies and the `vpscfg index` cache live in a temp estate; ssh is
a fake that records every call (so the --index-only zero-dial guarantee is
checked directly, never assumed); the journal is redirected by the vpsexec
test harness (`test_vpsexec._Harness`). Nothing here reads a real index
cache, ~/.vpscfg, vpscfgfarm-estate, vpscfg-control.json or dials a host.

Fictional names only: hosts edge1/web1, app shop, role shop_app, user alice.
"""
import datetime
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_actions_core as tac  # noqa: E402
import test_runbookcheck as trc  # noqa: E402
import test_vpsexec as tv  # noqa: E402
from vpscfg import indexstore, probe, runbookcheck, vpsexecpolicy  # noqa: E402
from vpscfg.gates import Refused  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

NOW = datetime.datetime(2026, 10, 12, 12, 0, 0, tzinfo=datetime.timezone.utc)
TODAY = "2026-10-12"
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def _ts(dt):
    return dt.strftime(STAMP)


def _doc(host="edge1", collected_at=None, sections=None, index_version=1):
    return {"host": host, "index_version": index_version,
            "collected_at": collected_at if collected_at is not None else _ts(NOW),
            "sections": sections or {}}


def _pg_sections(container="shop-db", database="shop", schema="shop",
                 not_owned=8, owned=0, role="shop_app", other="postgres", error=None):
    if error:
        return {"postgres": {"error": error}}
    tables = [{"name": "t%d" % i, "owner": other} for i in range(not_owned)]
    tables += [{"name": "ok%d" % i, "owner": role} for i in range(owned)]
    return {"postgres": {"instances": [{
        "container": container, "source": "container",
        "databases": [{"name": database, "owner": other,
                       "schemas": [{"name": schema, "owner": other,
                                   "ownership": [], "tables": tables}]}]}]}}


# ===========================================================================
# indexstore.cache_status — the file-level freshness check
# ===========================================================================

class CacheStatusTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, host="edge1", collected_at=None, mode=0o600, text=None,
              index_version=1):
        path = self.dir / ("%s.json" % host)
        path.write_text(text if text is not None else
                        json.dumps(_doc(host, collected_at, index_version=index_version)))
        os.chmod(str(path), mode)
        return path

    def status(self, host="edge1", max_age=12 * 3600, now=NOW):
        return indexstore.cache_status(host, self.dir, max_age, now=now)

    def test_missing_is_unusable(self):
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIsNone(age)
        self.assertIn("missing", reason)

    def test_fresh_is_usable(self):
        self.write(collected_at=_ts(NOW - datetime.timedelta(hours=3)))
        doc, age, reason = self.status()
        self.assertIsNotNone(doc)
        self.assertIsNone(reason)
        self.assertAlmostEqual(age, 3 * 3600, delta=5)

    def test_another_hosts_document_under_this_name_is_unusable(self):
        # A copied or renamed cache file: fresh, 0600, ours, but about web1.
        path = self.dir / "edge1.json"
        path.write_text(json.dumps(_doc("web1", _ts(NOW - datetime.timedelta(hours=1)))))
        os.chmod(str(path), 0o600)
        doc, age, reason = self.status("edge1")
        self.assertIsNone(doc)
        self.assertIsNone(age)
        self.assertIn("describes host 'web1'", reason)

    def test_a_document_with_no_host_is_unusable(self):
        d = _doc("edge1", _ts(NOW - datetime.timedelta(hours=1)))
        d.pop("host", None)
        self.write(text=json.dumps(d))
        doc, _, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("describes host None", reason)

    def test_stale_is_unusable(self):
        self.write(collected_at=_ts(NOW - datetime.timedelta(hours=31)))
        doc, age, reason = self.status(max_age=12 * 3600)
        self.assertIsNone(doc)
        self.assertIn("stale", reason)

    def test_exactly_at_the_limit_is_still_usable(self):
        self.write(collected_at=_ts(NOW - datetime.timedelta(hours=12)))
        doc, age, reason = self.status(max_age=12 * 3600)
        self.assertIsNotNone(doc)
        self.assertIsNone(reason)

    def test_future_dated_is_unusable(self):
        self.write(collected_at=_ts(NOW + datetime.timedelta(hours=1)))
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("future", reason)

    def test_slight_future_skew_is_tolerated(self):
        self.write(collected_at=_ts(NOW + datetime.timedelta(seconds=30)))
        doc, age, reason = self.status()
        self.assertIsNotNone(doc)
        self.assertIsNone(reason)

    def test_wrong_mode_is_unusable(self):
        self.write(mode=0o640)
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("mode", reason)

    def test_world_readable_is_unusable(self):
        self.write(mode=0o644)
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("mode", reason)

    def test_symlink_is_unusable(self):
        real = self.dir / "real.json"
        real.write_text(json.dumps(_doc("edge1")))
        os.chmod(str(real), 0o600)
        (self.dir / "edge1.json").symlink_to(real)
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("symlink", reason)

    def test_other_owner_is_unusable(self):
        self.write()
        with mock.patch.object(indexstore.os, "getuid", return_value=os.getuid() + 1):
            doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("uid", reason)

    def test_corrupt_json_is_unusable(self):
        self.write(text="{not json at all")
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("corrupt", reason)

    def test_unknown_index_version_is_unusable(self):
        path = self.dir / "edge1.json"
        path.write_text(json.dumps({"host": "edge1", "collected_at": _ts(NOW),
                                    "sections": {}}))
        os.chmod(str(path), 0o600)
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("index_version", reason)

    def test_an_index_version_this_tool_does_not_know_is_unusable(self):
        # L6: "known" means a version this reader understands, not merely
        # present.
        for version in (2, 99, 0, "1", True, 1.5, [1]):
            with self.subTest(version=version):
                self.write(index_version=version)
                doc, age, reason = self.status()
                self.assertIsNone(doc)
                self.assertIn("index_version", reason)
        self.write(index_version=1)
        self.assertIsNotNone(self.status()[0])

    def _swapped(self, **fake):
        """The file passes lstat, then os.fstat on the OPENED fd reports
        something else (a swap between the two calls)."""
        self.write()
        real = os.fstat

        def fstat(fd):
            st = real(fd)
            values = list(st)
            if "uid" in fake:
                values[4] = fake["uid"]
            if "mode" in fake:
                values[0] = fake["mode"]
            return os.stat_result(values)
        with mock.patch.object(indexstore.os, "fstat", side_effect=fstat):
            return self.status()

    def test_the_opened_file_is_rechecked_for_its_owner(self):
        doc, _, reason = self._swapped(uid=os.getuid() + 1)
        self.assertIsNone(doc)
        self.assertIn("as opened", reason)

    def test_the_opened_file_is_rechecked_for_its_mode(self):
        import stat as _stat
        doc, _, reason = self._swapped(mode=_stat.S_IFREG | 0o644)
        self.assertIsNone(doc)
        self.assertIn("as opened", reason)

    def test_the_opened_file_is_rechecked_for_being_regular(self):
        import stat as _stat
        doc, _, reason = self._swapped(mode=_stat.S_IFIFO | 0o600)
        self.assertIsNone(doc)
        self.assertIn("not a regular file", reason)

    def test_unparseable_collected_at_is_unusable(self):
        path = self.dir / "edge1.json"
        path.write_text(json.dumps({"host": "edge1", "index_version": 1,
                                    "collected_at": "not-a-date", "sections": {}}))
        os.chmod(str(path), 0o600)
        doc, age, reason = self.status()
        self.assertIsNone(doc)
        self.assertIn("collected_at", reason)

    def test_max_age_seconds_defaults_and_clamps(self):
        self.assertEqual(indexstore.max_age_seconds({}), 12 * 3600)
        self.assertEqual(indexstore.max_age_seconds({"index_max_age_hours": 6}), 6 * 3600)
        self.assertEqual(indexstore.max_age_seconds({"index_max_age_hours": 48}), 24 * 3600)
        self.assertEqual(indexstore.max_age_seconds({"index_max_age_hours": -1}), 12 * 3600)
        self.assertEqual(indexstore.max_age_seconds({"index_max_age_hours": "12"}), 12 * 3600)
        self.assertEqual(indexstore.max_age_seconds({"index_max_age_hours": True}), 12 * 3600)


# ===========================================================================
# runbookcheck.preflight — owner_of_tables upgraded, source labelling,
# --live / --index-only, alias resolution, journalled source
# ===========================================================================

class _IndexEstate(trc._Estate):

    def setUp(self):
        super().setUp()
        self.index_dir = self.root / "index"
        self.index_dir.mkdir()

    def write_index(self, host, doc):
        path = self.index_dir / ("%s.json" % host)
        path.write_text(json.dumps(doc))
        os.chmod(str(path), 0o600)
        return path

    def preflight(self, assumes, host=None, steps=None, live=False, index_only=False,
                 now=NOW, index_dir=None, guard=None):
        host_ssh = host if host is not None else trc.FakeHost()
        path = self.write_policy(trc._policy_text(steps=steps, assumes=assumes))
        rep = runbookcheck.preflight(path, guard or self.guard, tv._yaml_policy(),
                                     ssh=host_ssh, today=TODAY, live=live,
                                     index_only=index_only,
                                     index_dir=self.index_dir if index_dir is None
                                     else index_dir, now=now)
        return rep, host_ssh


OWNER_ASSUMES = """
assumes:
  - host: edge1
    owner_of_tables: {container: shop-db, role: shop_app, database: shop, schema: shop}
"""


class OwnerOfTablesIndexTest(_IndexEstate):

    def test_weekend_example_turns_manual_into_fail_naming_the_tables(self):
        # The weekend halt: 8 tables in shop.shop owned by postgres, none by
        # shop_app. A fresh index turns the old MANUAL into a named FAIL.
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=8, owned=0)))
        rep, host = self.preflight(OWNER_ASSUMES)
        name = "assumes[1] owner_of_tables"
        self.assertEqual(self.status(rep, name), "fail")
        ev = self.evidence(rep, name)
        for i in range(8):
            self.assertIn("shop.t%d" % i, ev)
        self.assertIn("(index,", ev)
        self.assertEqual(rep["verdict"], "NO-GO")
        self.assertEqual(host.calls, [])  # answered from the cache, no dial

    def test_fresh_index_all_owned_passes(self):
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=0, owned=3)))
        rep, host = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "pass")
        self.assertIn("(index,", self.evidence(rep, "assumes[1] owner_of_tables"))
        self.assertEqual(host.calls, [])

    def test_no_index_stays_manual_as_before(self):
        rep, host = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertIn("index missing", self.evidence(rep, "assumes[1] owner_of_tables"))
        self.assertEqual(host.calls, [])

    def test_section_error_stays_manual(self):
        self.write_index("edge1", _doc(sections=_pg_sections(error="docker exec failed")))
        rep, _ = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertIn("section has an error",
                      self.evidence(rep, "assumes[1] owner_of_tables"))

    def test_stale_index_falls_back_to_manual_with_a_reason(self):
        self.write_index("edge1", _doc(collected_at=_ts(NOW - datetime.timedelta(hours=31)),
                                       sections=_pg_sections(not_owned=8)))
        rep, _ = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertIn("stale", self.evidence(rep, "assumes[1] owner_of_tables"))

    def test_live_flag_bypasses_a_fresh_index(self):
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=8)))
        rep, _ = self.preflight(OWNER_ASSUMES, live=True)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertIn("--live", self.evidence(rep, "assumes[1] owner_of_tables"))

    def test_index_only_skips_rather_than_manual_when_unanswerable(self):
        rep, host = self.preflight(OWNER_ASSUMES, index_only=True)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "skip")
        self.assertNotEqual(rep["verdict"], "NO-GO")
        self.assertEqual(host.calls, [])

    def test_index_only_still_answers_from_a_fresh_index(self):
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=8)))
        rep, host = self.preflight(OWNER_ASSUMES, index_only=True)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "fail")
        self.assertEqual(host.calls, [])

    def test_alias_host_resolves_to_the_canonical_cache_file(self):
        # The governor says `web1` IS `web1.example.internal`; the index is
        # cached under the canonical name, and preflight must look there.
        self.write_index("web1.example.internal",
                         _doc(host="web1.example.internal",
                              sections=_pg_sections(container="shop-db", not_owned=5)))
        guard = tv._guard(tv._policy_aliased())
        assumes = OWNER_ASSUMES.replace("host: edge1", "host: web1")
        rep, host = self.preflight(assumes, guard=guard)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "fail")
        self.assertEqual(host.calls, [])

    def test_live_fallback_is_journalled(self):
        rep, _ = self.preflight(OWNER_ASSUMES)
        events = [e for e in self.events() if e.get("event") == "preflight_source"]
        self.assertTrue(events, "no preflight_source event was journalled")
        ev = events[0]
        self.assertEqual(ev["host"], "edge1")
        self.assertFalse(ev["index_usable"])
        self.assertIn("missing", ev["reason"])

    def test_fresh_index_is_journalled_as_usable(self):
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=0)))
        self.preflight(OWNER_ASSUMES)
        events = [e for e in self.events() if e.get("event") == "preflight_source"]
        self.assertTrue(events[0]["index_usable"])
        self.assertIsNone(events[0]["reason"])

    def test_the_index_is_fetched_once_per_host_per_run(self):
        # Two owner_of_tables facts on the same host must stat the cache once.
        assumes = OWNER_ASSUMES + """
  - host: edge1
    owner_of_tables: {container: shop-db, role: shop_app, database: shop}
"""
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=1)))
        with mock.patch.object(indexstore, "cache_status",
                               wraps=indexstore.cache_status) as spy:
            self.preflight(assumes)
        self.assertEqual(spy.call_count, 1)

    def test_a_truncated_table_list_with_nothing_unowned_is_never_a_pass(self):
        # M2: a truncated list may hide an unowned table.
        sections = _pg_sections(not_owned=0, owned=3)
        sections["postgres"]["instances"][0]["databases"][0]["schemas"][0][
            "tables_truncated"] = True
        self.write_index("edge1", _doc(sections=sections))
        rep, host = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertIn("truncated", self.evidence(rep, "assumes[1] owner_of_tables"))
        rep, host = self.preflight(OWNER_ASSUMES, index_only=True)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "skip")
        self.assertEqual(host.calls, [])

    def test_a_truncated_list_naming_an_unowned_table_still_fails(self):
        sections = _pg_sections(not_owned=2, owned=3)
        sections["postgres"]["instances"][0]["databases"][0]["schemas"][0][
            "tables_truncated"] = True
        self.write_index("edge1", _doc(sections=sections))
        rep, _ = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "fail")
        self.assertIn("truncated", self.evidence(rep, "assumes[1] owner_of_tables"))

    def test_zero_recorded_tables_proves_nothing(self):
        # M2: an empty table list is not "owns every table".
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=0, owned=0)))
        rep, _ = self.preflight(OWNER_ASSUMES)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "manual")
        self.assertIn("no tables", self.evidence(rep, "assumes[1] owner_of_tables"))
        rep, _ = self.preflight(OWNER_ASSUMES, index_only=True)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "skip")

    def test_default_index_dir_resolves_under_the_policy_estate(self):
        # Without an explicit index_dir, preflight must look at
        # <estate>/index/<host>.json, derived from the policy's own path —
        # never a global "current estate" singleton.
        self.write_index("edge1", _doc(sections=_pg_sections(not_owned=2)))
        path = self.write_policy(trc._policy_text(assumes=OWNER_ASSUMES))
        rep = runbookcheck.preflight(path, self.guard, tv._yaml_policy(),
                                     ssh=trc.FakeHost(), today=TODAY, now=NOW)
        self.assertEqual(self.status(rep, "assumes[1] owner_of_tables"), "fail")


def _containers_section(state="running", image=None, env_names=("DB_HOST", "DB_NAME",
                                                                 "DB_USER", "DB_PASS"),
                        name="shop-api", error=None):
    if error:
        return {"containers": {"error": error}}
    return {"containers": {"docker": {"server_version": "27.0"}, "skipped": [], "containers": [
        {"name": name, "image": "shop/api:1.5", "image_id": image or trc.IMAGE,
         "state": state, "env_names": sorted(env_names),
         "compose": {"project": "shop", "service": "api",
                     "config_files": ["/srv/shop/compose.yaml"], "working_dir": "/srv/shop"}}]}}


class ContainerFactsFromIndexTest(_IndexEstate):
    """V7b: container state, image and env NAMES (DATABASE_URL vs DB_*) are
    answered from a fresh index, citing its age; anything else falls back to
    a live read, journaled with the reason."""

    def test_db_star_env_names_pass_from_the_index_without_dialing(self):
        self.write_index("edge1", _doc(sections=_containers_section()))
        rep, host = self.preflight(trc.ASSUMES_OK)
        self.assertEqual(host.calls, [], "answered from the cache, no dial")
        for name in ("assumes[1] shop-api", "assumes[1] shop-api image",
                     "assumes[1] shop-api env names"):
            self.assertEqual(self.status(rep, name), "pass", name)
            self.assertIn("(index, ", self.evidence(rep, name))
        self.assertIn("DB_HOST", self.evidence(rep, "assumes[1] shop-api env names"))

    def test_missing_env_names_and_a_stopped_container_fail_from_the_index(self):
        self.write_index("edge1", _doc(sections=_containers_section(
            state="exited", env_names=("DB_HOST",))))
        rep, host = self.preflight(trc.ASSUMES_OK, index_only=True)
        self.assertEqual(host.calls, [])
        self.assertEqual(self.status(rep, "assumes[1] shop-api"), "fail")
        self.assertEqual(self.status(rep, "assumes[1] shop-api env names"), "fail")
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_a_container_absent_from_a_fresh_index_fails(self):
        self.write_index("edge1", _doc(sections=_containers_section(name="other")))
        rep, host = self.preflight(trc.ASSUMES_OK)
        self.assertEqual(self.status(rep, "assumes[1] shop-api"), "fail")
        self.assertEqual(host.calls, [])

    def test_a_stale_index_falls_back_to_live_and_journals_why(self):
        self.write_index("edge1", _doc(collected_at=_ts(NOW - datetime.timedelta(hours=31)),
                                       sections=_containers_section()))
        rep, host = self.preflight(trc.ASSUMES_OK)
        self.assertTrue(host.calls, "a live read was made")
        self.assertIn("(live; index:", self.evidence(rep, "assumes[1] shop-api"))
        self.assertIn("stale", self.evidence(rep, "assumes[1] shop-api"))
        falls = [e for e in self.events() if e.get("event") == "preflight_live_fallback"]
        self.assertTrue(falls)
        self.assertIn("stale", falls[0]["reason"])

    def test_a_section_error_falls_back_to_live(self):
        self.write_index("edge1", _doc(sections=_containers_section(error="docker down")))
        rep, host = self.preflight(trc.ASSUMES_OK)
        self.assertTrue(host.calls)
        self.assertIn("containers section has an error",
                      self.evidence(rep, "assumes[1] shop-api"))

    def test_index_only_with_no_index_skips_never_passes(self):
        rep, host = self.preflight(trc.ASSUMES_OK, index_only=True)
        self.assertEqual(host.calls, [])
        self.assertEqual(self.status(rep, "assumes[1] container"), "skip")

    def test_a_label_the_index_does_not_record_goes_live(self):
        assumes = trc.ASSUMES_OK + "    compose_labels: {com.example.tier: web}\n"
        self.write_index("edge1", _doc(sections=_containers_section()))
        rep, host = self.preflight(assumes, index_only=True)
        self.assertEqual(host.calls, [])
        self.assertIn("does not record label", self.evidence(rep, "assumes[1] container"))

    def test_recorded_compose_labels_and_files_answer_from_the_index(self):
        assumes = trc.ASSUMES_OK + ("    compose_labels: {com.docker.compose.project: shop}\n"
                                    "    compose_files: [/srv/shop/compose.yaml]\n")
        self.write_index("edge1", _doc(sections=_containers_section()))
        rep, host = self.preflight(assumes)
        self.assertEqual(host.calls, [])
        self.assertEqual(self.status(rep, "assumes[1] shop-api label "
                                          "com.docker.compose.project"), "pass")
        self.assertEqual(self.status(rep, "assumes[1] shop-api compose files"), "pass")


class IndexOnlyNeverDialsTest(_IndexEstate):

    ASSUMES = """
    assumes:
      - host: edge1
        container: shop-api
        image: %s
        absent: [/srv/releases/shop-1.5.0]
        min_free_gb: {/opt: 5}
        owner_of_tables: {container: shop-db, role: shop_app, database: shop}
        privileges: {container: shop-db, db: shop, role: shop_app, table: orders,
                     privs: [SELECT]}
    """ % trc.IMAGE

    def test_index_only_never_dials_and_every_result_is_skip_or_manual_never_pass(self):
        rep, host = self.preflight(self.ASSUMES, index_only=True)
        self.assertEqual(host.calls, [])
        for c in rep["checks"]:
            self.assertNotEqual(c["status"], "pass", c)
        statuses = set(c["status"] for c in rep["checks"])
        self.assertTrue(statuses <= {"skip", "manual", "warn"}, statuses)


# ===========================================================================
# assumes.privileges — validation (accept / refuse) and the live check
# ===========================================================================

GOV_HOSTS = set(tv._policy()["hosts"])
GOOD_PRIVILEGE = {"container": "shop-db", "db": "shop", "role": "shop_app",
                  "table": "orders", "privs": ["SELECT", "INSERT"]}


class PrivilegesAssumeValidationTest(unittest.TestCase):

    def check(self, privileges):
        doc = {"assumes": [dict({"host": "edge1"}, privileges=privileges)]}
        return vpsexecpolicy.check_assumes(Path("x.yaml"), doc, probe.HOST_RE, GOV_HOSTS)

    def test_well_formed_privileges_is_accepted(self):
        out = self.check(GOOD_PRIVILEGE)
        self.assertEqual(out[0]["privileges"], GOOD_PRIVILEGE)

    def test_single_privilege_is_accepted(self):
        self.check(dict(GOOD_PRIVILEGE, privs=["SELECT"]))

    def test_an_optional_schema_is_accepted(self):
        out = self.check(dict(GOOD_PRIVILEGE, schema="sales"))
        self.assertEqual(out[0]["privileges"]["schema"], "sales")

    def test_refusals(self):
        bad = {
            "missing table": {k: v for k, v in GOOD_PRIVILEGE.items() if k != "table"},
            "unknown key": dict(GOOD_PRIVILEGE, column="id"),
            "schema injection": dict(GOOD_PRIVILEGE, schema="public'; drop table x; --"),
            "uppercase schema": dict(GOOD_PRIVILEGE, schema="Public"),
            "empty privs": dict(GOOD_PRIVILEGE, privs=[]),
            "bad priv value": dict(GOOD_PRIVILEGE, privs=["DROP"]),
            "duplicate privs": dict(GOOD_PRIVILEGE, privs=["SELECT", "SELECT"]),
            "privs not a list": dict(GOOD_PRIVILEGE, privs="SELECT"),
            "uppercase table": dict(GOOD_PRIVILEGE, table="Orders"),
            "uppercase role": dict(GOOD_PRIVILEGE, role="Shop_App"),
            "table with dot": dict(GOOD_PRIVILEGE, table="shop.orders"),
            "container injection": dict(GOOD_PRIVILEGE, container="shop-db; rm -rf /"),
            "sql injection in table": dict(GOOD_PRIVILEGE, table="orders'; drop table x; --"),
            "not a mapping": "shop_app",
            "db not a string": dict(GOOD_PRIVILEGE, db=1),
        }
        for label, value in bad.items():
            with self.subTest(label):
                with self.assertRaises(Refused):
                    self.check(value)

    def test_privileges_item_combined_with_other_facts_is_fine(self):
        doc = {"assumes": [{"host": "edge1", "container": "shop-db",
                            "privileges": GOOD_PRIVILEGE}]}
        out = vpsexecpolicy.check_assumes(Path("x.yaml"), doc, probe.HOST_RE, GOV_HOSTS)
        self.assertEqual(out[0]["container"], "shop-db")
        self.assertEqual(out[0]["privileges"], GOOD_PRIVILEGE)


class _PrivHost(object):
    """Answers the has_table_privilege probe sent over stdin to a docker-exec
    psql session, as runbookcheck._privileges_check sends it."""

    def __init__(self, granted=True, broken=False, rc=0, raw_answer=None):
        self.granted, self.broken, self.rc = granted, broken, rc
        self.raw_answer = raw_answer
        self.calls = []

    def __call__(self, host, cmd, timeout=None, connect_timeout=None, data=None):
        # The real transport is binary-mode (L1): stdin must be bytes, and the
        # answer comes back as bytes too.
        if data is not None and not isinstance(data, bytes):
            raise TypeError("a bytes-like object is required, not %r" % type(data).__name__)
        text = data.decode("utf-8") if data is not None else None
        self.calls.append((host, cmd, text))
        if self.broken:
            raise OSError("ssh: connect to host edge1: Connection refused")
        if self.raw_answer is not None:
            return self.raw_answer
        if "has_table_privilege" in (text or ""):
            token = "VPSCFG-DONE" if self.granted else "VPSCFG-NEEDED"
            return self.rc, ("@@@check\n%s\n" % token).encode(), b""
        raise AssertionError("unexpected command: %r (stdin: %r)" % (cmd, text))


class PrivilegesLiveCheckTest(_IndexEstate):

    ASSUMES = """
    assumes:
      - host: edge1
        privileges: {container: shop-db, db: shop, role: shop_app, table: orders,
                     privs: [SELECT, INSERT]}
    """

    def test_role_holding_every_privilege_passes(self):
        rep, host = self.preflight(self.ASSUMES, host=_PrivHost(granted=True))
        self.assertEqual(self.status(rep, "assumes[1] privileges"), "pass")
        self.assertTrue(host.calls)
        self.assertEqual(host.calls[0][0], "edge1")

    def test_role_missing_a_privilege_fails(self):
        rep, _ = self.preflight(self.ASSUMES, host=_PrivHost(granted=False))
        self.assertEqual(self.status(rep, "assumes[1] privileges"), "fail")
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_transport_failure_is_an_error_not_a_pass(self):
        rep, _ = self.preflight(self.ASSUMES, host=_PrivHost(broken=True))
        self.assertEqual(self.status(rep, "assumes[1]"), "error")

    def test_a_bad_token_fails_closed(self):
        host = _PrivHost(raw_answer=(0, "@@@check\nVPSCFG-DONE\nextra\n", ""))
        rep, _ = self.preflight(self.ASSUMES, host=host)
        self.assertEqual(self.status(rep, "assumes[1] privileges"), "error")

    def test_index_only_never_dials_for_privileges(self):
        rep, host = self.preflight(self.ASSUMES, host=_PrivHost(granted=True),
                                   index_only=True)
        self.assertEqual(self.status(rep, "assumes[1] privileges"), "skip")
        self.assertEqual(host.calls, [])

    def test_the_sent_statement_checks_each_privilege_separately(self):
        host = _PrivHost(granted=True)
        self.preflight(self.ASSUMES, host=host)
        _, _, data = host.calls[0]
        self.assertEqual(data.count("has_table_privilege"), 2)
        self.assertIn("'shop_app'", data)
        self.assertIn("'orders'", data)
        self.assertIn("'SELECT'", data)
        self.assertIn("'INSERT'", data)
        # L1: schema-qualified (default public), never left to search_path
        self.assertEqual(data.count("format('%I.%I', 'public', 'orders')"), 2)

    def test_a_named_schema_qualifies_the_table(self):
        host = _PrivHost(granted=True)
        rep, _ = self.preflight(self.ASSUMES.replace("table: orders,",
                                                     "table: orders, schema: sales,"),
                                host=host)
        self.assertIn("format('%I.%I', 'sales', 'orders')", host.calls[0][2])
        self.assertIn("shop.sales.orders", self.evidence(rep, "assumes[1] privileges"))

    def test_a_str_stdin_would_have_crashed_the_real_transport(self):
        # The regression: the transport fake enforces bytes, as the real one
        # does; passing a str raises before anything is sent.
        with self.assertRaises(TypeError):
            _PrivHost()("edge1", "docker exec -i x", data="SELECT 1")


# ===========================================================================
# the probe step lint rule — a probe/precheck/check/STOP step must be a read
# ===========================================================================

class ProbeLintTest(trc._Estate):

    def test_clean_policy_has_no_probe_step_failures(self):
        rep = self.lint()
        self.assertEqual(self.status(rep, "probe steps"), "pass")
        self.assertEqual(rep["verdict"], "GO", runbookcheck.render(rep))

    def test_a_write_used_as_a_precheck_fails(self):
        # The weekend halt: a "precheck" that is secretly a write.
        steps = [
            {"cmd": "docker exec shop-db sh -c \"echo x > /tmp/marker\"",
             "why": "D1: precheck — must already hold distinct secrets", "timeout": 30},
            {"cmd": "vpscfg-push %s shop.tar.gz" % trc.SHA, "why": "S1: stage the build",
             "timeout": 120},
            {"cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
             "why": "C1: recreate", "timeout": 240},
        ]
        rep = self.lint(trc._policy_text(steps=steps, assumes=trc.ASSUMES_OK))
        self.assertEqual(self.status(rep, "probe step 1"), "fail")
        self.assertIn("not a read", self.evidence(rep, "probe step 1"))
        self.assertEqual(rep["verdict"], "NO-GO")

    def test_a_real_read_precheck_passes(self):
        steps = [
            {"cmd": "docker inspect --format '{{.State.Status}}' shop-api",
             "why": "precheck: confirm the container exists", "timeout": 30},
            {"cmd": "vpscfg-push %s shop.tar.gz" % trc.SHA, "why": "S1: stage the build",
             "timeout": 120},
            {"cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
             "why": "C1: recreate", "timeout": 240},
        ]
        rep = self.lint(trc._policy_text(steps=steps, assumes=trc.ASSUMES_OK))
        self.assertEqual(self.status(rep, "probe steps"), "pass")

    def test_a_step_that_is_refused_outright_fails_the_rule(self):
        # A raw-device content read is refused outright by classify() itself
        # (readpolicy), not merely demoted to non-read — the rule must still
        # catch it rather than letting the Refused escape.
        steps = [
            {"cmd": "cat /dev/mem",
             "why": "check: read device memory", "timeout": 30},
            {"cmd": "vpscfg-push %s shop.tar.gz" % trc.SHA, "why": "S1: stage the build",
             "timeout": 120},
            {"cmd": "docker compose --project-directory /srv/shop up -d --no-build app",
             "why": "C1: recreate", "timeout": 240},
        ]
        rep = self.lint(trc._policy_text(steps=steps, assumes=trc.ASSUMES_OK))
        self.assertEqual(self.status(rep, "probe step 1"), "fail")


# ===========================================================================
# policies/actions/ placement, enforced inside runbookcheck.load_file
# ===========================================================================

class ActionsPlacementTest(tac._Registered, tac._PolicyDir):
    ACTIONS = (tac.TouchAction,)

    def test_action_policy_at_the_top_level_refuses(self):
        path = self.write(tac._action_policy(), top=True)
        with self.assertRaises(Refused) as cm:
            runbookcheck.load_file(path, tac.DENY, TODAY, tac.GOV_HOSTS)
        self.assertIn("policies/actions", str(cm.exception))

    def test_action_policy_in_the_actions_dir_loads(self):
        path = self.armed(tac._action_policy())
        doc, raw, runbooks, assumes = runbookcheck.load_file(
            path, tac.DENY, TODAY, tac.GOV_HOSTS)
        self.assertEqual(len(runbooks), 1)

    def test_groups_in_the_actions_dir_refuses(self):
        text = tac._action_policy() + "groups:\n  web: [edge1]\n"
        path = self.write(text)
        with self.assertRaises(Refused) as cm:
            runbookcheck.load_file(path, tac.DENY, TODAY, tac.GOV_HOSTS)
        self.assertIn("groups", str(cm.exception))

    def test_a_plain_policy_in_the_actions_dir_is_fine(self):
        text = ("version: 1\nexpires: \"2026-12-31\"\nreason: plain in actions dir\n")
        path = self.write(text)
        doc, raw, runbooks, assumes = runbookcheck.load_file(
            path, tac.DENY, TODAY, tac.GOV_HOSTS)
        self.assertEqual(runbooks, [])

    def test_estate_root_for_an_actions_policy_is_one_level_further_up(self):
        # policies/actions/<file> sits one directory deeper than policies/
        # <file>; lint's plays/releases/artifacts defaults must still land
        # beside the ESTATE, not beside policies/.
        path = self.armed(tac._action_policy())
        estate = self.pdir.parent
        (estate / "plays").mkdir()
        (estate / "releases").mkdir()
        (estate / "artifacts").mkdir()
        self.assertEqual(runbookcheck._estate_root(path), estate.resolve())
        rep = runbookcheck.lint(path, tv._guard(), tv._yaml_policy(), today=TODAY,
                                now=datetime.datetime(2026, 10, 12, 12, 0, 0))
        self.assertNotEqual(self.status(rep, "policy"), "fail", runbookcheck.render(rep))

    @staticmethod
    def status(rep, name):
        hits = [c for c in rep["checks"] if c["name"] == name]
        assert hits, "no check %r in %r" % (name, [c["name"] for c in rep["checks"]])
        return hits[0]["status"]


# ===========================================================================
# public-repo hygiene (S12) — the exporter's scan over every file this
# workstream touched, in dry-run (never writes, never pushes)
# ===========================================================================

class PublicHygieneTest(unittest.TestCase):
    FILES = [REPO / "vpscfg" / "runbookcheck.py", REPO / "vpscfg" / "indexstore.py",
             REPO / "vpscfg" / "vpsexecpolicy.py", REPO / "docs" / "VPSEXEC.md",
             REPO / "docs" / "INDEX.md", Path(__file__)]

    def test_exporter_scan_finds_nothing(self):
        spec = importlib.util.spec_from_file_location(
            "export_public_p2", REPO / "tools" / "export-public.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for path in self.FILES:
            hits = mod.scan_text(str(path.relative_to(REPO)), path.read_text(), [])
            self.assertEqual(hits, [], path)


if __name__ == "__main__":
    unittest.main()

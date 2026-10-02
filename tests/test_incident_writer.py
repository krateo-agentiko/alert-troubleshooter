"""The Incident writer: each firing counts on an open incident of the same problem or opens a new
one, and each incident gets one RCA.

Every apiserver call goes to tests/fake_k8s.FakeK8s, which keeps the Incident CRD's rules the
writer depends on; the RCA and the comparison are stubs returning canned answers.
"""
import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import compare  # noqa: E402
import handler  # noqa: E402
from fake_k8s import FakeK8s, http_error  # noqa: E402

NS, ALERT = "krateo-system", "cd-not-ready"
HOW = {"precondition": "#!/usr/bin/env bash\n# holds while fireworksapp is not Ready\nexit 1\n",
       "apply": "#!/usr/bin/env bash\n# pin chart 1.1.10\ntrue\n",
       "verify": "#!/usr/bin/env bash\n# fixed once Ready\nexit 0\n"}
BLOCK = {"sources": [{"type": "object", "ref": "cd/fireworksapp", "excerpt": "Ready=False"}],
         "rootCause": {"statement": "chart 1.1.9 is missing", "confidence": 0.8, "category": "config"},
         "howToFix": HOW}


def answer(block=BLOCK, prose="## Root cause\nchart 1.1.9 is missing"):
    return f"{prose}\n\n```json\n{json.dumps(block)}\n```"


def alert_cr(name=ALERT, where="Body LIKE '%x%'", interval=None):
    spec = {"displayName": "CompositionDefinition not ready", "where": where}
    if interval:
        spec["interval"] = interval
    return {"metadata": {"name": name, "namespace": NS}, "spec": spec, "status": {"state": "ALERT"}}


def ago(seconds):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class WriterCase(unittest.TestCase):
    def setUp(self):
        self.k8s = FakeK8s([alert_cr()])
        self.rca, self.answer, self.during_rca = [], answer(), None
        # The comparison's answer: the name of the incident it matches, None, or an exception.
        self.compared, self.match = [], None
        # The alert's current records, and each read of them.
        self.records, self.record_reads = [("Pod cd/fireworksapp-1: BackOff", 3)], []
        self._orig = (handler._k8s, handler.a2a_analyze, handler.llm_compare)
        handler._k8s = self.k8s
        handler.a2a_analyze = self._a2a
        handler.llm_compare = self._compare

    def tearDown(self):
        handler._k8s, handler.a2a_analyze, handler.llm_compare = self._orig

    def _a2a(self, prompt, context_id=None):
        self.rca.append((prompt, context_id))
        if self.during_rca:
            self.during_rca()
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer, []

    def _compare(self, prompt, names):
        self.compared.append((names, prompt))
        if isinstance(self.match, Exception):
            raise self.match
        return self.match, "stub"

    def _records(self, where, seconds):
        self.record_reads.append((where, seconds))
        if isinstance(self.records, Exception):
            raise self.records
        return self.records

    def fire(self, alert=ALERT, ns=NS, where="Body LIKE '%x%'", interval=None):
        cr = alert_cr(alert, where=where, interval=interval)
        cr["metadata"]["namespace"] = ns
        handler.fire(cr, self._records)

    def analyzed(self, name, created="2026-09-25T10:00:00Z", state="Open"):
        """An open incident of ALERT with an analysis, which a firing is compared with."""
        return self.k8s.put(NS, name, ALERT, state=state, created=created,
                            root_cause=f"the cause of {name}")

    def status_writes(self):
        return [body["status"] for method, _, sub, body in self.k8s.calls
                if method == "PATCH" and sub == "status"]


class TestOpening(WriterCase):
    def test_the_name_is_the_alert_and_the_opening_second(self):
        at = datetime(2026, 9, 25, 14, 0, 5, tzinfo=timezone.utc)
        self.assertEqual(handler.incident_name(ALERT, at), "cd-not-ready-20260925-140005")

    def test_a_first_firing_opens_an_incident_and_writes_its_analysis(self):
        self.fire(where="Body LIKE '%x%'")
        inc = self.k8s.only()
        name = inc["metadata"]["name"]
        self.assertRegex(name, r"^cd-not-ready-\d{8}-\d{6}$")
        self.assertEqual(inc["metadata"]["labels"], {"observability.krateo.io/alert": ALERT})
        spec = inc["spec"]
        self.assertEqual(spec["alertRef"], {"name": ALERT, "namespace": NS})
        self.assertEqual(spec["trigger"], "alert")
        self.assertIn("`Body LIKE '%x%'`", spec["prompt"])
        st = inc["status"]
        self.assertEqual((st["state"], st["firings"], st["lastFiredAt"]),
                         ("Open", 1, spec["triggeredAt"]))
        self.assertEqual(st["howToFix"], HOW)
        self.assertEqual(st["rootCause"]["statement"], "chart 1.1.9 is missing")
        self.assertTrue(st["report"].startswith("## Root cause"))
        self.assertIn("completedAt", st)
        self.assertNotIn("error", st)
        self.assertNotIn("evidence", st)       # the Incident CRD has no such field
        self.assertEqual(self.rca, [(spec["prompt"], str(uuid.uuid5(uuid.NAMESPACE_DNS, name)))])

    def test_it_is_Analyzing_until_the_analysis_is_written(self):
        self.fire()
        first, last = self.status_writes()[0], self.status_writes()[-1]
        self.assertEqual((first["state"], first["firings"]), ("Analyzing", 1))
        self.assertEqual(last["state"], "Open")
        self.assertIn("howToFix", last)        # Open and its scripts land in one write

    def test_the_incident_lives_in_the_alerts_namespace(self):
        self.fire(ns="team-a")
        self.assertEqual(self.k8s.only("team-a")["spec"]["alertRef"]["namespace"], "team-a")

    def test_an_alert_name_over_63_characters_opens_nothing(self):
        self.fire(alert="a" * 64)
        self.assertEqual((self.k8s.incidents, self.rca), ({}, []))

    def test_a_webhook_notification_opens_nothing(self):
        """The reconciler's pass fires alerts; a notification would only fire twice."""
        handler.process({"alertName": f"🚨 {ALERT}", "state": "ALERT"})
        self.assertEqual((self.k8s.incidents, self.k8s.calls, self.rca), ({}, [], []))


class TestOpeningPolicy(WriterCase):
    def test_the_same_problem_is_counted_on_its_incident_and_runs_no_RCA(self):
        for state in ("Open", "Verifying"):
            with self.subTest(state=state):
                self.k8s.incidents.clear()
                self.analyzed(f"{ALERT}-x", state=state)
                self.match = f"{ALERT}-x"
                self.fire()
                inc = self.k8s.only()
                self.assertEqual(inc["status"]["firings"], 2)
                self.assertIn("lastFiredAt", inc["status"])
                self.assertEqual(inc["status"]["state"], state)
        self.assertEqual(self.rca, [])

    def test_a_different_problem_opens_a_second_incident(self):
        self.analyzed(f"{ALERT}-x")
        self.fire()
        self.assertEqual([n for n, _ in self.compared], [[f"{ALERT}-x"]])
        self.assertEqual(len(self.k8s.incidents), 2)
        self.assertEqual(len(self.rca), 1)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-x")]["status"]["firings"], 1)

    def test_all_open_incidents_are_compared_in_one_call_and_the_match_takes_the_firing(self):
        self.analyzed(f"{ALERT}-old", created="2026-09-25T08:00:00Z")
        self.analyzed(f"{ALERT}-mid", created="2026-09-25T09:00:00Z")
        self.analyzed(f"{ALERT}-new", created="2026-09-25T10:00:00Z")
        self.match = f"{ALERT}-mid"
        self.fire()
        self.assertEqual([n for n, _ in self.compared],
                         [[f"{ALERT}-new", f"{ALERT}-mid", f"{ALERT}-old"]])
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-mid")]["status"]["firings"], 2)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-old")]["status"]["firings"], 1)

    def test_the_comparison_sees_the_alert_its_records_and_the_incident(self):
        self.analyzed(f"{ALERT}-x")
        self.fire(where="Body LIKE '%boom%'", interval="15m")
        prompt = self.compared[0][1]
        self.assertIn("`Body LIKE '%boom%'`", prompt)
        self.assertIn("- 3× Pod cd/fireworksapp-1: BackOff", prompt)
        self.assertIn(f"the cause of {ALERT}-x", prompt)
        self.assertEqual(self.record_reads, [("Body LIKE '%boom%'", 900)])

    def test_only_the_newest_candidates_are_compared(self):
        for n in range(compare.MAX_CANDIDATES + 2):
            self.analyzed(f"{ALERT}-{n:02d}", created=f"2026-09-25T10:{n:02d}:00Z")
        self.fire()
        names = self.compared[0][0]
        self.assertEqual(len(names), compare.MAX_CANDIDATES)
        self.assertEqual(names[0], f"{ALERT}-{compare.MAX_CANDIDATES + 1:02d}")
        self.assertNotIn(f"{ALERT}-00", names)

    def test_unreadable_records_are_no_verdict(self):
        self.analyzed(f"{ALERT}-x")
        self.records = RuntimeError("HyperDX is down")
        self.fire()
        self.assertEqual((self.compared, self.rca), ([], []))
        self.assertEqual(self.k8s.only()["status"]["firings"], 1)

    def test_no_matching_records_are_no_verdict(self):
        self.analyzed(f"{ALERT}-x")
        self.records = []
        self.fire()
        self.assertEqual((self.compared, self.rca, len(self.k8s.incidents)), ([], [], 1))
        self.assertEqual(self.k8s.only()["status"]["firings"], 1)

    def test_no_matching_records_still_count_on_an_incident_without_an_analysis(self):
        self.analyzed(f"{ALERT}-x", created="2026-09-25T09:00:00Z")
        self.k8s.put(NS, f"{ALERT}-a", ALERT, state="Analyzing")
        self.records = []
        self.fire()
        self.assertEqual(self.compared, [])
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-a")]["status"]["firings"], 2)
        self.assertEqual(len(self.k8s.incidents), 2)

    def test_records_are_not_read_with_nothing_to_compare(self):
        self.fire()
        self.assertEqual((self.record_reads, len(self.rca)), ([], 1))

    def test_an_incident_without_an_analysis_takes_the_firing_uncompared(self):
        """Analyzing, or its RCA failed: nothing to compare with, and a new one would rerun it."""
        for state in ("Analyzing", "Open", "Verifying"):
            with self.subTest(state=state):
                self.k8s.incidents.clear()
                self.k8s.put(NS, f"{ALERT}-x", ALERT, state=state, firings=3)
                self.fire()
                self.assertEqual(self.k8s.only()["status"]["firings"], 4)
        self.assertEqual((self.compared, self.rca), ([], []))

    def test_a_failed_RCA_with_error_prose_takes_the_firing_uncompared(self):
        """A failed RCA can leave the agent's error text in `report`; it is still no analysis."""
        self.k8s.put(NS, f"{ALERT}-x", ALERT, state="Open", firings=3)
        self.k8s.write_status(NS, f"{ALERT}-x", {
            "report": "LLM error: 429 Too Many Requests",
            "error": "The analysis returned no structured block, so the incident has no scripts "
                     "to check or fix it."})
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 4)
        self.assertEqual((self.compared, self.rca), ([], []))

    def test_a_failed_RCA_stops_taking_firings_after_the_hold(self):
        """Past FAILED_ANALYSIS_HOLD the failed incident stays Open, and a firing nothing else
        covers opens a new incident with a fresh RCA."""
        self.k8s.put(NS, f"{ALERT}-x", ALERT, state="Open", firings=3,
                     completed=ago(handler.FAILED_ANALYSIS_HOLD + 60))
        self.k8s.write_status(NS, f"{ALERT}-x", {"error": "The analysis failed: 429"})
        self.fire()
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-x")]["status"]["firings"], 3)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-x")]["status"]["state"], "Open")
        self.assertEqual((len(self.k8s.incidents), len(self.rca)), (2, 1))

    def test_a_failed_RCA_inside_the_hold_still_takes_the_firing(self):
        self.k8s.put(NS, f"{ALERT}-x", ALERT, state="Open", firings=3,
                     completed=ago(handler.FAILED_ANALYSIS_HOLD - 60))
        self.k8s.write_status(NS, f"{ALERT}-x", {"error": "The analysis failed: 429"})
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 4)
        self.assertEqual(self.rca, [])

    def test_an_incident_still_analyzing_takes_firings_past_the_hold(self):
        self.k8s.put(NS, f"{ALERT}-x", ALERT, state="Analyzing", firings=3,
                     created=ago(handler.FAILED_ANALYSIS_HOLD + 60))
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 4)
        self.assertEqual(self.rca, [])

    def test_the_hold_counts_from_creation_without_completedAt(self):
        old = {"metadata": {"creationTimestamp": ago(handler.FAILED_ANALYSIS_HOLD + 60)},
               "status": {"state": "Open", "error": "The analysis failed: 429"}}
        now = datetime.now(timezone.utc)
        self.assertFalse(handler.holds_firings(old, now))
        self.assertTrue(handler.holds_firings(old, now, hold=handler.FAILED_ANALYSIS_HOLD + 600))

    def test_an_equal_analyzed_incident_takes_the_firing_before_an_analyzing_one(self):
        self.analyzed(f"{ALERT}-x", created="2026-09-25T09:00:00Z")
        self.k8s.put(NS, f"{ALERT}-y", ALERT, state="Analyzing", created="2026-09-25T10:00:00Z")
        self.match = f"{ALERT}-x"
        self.fire()
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-x")]["status"]["firings"], 2)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-y")]["status"]["firings"], 1)

    def test_a_different_problem_waits_on_an_incident_still_analyzing(self):
        self.analyzed(f"{ALERT}-x", created="2026-09-25T09:00:00Z")
        self.k8s.put(NS, f"{ALERT}-y", ALERT, state="Analyzing", created="2026-09-25T10:00:00Z")
        self.fire()
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-y")]["status"]["firings"], 2)
        self.assertEqual((len(self.k8s.incidents), self.rca), (2, []))

    def test_no_verdict_opens_nothing_and_counts_nothing(self):
        """A failed or rate-limited comparison leaves "new problem?" unknown: the next pass retries."""
        self.analyzed(f"{ALERT}-x")
        self.match = compare.NoVerdict("rate-limited")
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 1)
        self.assertEqual(self.rca, [])

    def test_an_evaluation_still_running_skips_the_alerts_next_firing(self):
        self.analyzed(f"{ALERT}-x")

        def slow(prompt, names):
            self.fire()                        # the next pass, while this comparison runs
            return f"{ALERT}-x", "stub"
        handler.llm_compare = slow
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 2)
        self.assertEqual(handler._firing, set())

    def test_an_ended_incident_does_not_count_a_new_firing_opens_one(self):
        self.k8s.put(NS, f"{ALERT}-resolved", ALERT, state="Resolved")
        self.k8s.write_status(NS, f"{ALERT}-resolved",
                              {"resolution": {"by": "verify", "at": ago(3600)}})  # past the window
        self.k8s.put(NS, f"{ALERT}-closed", ALERT, state="Closed")
        self.fire()
        self.assertEqual(len(self.k8s.incidents), 3)
        self.assertEqual((len(self.rca), self.compared), (1, []))
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-resolved")]["status"]["firings"], 1)

    def test_another_alerts_incident_is_not_counted(self):
        self.k8s.put(NS, "other-x", "other", state="Open")
        self.fire()
        self.assertEqual(len(self.k8s.incidents), 2)

    def test_the_newest_unanalyzed_incident_counts(self):
        self.k8s.put(NS, f"{ALERT}-old", ALERT, state="Open", created="2026-09-25T09:00:00Z")
        self.k8s.put(NS, f"{ALERT}-new", ALERT, state="Open", created="2026-09-25T10:00:00Z")
        self.fire()
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-new")]["status"]["firings"], 2)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-old")]["status"]["firings"], 1)

    def test_a_concurrent_status_write_is_not_lost(self):
        """The controller appends a check between our read and our write: the conditioned
        patch is refused, re-read and retried, and both writes survive."""
        self.k8s.put(NS, f"{ALERT}-x", ALERT, state="Open", firings=2, root_cause="c")
        self.match = f"{ALERT}-x"
        hits = []

        def controller(ns, name):
            if not hits:
                hits.append(name)
                self.k8s.write_status(ns, name, {"checks": [{"script": "precondition", "exit": 1}]})
        self.k8s.before_patch = controller
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["firings"], 3)
        self.assertEqual(st["checks"], [{"script": "precondition", "exit": 1}])
        self.assertEqual(len(self.compared), 1)  # the retry re-reads; it does not re-compare

    def test_a_concurrent_create_is_counted_on(self):
        """Another firing created the same-second incident first: this one counts on it."""
        def other_firing(ns, name):
            if (ns, name) not in self.k8s.incidents:
                self.k8s.put(ns, name, ALERT, state="Analyzing")
        self.k8s.before_create = other_firing
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 2)
        self.assertEqual(self.rca, [])

    def test_an_apiserver_failure_loses_the_firing_not_the_caller(self):
        def down(*a, **k):
            raise http_error(500)
        handler._k8s = down
        self.fire()                            # does not raise
        self.assertEqual(self.rca, [])


class TestResolvedGrace(WriterCase):
    """For one spec.interval after the alert's latest incident is Resolved, a firing counts on it:
    a `where` alert keeps counting pre-fix rows for its lookback window."""

    def ended(self, name, state, seconds_ago, created="2026-09-25T10:00:00Z"):
        self.k8s.put(NS, name, ALERT, state=state, created=created)
        self.k8s.write_status(NS, name, {"resolution": {"by": "verify" if state == "Resolved"
                                                        else "user", "at": ago(seconds_ago)}})

    def test_inside_the_window_the_firing_counts_on_the_Resolved_incident(self):
        self.ended(f"{ALERT}-r", "Resolved", 60)
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual((st["state"], st["firings"]), ("Resolved", 2))
        self.assertIn("lastFiredAt", st)
        self.assertEqual(self.rca, [])

    def test_outside_the_window_a_new_incident_opens(self):
        self.ended(f"{ALERT}-r", "Resolved", 600)
        self.fire()
        self.assertEqual(len(self.k8s.incidents), 2)
        self.assertEqual(len(self.rca), 1)

    def test_a_Closed_incident_never_takes_a_firing(self):
        self.ended(f"{ALERT}-c", "Closed", 10)
        self.fire()
        self.assertEqual(len(self.k8s.incidents), 2)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-c")]["status"]["firings"], 1)

    def test_only_the_latest_incident_gives_grace(self):
        """An older Resolved one inside the window does not count once a later one was Closed."""
        self.ended(f"{ALERT}-r", "Resolved", 30, created="2026-09-25T09:00:00Z")
        self.ended(f"{ALERT}-c", "Closed", 10, created="2026-09-25T10:00:00Z")
        self.fire()
        self.assertEqual(len(self.k8s.incidents), 3)

    def test_an_open_incident_takes_precedence(self):
        self.k8s.put(NS, f"{ALERT}-o", ALERT, state="Open", created="2026-09-25T09:00:00Z")
        self.ended(f"{ALERT}-r", "Resolved", 10, created="2026-09-25T10:00:00Z")
        self.fire()
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-o")]["status"]["firings"], 2)
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-r")]["status"]["firings"], 1)

    def test_a_different_problem_inside_the_window_counts_on_the_Resolved_incident(self):
        """Grace only stops a new incident: an open one of the same problem still takes it."""
        self.analyzed(f"{ALERT}-o", created="2026-09-25T09:00:00Z")
        self.ended(f"{ALERT}-r", "Resolved", 10, created="2026-09-25T10:00:00Z")
        self.fire()
        self.assertEqual([n for n, _ in self.compared], [[f"{ALERT}-o"]])
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-r")]["status"]["firings"], 2)
        self.assertEqual((len(self.k8s.incidents), self.rca), (2, []))

    def test_no_verdict_inside_the_window_counts_on_the_Resolved_incident(self):
        self.analyzed(f"{ALERT}-o", created="2026-09-25T09:00:00Z")
        self.ended(f"{ALERT}-r", "Resolved", 10, created="2026-09-25T10:00:00Z")
        self.match = compare.NoVerdict("rate-limited")
        self.fire()
        self.assertEqual(self.k8s.incidents[(NS, f"{ALERT}-r")]["status"]["firings"], 2)

    def test_the_window_is_the_alerts_interval(self):
        for interval, seconds_ago, counted in (("15m", 600, True), ("1m", 90, False),
                                               (None, 200, True), ("weird", 400, False)):
            with self.subTest(interval=interval, seconds_ago=seconds_ago):
                self.k8s.incidents.clear()
                self.ended(f"{ALERT}-r", "Resolved", seconds_ago)
                self.fire(interval=interval)
                self.assertEqual(len(self.k8s.incidents) == 1, counted)

    def test_the_boundary_is_exclusive(self):
        resolved = datetime(2026, 9, 25, 14, 0, 0, tzinfo=timezone.utc)
        inc = {"metadata": {"name": "r", "creationTimestamp": "t"},
               "status": {"state": "Resolved", "resolution": {"by": "verify",
                                                              "at": "2026-09-25T14:00:00Z"}}}
        within = handler.resolved_within
        self.assertTrue(within(inc, resolved + timedelta(seconds=299), 300))
        self.assertFalse(within(inc, resolved + timedelta(seconds=300), 300))
        for broken in ({}, {"by": "verify"}, {"by": "verify", "at": "not a time"}):
            inc["status"]["resolution"] = broken
            self.assertFalse(within(inc, resolved, 300))

    def test_a_concurrent_write_on_the_Resolved_incident_is_retried(self):
        self.ended(f"{ALERT}-r", "Resolved", 60)
        hits = []

        def controller(ns, name):
            if not hits:
                hits.append(name)
                self.k8s.write_status(ns, name, {"conditions": [{"type": "Ready"}]})
        self.k8s.before_patch = controller
        self.fire()
        self.assertEqual(self.k8s.only()["status"]["firings"], 2)



class TestAnalysisOutcome(WriterCase):
    def test_at_most_MAX_CONCURRENT_ANALYSES_RCAs_run_at_once(self):
        import threading
        import time
        running, peak, lock = [0], [0], threading.Lock()

        def rca(prompt, context_id=None):
            with lock:
                running[0] += 1
                peak[0] = max(peak[0], running[0])
            time.sleep(0.05)
            with lock:
                running[0] -= 1
            return answer(), []
        handler.a2a_analyze = rca
        threads = [threading.Thread(target=handler.run_analysis, args=(NS, f"{ALERT}-{i}", "p"))
                   for i in range(5)]
        for i in range(5):
            self.k8s.put(NS, f"{ALERT}-{i}", ALERT, state="Analyzing")
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(peak[0], handler.MAX_CONCURRENT_ANALYSES)

    def test_a_failed_RCA_opens_the_incident_with_the_error(self):
        self.answer = RuntimeError("A2A timed out")
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["state"], "Open")
        self.assertIn("A2A timed out", st["error"])
        self.assertNotIn("howToFix", st)
        self.assertNotIn("report", st)

    def test_an_empty_answer_is_an_error(self):
        self.answer = ""
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual((st["state"], st["error"]), ("Open", "The analysis returned no output."))

    def test_an_unstructured_answer_keeps_its_prose(self):
        self.answer = "The composition is broken."
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["report"], "The composition is broken.")
        self.assertIn("no structured block", st["error"])
        self.assertNotIn("howToFix", st)

    def test_an_unusable_how_to_fix_is_an_error_and_a_gap(self):
        self.answer = answer(dict(BLOCK, howToFix={"precondition": HOW["precondition"]}))
        self.fire()
        st = self.k8s.only()["status"]
        self.assertIn("no usable howToFix", st["error"])
        self.assertTrue(st["missingContext"][-1].startswith("No usable howToFix (apply missing"))

    def test_closed_while_analyzing_stays_Closed_and_gets_the_analysis(self):
        def human_closes():
            inc = self.k8s.only()
            self.k8s.write_status(NS, inc["metadata"]["name"],
                                  {"state": "Closed", "resolution": {"by": "user", "at": "t"}})
        self.during_rca = human_closes
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["state"], "Closed")
        self.assertEqual(st["howToFix"], HOW)

    def test_closed_between_the_reread_and_the_write(self):
        """The conditioned write is refused, and the re-read sees Closed."""
        patches = []

        def human_closes(ns, name):
            patches.append(name)
            if len(patches) == 2:              # the analysis write, after the Analyzing one
                self.k8s.write_status(ns, name, {"state": "Closed"})
        self.k8s.before_patch = human_closes
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["state"], "Closed")
        self.assertEqual(st["howToFix"], HOW)
        self.assertNotIn("state", self.status_writes()[-1])

    def test_an_incident_a_human_moved_on_keeps_its_state(self):
        """Opened by the restart sweep and then applied: the late analysis does not reset it."""
        def moved_on():
            inc = self.k8s.only()
            self.k8s.write_status(NS, inc["metadata"]["name"], {"state": "Verifying"})
        self.during_rca = moved_on
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["state"], "Verifying")
        self.assertEqual(st["howToFix"], HOW)


class TestRecoverInterrupted(WriterCase):
    def test_incidents_a_restart_left_analyzing_are_opened_with_the_reason(self):
        self.k8s.put(NS, "a-1", "a", state="Analyzing")
        self.k8s.put(NS, "b-1", "b")                       # no state: its first write never landed
        self.k8s.put(NS, "c-1", "c", state="Open")
        handler.recover_interrupted(NS)
        got = {n: o["status"] for (_, n), o in self.k8s.incidents.items()}
        self.assertEqual((got["a-1"]["state"], got["a-1"]["error"]), ("Open", handler.INTERRUPTED))
        self.assertEqual(got["b-1"]["state"], "Open")
        self.assertIn("completedAt", got["a-1"])            # the failed-RCA hold counts from here
        self.assertNotIn("error", got["c-1"])

    def test_a_late_analysis_clears_the_interruption(self):
        def swept():
            handler.recover_interrupted(NS)
        self.during_rca = swept
        self.fire()
        st = self.k8s.only()["status"]
        self.assertEqual(st["state"], "Open")
        self.assertNotIn("error", st)
        self.assertEqual(st["howToFix"], HOW)

    def test_no_Incident_CRD_is_not_an_error(self):
        def missing(*a, **k):
            raise http_error(404)
        handler._k8s = missing
        handler.recover_interrupted(NS)                    # does not raise


if __name__ == "__main__":
    unittest.main()

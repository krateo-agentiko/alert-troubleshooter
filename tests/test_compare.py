"""The incident comparison contract (compare.py) and its A2A call (handler.a2a_compare)."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

import compare  # noqa: E402
import handler  # noqa: E402

ALERT = {"metadata": {"name": "pod-crashloop", "namespace": "krateo-system"},
         "spec": {"displayName": "Pod crash-looping", "where": "Body LIKE '%BackOff%'",
                  "interval": "15m", "threshold": 3, "thresholdType": "above",
                  "message": "a pod is crash-looping"}}


def incident(**status):
    return {"metadata": {"name": "pod-crashloop-20260928-100000"},
            "spec": {"triggeredAt": "2026-09-28T10:00:00Z"},
            "status": {"state": "Open", "firings": 4, "lastFiredAt": "2026-09-28T10:03:00Z",
                       **status}}


ANALYZED = incident(
    rootCause={"statement": "payments-api is OOMKilled at 128Mi", "category": "capacity"},
    analyzedResources=[{"gvr": "apps/v1/deployments", "name": "payments-api",
                        "namespace": "payments"}],
    sources=[{"type": "events", "ref": "payments/payments-api", "excerpt": "OOMKilled"}],
    checks=[{"script": "precondition", "exit": 1, "at": "2026-09-28T10:02:00Z"},
            {"script": "precondition", "at": "2026-09-28T10:03:00Z"}],
    report="## Root cause\npayments-api runs out of memory.")


class TestComparable(unittest.TestCase):
    def test_an_incident_with_a_root_cause_or_a_report_is_comparable(self):
        self.assertTrue(compare.comparable(ANALYZED))
        self.assertTrue(compare.comparable(incident(report="prose only")))

    def test_analyzing_failed_and_empty_incidents_are_not(self):
        self.assertFalse(compare.comparable(incident(state="Analyzing", report="partial")))
        self.assertFalse(compare.comparable(incident(error="The analysis failed: 429")))
        self.assertFalse(compare.comparable(incident(report="  ", rootCause={})))

    def test_a_failed_analysis_with_error_prose_is_not(self):
        failed = incident(report="LLM error: 429 Too Many Requests",
                          error="The analysis returned no structured block, so the incident has "
                                "no scripts to check or fix it.")
        self.assertFalse(compare.comparable(failed))

    def test_a_root_cause_without_usable_scripts_is(self):
        self.assertTrue(compare.comparable(incident(
            rootCause={"statement": "payments-api is OOMKilled"}, report="## Root cause",
            error="The analysis returned no usable howToFix, so the incident has no scripts.")))


class TestPrompt(unittest.TestCase):
    def test_it_carries_the_alert_and_incident_A(self):
        p = compare.build_prompt(ALERT, ANALYZED, "2026-09-28T10:04:00Z")
        for part in ('"Pod crash-looping" (krateo-system/pod-crashloop)',
                     "`Body LIKE '%BackOff%'` over the last 15m", "above 3",
                     "Its intent: a pod is crash-looping.",
                     "Incident A is open: pod-crashloop-20260928-100000",
                     "payments-api is OOMKilled at 128Mi", "apps/v1/deployments payments/payments-api",
                     "- [events] payments/payments-api: OOMKilled",
                     "## Root cause", "Incident B would open now, 2026-09-28T10:04:00Z",
                     "Only read: change nothing.", '{"equal": true, "reason": "<one sentence>"}'):
            self.assertIn(part, p)

    def test_the_latest_precondition_run_is_quoted(self):
        p = compare.build_prompt(ALERT, ANALYZED, "t")
        self.assertIn("last exited with no exit code (unknown) at 2026-09-28T10:03:00Z", p)
        self.assertIn("has not run yet", compare.build_prompt(ALERT, incident(report="r"), "t"))

    def test_long_fields_are_cut(self):
        p = compare.build_prompt(ALERT, incident(report="x" * 5000), "t")
        self.assertIn("x" * compare.REPORT_CHARS + " …(truncated)", p)
        self.assertNotIn("x" * (compare.REPORT_CHARS + 1), p)


class TestVerdict(unittest.TestCase):
    def test_the_last_fenced_block_wins(self):
        text = ('Compared.\n```json\n{"equal": false, "reason": "draft"}\n```\n'
                'On reflection:\n```json\n{"equal": true, "reason": "same OOMKill"}\n```')
        self.assertEqual(compare.parse_verdict(text), (True, "same OOMKill"))

    def test_a_bare_object_is_read(self):
        self.assertEqual(compare.parse_verdict('{"equal": false, "reason": "other pod"}'),
                         (False, "other pod"))

    def test_no_boolean_equal_is_no_verdict(self):
        for text in ("", "They look the same.", '```json\n{"equal": "yes"}\n```',
                     '```json\n{"same": true}\n```', "```json\nnot json\n```"):
            with self.subTest(text=text), self.assertRaises(compare.NoVerdict):
                compare.parse_verdict(text)


def _http_error(code):
    return requests.HTTPError(f"{code}", response=types.SimpleNamespace(status_code=code))


class TestCompareCall(unittest.TestCase):
    def setUp(self):
        self._orig = handler._a2a
        self.calls = []

    def tearDown(self):
        handler._a2a = self._orig

    def _stub(self, result):
        def a2a(url, prompt, context_id=None, timeout=None, headers=None):
            self.calls.append((url, context_id, timeout, headers))
            if isinstance(result, Exception):
                raise result
            return result, []
        handler._a2a = a2a

    def test_it_calls_the_comparison_agent_with_the_purpose_header_on_a_fresh_thread(self):
        self._stub('```json\n{"equal": true, "reason": "r"}\n```')
        self.assertEqual(handler.a2a_compare("p"), (True, "r"))
        url, context_id, timeout, headers = self.calls[0]
        self.assertEqual((url, context_id, timeout),
                         (handler.COMPARE_A2A, None, handler.COMPARE_TIMEOUT))
        self.assertEqual(headers, {"X-Krateo-Purpose": "incident-compare"})

    def test_a_429_is_no_verdict_rate_limited(self):
        self._stub(_http_error(429))
        with self.assertRaisesRegex(compare.NoVerdict, "rate-limited"):
            handler.a2a_compare("p")

    def test_any_other_failure_is_no_verdict(self):
        for err in (_http_error(503), requests.Timeout("read timed out"), ValueError("bad")):
            with self.subTest(err=err):
                self._stub(err)
                with self.assertRaisesRegex(compare.NoVerdict, "the call failed"):
                    handler.a2a_compare("p")

    def test_an_answer_without_a_verdict_is_no_verdict(self):
        self._stub("I think they are the same.")
        with self.assertRaises(compare.NoVerdict):
            handler.a2a_compare("p")


if __name__ == "__main__":
    unittest.main()

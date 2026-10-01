"""The incident comparison contract (compare.py) and its LLM call (handler.llm_compare)."""
import base64
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
ROWS = [("Pod payments/payments-api-1: BackOff Back-off restarting failed container", 12),
        ("Pod shop/cart-2: BackOff Back-off restarting failed container", 2)]


def incident(name="pod-crashloop-20260928-100000", **status):
    return {"metadata": {"name": name, "creationTimestamp": "2026-09-28T10:00:00Z"},
            "spec": {"triggeredAt": "2026-09-28T10:00:00Z"},
            "status": {"state": "Open", "firings": 4, "lastFiredAt": "2026-09-28T10:03:00Z",
                       **status}}


ANALYZED = incident(
    rootCause={"statement": "payments-api is OOMKilled at 128Mi", "category": "capacity"},
    analyzedResources=[{"gvr": "apps/v1/deployments", "name": "payments-api",
                        "namespace": "payments"}],
    sources=[{"type": "events", "ref": "payments/payments-api", "excerpt": "OOMKilled"}],
    howToFix={"precondition": "kubectl -n payments get deploy payments-api\nexit 1",
              "apply": "kubectl -n payments set resources deploy payments-api --limits=memory=512Mi",
              "verify": "exit 0", "rollback": "kubectl rollout undo"},
    report="## Root cause\npayments-api runs out of memory.")


class TestCandidateCap(unittest.TestCase):
    def test_fifty_by_default_and_MAX_COMPARE_CANDIDATES_overrides(self):
        import importlib
        self.assertEqual(compare.MAX_CANDIDATES, 50)
        os.environ["MAX_COMPARE_CANDIDATES"] = "7"
        try:
            self.assertEqual(importlib.reload(compare).MAX_CANDIDATES, 7)
        finally:
            del os.environ["MAX_COMPARE_CANDIDATES"]
            importlib.reload(compare)


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
    def test_it_carries_the_alert_its_records_and_each_incident(self):
        other = incident("pod-crashloop-20260928-090000", rootCause={"statement": "cart lacks DB_URL"})
        p = compare.build_prompt(ALERT, [ANALYZED, other], ROWS)
        for part in ('Alert "Pod crash-looping"', "`Body LIKE '%BackOff%'` over the last 15m",
                     "above 3", "Its intent: a pod is crash-looping.",
                     "- 12× Pod payments/payments-api-1: BackOff",
                     "- 2× Pod shop/cart-2: BackOff",
                     "### Incident 1 (Open, opened 2026-09-28T10:00:00Z)",
                     "Root cause: payments-api is OOMKilled at 128Mi",
                     "precondition:\n```bash\nkubectl -n payments get deploy payments-api",
                     "apply:\n```bash\nkubectl -n payments set resources",
                     "verify:\n```bash\nexit 0",
                     "### Incident 2", "Root cause: cart lacks DB_URL",
                     '{"match": <incident number>, "reason": "<one sentence>"}'):
            self.assertIn(part, p)
        self.assertNotIn("pod-crashloop-2026", p)  # the gateway masks the names as phone numbers
        self.assertLess(p.index("OOMKilled at 128Mi"), p.index("cart lacks DB_URL"))

    def test_only_the_description_and_scripts_are_sent(self):
        p = compare.build_prompt(ALERT, [ANALYZED], ROWS)
        for part in ("rollout undo", "OOMKilled\n", "apps/v1/deployments", "runs out of memory",
                     "firings"):
            self.assertNotIn(part, p)

    def test_a_report_stands_in_for_a_missing_root_cause(self):
        p = compare.build_prompt(ALERT, [incident(report="prose only")], ROWS)
        self.assertIn("Root cause: prose only", p)

    def test_no_records_and_many_records_are_said(self):
        self.assertIn("No record matches now.", compare.build_prompt(ALERT, [ANALYZED], []))
        rows = [(f"r{n}", 1) for n in range(compare.MAX_ROWS + 3)]
        p = compare.build_prompt(ALERT, [ANALYZED], rows)
        self.assertIn(f"- 1× r{compare.MAX_ROWS - 1}", p)
        self.assertNotIn(f"- 1× r{compare.MAX_ROWS}\n", p)
        self.assertIn("… and 3 more distinct records", p)

    def test_long_fields_are_cut(self):
        p = compare.build_prompt(ALERT, [incident(report="x" * 5000)], ROWS)
        self.assertIn("x" * compare.DESCRIPTION_CHARS + " …(truncated)", p)
        self.assertNotIn("x" * (compare.DESCRIPTION_CHARS + 1), p)

    def test_the_system_prompt_is_short(self):
        self.assertLess(len(compare.SYSTEM), 300)


NAMES = ["a", "b"]


class TestVerdict(unittest.TestCase):
    def test_the_last_fenced_block_wins(self):
        text = ('Compared.\n```json\n{"match": 1, "reason": "draft"}\n```\n'
                'On reflection:\n```json\n{"match": 2, "reason": "same OOMKill"}\n```')
        self.assertEqual(compare.parse_verdict(text, NAMES), ("b", "same OOMKill"))

    def test_a_bare_object_and_a_null_match_are_read(self):
        self.assertEqual(compare.parse_verdict('{"match": null, "reason": "other pod"}', NAMES),
                         (None, "other pod"))

    def test_no_match_among_the_candidates_is_no_verdict(self):
        for text in ("", "They look the same.", '{"match": "a"}', '{"match": 3}', '{"match": 0}',
                     '{"match": true}', '{"match": 1.0}', '{"equal": true}',
                     "```json\nnot json\n```"):
            with self.subTest(text=text), self.assertRaises(compare.NoVerdict):
                compare.parse_verdict(text, NAMES)


def _http_error(code):
    return requests.HTTPError(f"{code}", response=types.SimpleNamespace(status_code=code))


class _Resp:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


GATEWAY = {"spec": {"provider": "OpenAI", "model": "gemini-3.8-flash", "apiKeyPassthrough": True,
                    "openAI": {"baseUrl": "http://gw:8080/llm/v1/"}}}


class TestCompareCall(unittest.TestCase):
    def setUp(self):
        self._orig = (handler._k8s, handler._service_jwt, requests.post)
        self.objects, self.posts = {}, []
        handler._k8s = lambda method, path, body=None, subresource="": self.objects[path]
        handler._service_jwt = lambda: "service-jwt"

    def tearDown(self):
        handler._k8s, handler._service_jwt, requests.post = self._orig

    def _model_config(self, obj):
        self.objects[f"/apis/kagent.dev/v1alpha2/namespaces/{handler.NAMESPACE}/modelconfigs/"
                     f"{handler.COMPARE_MODEL_CONFIG}"] = obj

    def _stub(self, result):
        def post(url, headers=None, timeout=None, json=None):
            self.posts.append((url, headers, timeout, json))
            if isinstance(result, Exception):
                raise result
            return _Resp(result)
        requests.post = post

    def test_one_chat_completion_on_the_model_config_with_the_service_jwt(self):
        self._model_config(GATEWAY)
        self._stub('{"match": 1, "reason": "r"}')
        self.assertEqual(handler.llm_compare("p", NAMES), ("a", "r"))
        url, headers, timeout, body = self.posts[0]
        self.assertEqual(url, "http://gw:8080/llm/v1/chat/completions")
        self.assertEqual(headers, {"Authorization": "Bearer service-jwt"})
        self.assertEqual(timeout, handler.COMPARE_TIMEOUT)
        self.assertEqual(body, {"model": "gemini-3.8-flash", "messages": [
            {"role": "system", "content": compare.SYSTEM}, {"role": "user", "content": "p"}]})

    def test_a_gemini_model_config_uses_its_key_secret(self):
        self._model_config({"spec": {"provider": "Gemini", "model": "m", "apiKeySecret": "k",
                                     "apiKeySecretKey": "apiKey"}})
        self.objects[f"/api/v1/namespaces/{handler.NAMESPACE}/secrets/k"] = {
            "data": {"apiKey": base64.b64encode(b"AIza-key").decode()}}
        self._stub('{"match": null, "reason": "r"}')
        self.assertEqual(handler.llm_compare("p", NAMES), (None, "r"))
        url, headers, _, _ = self.posts[0]
        self.assertEqual(url, f"{handler.GEMINI_OPENAI_URL}/chat/completions")
        self.assertEqual(headers, {"Authorization": "Bearer AIza-key"})

    def test_an_unsupported_provider_is_no_verdict(self):
        self._model_config({"spec": {"provider": "GeminiVertexAI", "model": "m"}})
        self._stub('{"match": 1}')
        with self.assertRaisesRegex(compare.NoVerdict, "GeminiVertexAI"):
            handler.llm_compare("p", NAMES)
        self.assertEqual(self.posts, [])

    def test_a_429_is_no_verdict_rate_limited(self):
        self._model_config(GATEWAY)
        self._stub(_http_error(429))
        with self.assertRaisesRegex(compare.NoVerdict, "rate-limited"):
            handler.llm_compare("p", NAMES)

    def test_any_other_failure_is_no_verdict(self):
        self._model_config(GATEWAY)
        for err in (_http_error(503), requests.Timeout("read timed out"), ValueError("bad")):
            with self.subTest(err=err):
                self._stub(err)
                with self.assertRaisesRegex(compare.NoVerdict, "the call failed"):
                    handler.llm_compare("p", NAMES)

    def test_an_answer_without_a_verdict_is_no_verdict(self):
        self._model_config(GATEWAY)
        self._stub("I think they are the same.")
        with self.assertRaises(compare.NoVerdict):
            handler.llm_compare("p", NAMES)


class TestRecordCounts(unittest.TestCase):
    def test_buckets_are_summed_per_group_most_frequent_first(self):
        import hyperdx_v2
        hdx = hyperdx_v2.HyperDXV2("http://hdx", "k")
        sent = []

        def req(method, path, body=None):
            sent.append((method, path, body))
            return [{"group": ["b"], "series_0.data": "2"}, {"group": ["a"], "series_0.data": "1"},
                    {"group": ["a"], "series_0.data": "4"}]
        hdx._req = req
        self.assertEqual(hdx.record_counts("src", "x = 1", 300, "g"), [("a", 5), ("b", 2)])
        method, path, body = sent[0]
        self.assertEqual((method, path), ("POST", "/api/v2/charts/series"))
        self.assertEqual(body["endTime"] - body["startTime"], 300000)
        self.assertEqual(body["granularity"], "5m")
        self.assertEqual(body["series"], [{"sourceId": "src", "aggFn": "count", "where": "x = 1",
                                           "whereLanguage": "sql", "groupBy": ["g"]}])


if __name__ == "__main__":
    unittest.main()

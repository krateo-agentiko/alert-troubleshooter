#!/usr/bin/env python3
"""Writes the golden corpora the Go tests hold the port to: inputs, and the outputs the Python
implementation gave for them.

The Python implementation is gone from the tree; run this against the last commit that has it:

    git worktree add /tmp/alert-provider-py 3f894e4
    python3 -m venv /tmp/venv && /tmp/venv/bin/pip install requests==2.32.3 pytest
    /tmp/venv/bin/python hack/golden/generate.py /tmp/alert-provider-py .

The inputs are those the Python test suite passes (recorded while it runs) plus seeded random ones
built around each contract's edge cases.
"""
import gzip
import json
import os
import random
import sys

PY, OUT = sys.argv[1], sys.argv[2]
sys.path.insert(0, PY)
sys.path.insert(0, os.path.join(PY, "tests"))

import pytest  # noqa: E402

import compare  # noqa: E402
import handler  # noqa: E402
import hyperdx_v2  # noqa: E402
import report_v2  # noqa: E402
import reconciler  # noqa: E402

rnd = random.Random(20261005)
PARSE, PROMPT, RCA_PROMPT, TOOL_RESULTS = (report_v2.parse_structured_report, compare.build_prompt,
                                           handler.build_prompt, handler._tool_results)
recorded = {"parse": [], "prompt": [], "verdict": [], "rca_prompt": [], "tool_results": []}


def record(name, fn, convert):
    def wrapped(*args, **kwargs):
        out = fn(*args, **kwargs)
        try:
            recorded[name].append(convert(args, kwargs, out))
        except (TypeError, ValueError):
            pass
        return out
    return wrapped


def jsonable(v):
    return json.loads(json.dumps(v))


class Harvest:
    """Records the contracts' calls while the Python test suite runs."""

    def pytest_sessionstart(self, session):
        report_v2.parse_structured_report = record(
            "parse", report_v2.parse_structured_report,
            lambda a, k, out: {"text": a[0], "ledger": jsonable(a[1] if len(a) > 1 else k.get("tool_ledger")),
                               "prose": out[0], "v2": jsonable(out[1])})
        compare.build_prompt = record(
            "prompt", compare.build_prompt,
            lambda a, k, out: {"alert": jsonable(a[0]), "incidents": jsonable(a[1]),
                               "rows": jsonable(a[2]), "prompt": out})
        handler.build_prompt = record(
            "rca_prompt", handler.build_prompt,
            lambda a, k, out: {"args": jsonable(list(a)), "prompt": out})
        handler._tool_results = record(
            "tool_results", handler._tool_results,
            lambda a, k, out: {"parts": jsonable(a[0]), "results": jsonable(out)})


def verdict_case(text, names):
    try:
        match, reason = compare.parse_verdict(text, names)
        return {"text": text, "names": names, "match": match, "reason": reason}
    except compare.NoVerdict as e:
        return {"text": text, "names": names, "error": str(e)}


# ---- random inputs ----

STRINGS = ["", " ", "  x  ", "abc", "abc\n", "\tmixed\n", "é ünï", "⚠︎ warn", "a" * 5000,
           "Forbidden: cannot list pods", "no rows", "connection refused", "x y", "\x1c y \x1f"]


def rstr():
    return rnd.choice(STRINGS + [f"s{rnd.randint(0, 99)}"])


def rnum():
    return rnd.choice([0, 1, -1, 2, 3, 40, 10 ** 30, 0.5, 1.0, -0.0, 0.85, 2.5e20, 1e-7, 0.1 + 0.2, 0.999, 0.005,
                       0.015, 1.5, -3.25])


def rval(depth=0):
    kinds = ["none", "bool", "num", "str"] + (["list", "dict"] if depth < 2 else [])
    k = rnd.choice(kinds)
    if k == "none":
        return None
    if k == "bool":
        return rnd.choice([True, False])
    if k == "num":
        return rnum()
    if k == "str":
        return rstr()
    if k == "list":
        return [rval(depth + 1) for _ in range(rnd.randint(0, 3))]
    return {rstr()[:8]: rval(depth + 1) for _ in range(rnd.randint(0, 3))}


def maybe(fn, p=0.8):
    return fn() if rnd.random() < p else rval()


def robj(fields):
    return maybe(lambda: {f: maybe(rstr) for f in fields if rnd.random() < 0.8})


def rlist(fn, n=4):
    return maybe(lambda: [fn() for _ in range(rnd.randint(0, n))])


SCRIPT = "#!/usr/bin/env bash\n# test\nexit 1\n"


def rscript():
    return rnd.choice([SCRIPT, "  " + SCRIPT + "\n\n", ["#!/usr/bin/env bash", "exit 0"], ["a", 1], [], "",
                       "   ", None, 5, {"a": 1}] * 8 + ["x" * 16385, "y" * 16384])


def raction():
    return maybe(lambda: {k: v for k, v in {
        "verb": rnd.choice(["patch", "create", "delete", "Patch", "x", None, 1, ["patch"]]),
        "apiVersion": rnd.choice(["apps/v1", "v1", "composition.krateo.io/v1-12-36", "Apps/v1", "v1beta1",
                                  "", None, "apps/v1\n", "observability.krateo.io/v1alpha1"]),
        "resource": rnd.choice(["deployments", "Deployments", "namespaces", "nodes", "", 5, "alerts"]),
        "name": rnd.choice(["web", "web.x", "-bad", "a" * 300, None, "web\n"]),
        "namespace": rnd.choice([None, "", "shop", "Shop", 3, "a" * 64]),
        "payload": rnd.choice([{}, None, [], {"spec": {"replicas": 2}}, {"spec": {"x": "é" * 2728}},
                               {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": "shop"}},
                               {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}},
                               {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web", "namespace": None}},
                               {"apiVersion": "v1", "kind": 3, "metadata": {"name": "web"}},
                               {"n": [1.5, 2, -0.0, 1e21, True, None]}] * 4 + [{"big": "z" * 16360}, {"big": "z" * 16370}]),
    }.items() if rnd.random() < 0.9}, p=0.85)


def rhowtofix():
    return maybe(lambda: {k: v for k, v in {
        "precondition": rscript() if rnd.random() < 0.2 else SCRIPT,
        "apply": rscript() if rnd.random() < 0.2 else SCRIPT,
        "verify": rscript() if rnd.random() < 0.2 else SCRIPT,
        "rollback": rscript(),
        "applyAction": raction(),
        "remediationPlan": rval(),
    }.items() if rnd.random() < 0.92})


def rconfidence():
    return rnd.choice([0.85, "0.9", "1", 1, 1.5, -1, "abc", True, None, " 0.3 ", "1e-3", 0.005, 0.015, 0.125,
                       "0.40", 0.4, 0.6, 0.61, 0.2, 0.19, 1e30, "inf", "-inf", "1e999"])


DENIALS = ['User "system:serviceaccount:krateo-system:krateo-alert-provider" cannot list resource "pods"',
           'pods is forbidden: User "system:serviceaccount:krateo-system:installers" cannot list resource',
           "I could not list pods: Forbidden", "we were denied", "no matching rows", "returned 0 rows",
           "timed out after 30s", "no healthy backend", "502 Bad Gateway", "all good", "", "  ",
           "unable to query clickhouse", "permission denied reading secret", "Unauthorized"]


def rretrieval():
    return rlist(lambda: maybe(lambda: {k: v for k, v in {
        "source": rnd.choice(["k8s", "logs", "metrics", "repo", "other", "K8S", "kube", "clickhouse", "git", "", None, 3]),
        "scope": rnd.choice(["pods in krateo-system", "", None, "otel_logs", "the repo"]),
        "outcome": rnd.choice(["success", "denied", "empty", "errored", "DENIED", "weird", "", None, "timeout"]),
        "detail": rnd.choice(DENIALS + [None]),
    }.items() if rnd.random() < 0.85}), n=6)


def rblock():
    keys = {
        "analyzedResources": lambda: rlist(lambda: robj(["gvr", "name", "namespace", "whatWasRead", "x"])),
        "sources": lambda: rlist(lambda: maybe(lambda: {"type": rnd.choice(["logs", "events", "metrics", "object", "LOGS", "x", None, 1]),
                                                        "ref": maybe(rstr), "excerpt": maybe(rstr)})),
        "retrieval": rretrieval,
        "missingContext": lambda: rlist(lambda: rnd.choice(DENIALS + STRINGS + [None, 3, 2.5, True])),
        "assumptions": lambda: rlist(lambda: maybe(rstr)),
        "reasoningTrace": lambda: rlist(lambda: maybe(lambda: {
            "step": rnd.choice([1, 7, None]), "statement": maybe(rstr),
            "evidenceRefs": maybe(lambda: [rnd.choice([0, 1, 2, 3, -1, 1.0, 2.0, 1.5, True, "1", None, 10 ** 20])
                                           for _ in range(rnd.randint(0, 4))])})),
        "rootCause": lambda: maybe(lambda: {k: v for k, v in {"statement": maybe(rstr, 0.9), "confidence": rconfidence(),
                                                              "category": maybe(rstr)}.items() if rnd.random() < 0.9}, 0.9),
        "howToFix": rhowtofix,
    }
    return {k: fn() for k, fn in keys.items() if rnd.random() < 0.7}


def rtext():
    blocks = []
    for _ in range(rnd.randint(0, 3)):
        lang = rnd.choice(["json", "", "yaml", "JSON", "Json", "bash"])
        body = rblock() if rnd.random() < 0.85 else rval()
        dumped = json.dumps(body, indent=rnd.choice([None, 2]), ensure_ascii=rnd.random() < 0.5)
        if rnd.random() < 0.08:
            dumped = dumped[:-1]  # malformed
        blocks.append(f"```{lang}{rnd.choice(['', ' ', ' \t'])}\n{dumped}\n```")
    prose = rnd.choice(["", "## Root cause\nthe chart is missing", "  lead  ", "text with ```inline``` fence"])
    sep = rnd.choice(["\n\n", "\n", "\r\n"])
    tail = rnd.choice(["", "\ntrailing words", "\n```\nstray fence"])
    return prose + sep + sep.join(blocks) + tail


def rledger():
    return [{"name": rnd.choice(["k8s_get_resources", "clickhouse_query", "repo_search", "metric_read", "", "  x  ",
                                 "a" * 200, "tool"]),
             "payload": rnd.choice(DENIALS * 4 + ["x" * 3000]),
             "failed": rnd.choice([True, False])} for _ in range(rnd.randint(0, 5))]


def parse_cases(n):
    out = []
    for _ in range(n):
        text, ledger = rtext(), rledger() if rnd.random() < 0.6 else None
        prose, v2 = PARSE(text, ledger)
        out.append({"text": text, "ledger": ledger, "prose": prose, "v2": jsonable(v2)})
    return out


def prompt_cases(n):
    out = []
    for _ in range(n):
        spec = {k: v for k, v in {
            "displayName": rnd.choice(["", "Krateo — x", None]), "where": rnd.choice(["", "a = 1", "Body LIKE '%x%'"]),
            "interval": rnd.choice(["", "15m", None]), "threshold": rnd.choice([1, 2, 0.5, "3"]),
            "thresholdType": rnd.choice(["", "above", "below"]), "message": rnd.choice(["", "the intent"]),
        }.items() if rnd.random() < 0.8 and v is not None}
        alert = {"metadata": {"name": "a-1", "namespace": "krateo-system"}, "spec": spec}
        incidents = []
        for i in range(rnd.randint(1, 3)):
            st = {"state": rnd.choice(["Open", "Verifying", None])}
            if rnd.random() < 0.7:
                st["rootCause"] = {"statement": rnd.choice(["cause", "c" * 1200, ""])}
            if rnd.random() < 0.4:
                st["report"] = rnd.choice(["the report", "  "])
            if rnd.random() < 0.6:
                st["howToFix"] = {s: rnd.choice([SCRIPT, "", "  ", "z" * 1600]) for s in ("precondition", "apply", "verify")
                                  if rnd.random() < 0.8}
            st = {k: v for k, v in st.items() if v is not None}
            inc = {"metadata": {"name": f"a-1-{i}"}, "status": st}
            if rnd.random() < 0.8:
                inc["metadata"]["creationTimestamp"] = f"2026-09-25T10:0{i}:00Z"
            incidents.append(inc)
        rows = [(rnd.choice(["Pod a/b: BackOff", "svc ns/pod", "r" * 400, ""]), rnd.randint(1, 9))
                for _ in range(rnd.choice([0, 1, 3, 25]))]
        out.append({"alert": alert, "incidents": incidents, "rows": jsonable(rows),
                    "prompt": PROMPT(alert, incidents, rows)})
    return out


def verdict_cases():
    names = ["a", "b", "c"]
    texts = ['{"match": 1, "reason": "r"}', '{"match": null, "reason": "  r  "}', '{"match": 0}', '{"match": 4}',
             '{"match": 1.0}', '{"match": true}', '{"match": "1"}', '{"reason": "x"}', "no json",
             '```json\n{"match": 2, "reason": "x"}\n```\nthen ```\n{"match": 3}\n```',
             '```\n{"match": 2}\n```', '```json\n{"match": 9}\n```\n{"match": 1}', "",
             '{"match": 1, "reason": 5}', '{"match": 1, "reason": ' + json.dumps("r" * 400) + '}',
             '{"match": -0}', '{"match": 2, "reason": null}', '[1]', '```json\r\n{"match": 1}\r\n```',
             '{"match": 3, "reason": "x"} trailing']
    return [verdict_case(t, names) for t in texts]


def tautology_cases():
    out = []
    for th in [0, 1, -1, 0.0, -0.5, 0.5, 2, "0", "1", "abc", None, " 2 ", "-1", 10 ** 30, "1e3", True]:
        for tt in ["above", "below", "below_or_equal", "ABOVE", "", None, "equal"]:
            out.append({"threshold": th, "thresholdType": tt,
                        "why": reconciler.tautology(th, tt) or ""})
    return out


def drift_cases():
    h = hyperdx_v2.HyperDXV2("http://x", "k")
    out = []
    for _ in range(300):
        live = {k: v for k, v in {
            "name": rnd.choice(["a-1", "Krateo — x", None]), "interval": rnd.choice(["5m", "15m", None]),
            "threshold": rnd.choice([1, 2, 1.0, "1", None, 0.5]),
            "thresholdType": rnd.choice(["above", "below", None]),
            "message": rnd.choice(["m", "", "a-1 threshold crossed — incident-agent will auto-triage.", None]),
        }.items() if rnd.random() < 0.9}
        want = {"interval": rnd.choice(["5m", "15m"]), "threshold": rnd.choice([1, 2, 1.0, "1", 0.5]),
                "threshold_type": rnd.choice(["above", "below"]), "message": rnd.choice(["m", ""])}
        out.append({"live": live, "name": "a-1", "want": want,
                    "drift": sorted(h.alert_drift(live, name="a-1", **want))})
    return out


def pyfmt_cases():
    floats = [0.1, 0.5, 1.0, 1e16, 1e15, 123456789012345678.0, 1e-4, 1e-5, 0.0001234, -0.0, 2.5e-7, 1.7976931348623157e308,
              5e-324, 100.0, 0.1 + 0.2, 1 / 3, 2 / 3, 1e21, 12345.678]
    floats += [rnd.uniform(-1e6, 1e6) for _ in range(100)] + [rnd.random() * 10 ** rnd.randint(-10, 25) for _ in range(100)]
    values = [rval() for _ in range(300)]
    strips = [rstr() for _ in range(50)] + ["  x　 ", "\x1cx\x1d", "​x​", "\x85x"]
    return {"floats": [{"f": f, "repr": repr(f)} for f in floats],
            "dumps": [{"v": v, "dumps": json.dumps(v, sort_keys=True), "str": str(v) if not isinstance(v, (list, dict)) else None}
                      for v in values],
            "strip": [{"s": s, "strip": s.strip()} for s in strips]}


def dedupe(cases, key):
    seen, out = set(), []
    for c in cases:
        k = json.dumps(c[key], sort_keys=True) if not isinstance(c[key], str) else c[key]
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def a2a_cases():
    """Streams replayed through handler.a2a_analyze: the two runtimes' real RCAs, as the Python
    tests replay them, and synthetic snapshot, delta and noise streams."""
    from unittest import mock
    import test_tool_ledger as ttl

    def sse(msg, where="status"):
        result = {"kind": "status-update", "status": {"state": "working", "message": msg}} if where == "status" \
            else {"kind": "message", **msg} if where == "flat" else {"message": msg}
        return "data: " + json.dumps({"jsonrpc": "2.0", "id": 1, "result": result})

    def agent(*texts, parts=()):
        return {"role": "agent", "parts": [{"kind": "text", "text": t} for t in texts] + list(parts)}

    streams = [ttl._Stream(ttl.PYTHON_TASK).lines, ttl._Stream(ttl.GO_TASK).lines]
    tool = {"kind": "data", "metadata": {"kagent_type": "function_response"},
            "data": {"name": "k8s_get", "response": {"content": [{"type": "text", "text": "pods is forbidden"}], "isError": True}}}
    streams += [
        [sse(agent("Hel")), sse(agent("Hello")), sse(agent("Hello world")), sse(agent("Hello world"))],
        [sse(agent("a")), sse(agent("b")), sse(agent("c")), sse(agent("c"))],
        ["", "event: message", ": comment", "data: not json", "data:" + json.dumps({"result": None}),
         sse({"role": "user", "parts": [{"kind": "text", "text": "the prompt"}]}),
         sse(agent("  answer  ", parts=[tool])), sse(agent(parts=[tool])),
         sse(agent("more"), where="message"), sse(agent(" tail"), where="flat")],
        [sse(agent("x", "y")), sse(agent("xy", parts=[tool, tool]))],
    ]
    out = []
    for lines in streams:
        stream = ttl._Stream({"id": "t", "contextId": "c", "history": []})
        stream.lines = lines
        with mock.patch.object(handler.requests, "post", return_value=stream), \
             mock.patch.object(handler, "_service_jwt", return_value=""):
            text, ledger = handler.a2a_analyze("prompt", "ctx")
        out.append({"lines": lines, "text": text, "ledger": ledger})
    return out


def write(path, data):
    path = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"
    with open(path, "wb") as f:
        f.write(gzip.compress(text.encode(), mtime=0) if path.endswith(".gz") else text.encode())
    print(f"{path}: {len(data) if isinstance(data, list) else sum(len(v) for v in data.values())} cases")


if __name__ == "__main__":
    code = pytest.main(["-q", "-p", "no:cacheprovider", os.path.join(PY, "tests")], plugins=[Harvest()])
    if code != 0:
        sys.exit(f"the Python test suite failed ({code})")
    # The outputs are recomputed outside the suite: some tests patch the code under test.
    harvested = dedupe([dict(c, key=[c["text"], c["ledger"]]) for c in recorded["parse"]], "key")
    for c in harvested:
        prose, v2 = PARSE(c["text"], c["ledger"])
        c.update(prose=prose, v2=jsonable(v2))
    write("internal/report/testdata/parse.json.gz", [{k: v for k, v in c.items() if k != "key"} for c in harvested]
          + parse_cases(1500))
    write("internal/compare/testdata/prompt.json.gz", recorded["prompt"] + prompt_cases(300))
    write("internal/compare/testdata/verdict.json", verdict_cases())
    for c in recorded["rca_prompt"]:
        c["prompt"] = RCA_PROMPT(*c["args"])
    for c in recorded["tool_results"]:
        c["results"] = jsonable(TOOL_RESULTS(c["parts"]))
    write("internal/incident/testdata/rca_prompt.json", dedupe(recorded["rca_prompt"], "args") + [
        {"args": a, "prompt": RCA_PROMPT(*a)} for a in
        [["x", "ALERT", None, None], ["Krateo — y", "ALERT", "a = 1", ""], ["z", "OK", "w", "intent"], ["z", "ALERT", "", "m"]]])
    write("internal/incident/testdata/tool_results.json", dedupe(recorded["tool_results"], "parts"))
    write("internal/incident/testdata/a2a.json.gz", a2a_cases())
    write("internal/controllers/alert/testdata/tautology.json", tautology_cases())
    write("internal/hyperdx/testdata/drift.json", drift_cases())
    write("internal/pyfmt/testdata/pyfmt.json", [pyfmt_cases()])

#!/usr/bin/env python3
"""krateo-alert-provider — turns a firing alert into Incidents, each with a root-cause analysis.

The reconciler mirrors every Alert's HyperDX state about every 60 s and calls fire() for each one
that is ALERT. fire() counts the firing on an incident that covers it (see _pick) or opens a new
one: it creates the Incident in state Analyzing, runs the incident-agent RCA over A2A, and writes
the analysis with its howToFix scripts in state Open. An alert therefore has any number of
incidents, one per problem. From Open on, the incident controller runs the scripts and moves the
Incident. Stdlib + requests.
"""
import base64
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import requests

import compare  # the incident-comparison contract: prompt + verdict parser
import report_v2  # the structured-report contract: prompt instructions + defensive parser

# --- config (env, with in-cluster defaults) ---
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
AUTOPILOT_A2A = os.environ.get("AUTOPILOT_A2A_URL", "http://incident-agent.krateo-system.svc:8080/")
APISERVER = os.environ.get("APISERVER", "https://kubernetes.default.svc")
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
GROUP, VERSION = "observability.krateo.io", "v1alpha1"
A2A_TIMEOUT = int(os.environ.get("A2A_TIMEOUT", "180"))
# The agent that judges whether a firing is the problem an open incident describes (compare.py).
COMPARE_A2A = os.environ.get("COMPARE_A2A_URL", "http://autopilot.krateo-system.svc:8080/")
COMPARE_TIMEOUT = int(os.environ.get("COMPARE_TIMEOUT", "120"))
# Sent on every comparison call. agentgateway-policies routes requests carrying it to its
# incident-compare route, whose rate limit bounds these calls (a 429 is no verdict).
COMPARE_HEADERS = {"X-Krateo-Purpose": "incident-compare"}

# The Incident contract (incident-controller apis/incident/v1alpha1).
LABEL_ALERT = "observability.krateo.io/alert"  # value: the Alert's metadata.name, so at most 63 chars
ENDED = ("Resolved", "Closed")                 # an incident in any other state is open
WRITE_ATTEMPTS = 5                             # conditioned status writes retried on a 409

# Alert spec.interval: the lookback window HyperDX counts the `where` rows over.
INTERVAL_SECONDS = {"1m": 60, "5m": 300, "15m": 900, "30m": 1800, "1h": 3600,
                    "6h": 21600, "12h": 43200, "1d": 86400}


def interval_seconds(interval):
    """spec.interval in seconds; 5m when unset or unknown."""
    return INTERVAL_SECONDS.get(interval, 300)

# Intra-service auth (Option A). The alert->RCA pipeline is autonomous — it carries NO user JWT —
# but incident-agent's MCP tools sit behind agentgateway, whose authz allows /mcp only with a valid
# Krateo JWT (`has(jwt.sub)`). So we mint a SERVICE identity: exchange this pod's projected
# ServiceAccount token (audience "authn") at authn's /serviceaccount/login for a Krateo JWT, and
# present it on the A2A call — incident-agent (KAGENT_PROPAGATE_TOKEN=true) then propagates it to the
# gateway on the MCP tool calls. Fully OPT-IN and graceful: with no AUTHN_URL / no projected token
# mounted (older clusters, no gateway) the exchange is skipped and the A2A call goes unauthenticated
# exactly as before. Enable by setting AUTHN_URL and mounting an audience-"authn" projected token at
# AUTHN_TOKEN_FILE (a serviceAccountToken projected volume, expirationSeconds ~600).
AUTHN_URL = os.environ.get("AUTHN_URL", "").rstrip("/")
AUTHN_TOKEN_FILE = os.environ.get("AUTHN_TOKEN_FILE", "/var/run/secrets/authn/token")

_firing = set()                  # (namespace, alert) pairs with an evaluation in progress
_firing_lock = threading.Lock()
_jwt_cache = {"token": "", "exp": 0.0}
_jwt_lock = threading.Lock()  # serialize the token exchange so concurrent fires reuse one JWT


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sa_token():
    with open(f"{SA_DIR}/token") as f:
        return f.read().strip()


def _service_jwt():
    """Exchange this pod's projected SA token (audience "authn") for a Krateo JWT via authn's
    `serviceaccount` login strategy; cache it until shortly before its own expiry. Returns "" when
    the projected token / AUTHN_URL are absent OR the exchange fails — the A2A call then proceeds
    unauthenticated, exactly as before (never break the RCA on an auth hiccup)."""
    if not AUTHN_URL or not os.path.exists(AUTHN_TOKEN_FILE):
        return ""
    with _jwt_lock:
        if _jwt_cache["token"] and time.time() < _jwt_cache["exp"] - 60:
            return _jwt_cache["token"]
        try:
            with open(AUTHN_TOKEN_FILE) as f:
                sa_tok = f.read().strip()
            r = requests.post(f"{AUTHN_URL}/serviceaccount/login",
                              headers={"Authorization": f"Bearer {sa_tok}"}, timeout=15)
            r.raise_for_status()
            jwt = (r.json() or {}).get("accessToken") or ""
            if not jwt:
                raise ValueError("authn response had no accessToken")
            # Cache until the JWT's own `exp` (decode the base64url payload; pad to a multiple of 4).
            seg = jwt.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
            _jwt_cache.update(token=jwt, exp=float(claims.get("exp") or (time.time() + 300)))
            return jwt
        except Exception as e:  # degrade to no JWT; each caller decides what that means
            print(f"[authn] service-JWT exchange failed ({e}); continuing without a JWT", flush=True)
            return ""


def _k8s(method, path, body=None, subresource=""):
    """Call the apiserver with the mounted SA token."""
    url = f"{APISERVER}{path}"
    if subresource:
        url += f"/{subresource}"
    headers = {"Authorization": f"Bearer {_sa_token()}", "Content-Type": "application/json"}
    if method == "PATCH":
        headers["Content-Type"] = "application/merge-patch+json"
    r = requests.request(method, url, headers=headers, data=json.dumps(body) if body else None,
                         verify=f"{SA_DIR}/ca.crt", timeout=30)
    r.raise_for_status()
    return r.json()


def _http_status(e):
    return getattr(getattr(e, "response", None), "status_code", None)


def _incidents(ns, name=""):
    path = f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/incidents"
    return f"{path}/{name}" if name else path


def incident_name(alert_ref, at):
    """`<alert>-<yyyymmdd-hhmmss>` of the opening firing, in UTC."""
    return f"{alert_ref}-{at.strftime('%Y%m%d-%H%M%S')}"


def _context_id(name):
    """The incident's own kagent thread: every RCA starts from an empty conversation."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))


def _newest(items):
    return max(items, default=None,
               key=lambda i: (i["metadata"].get("creationTimestamp", ""), i["metadata"]["name"]))


def _resolved_at(incident):
    at = ((incident.get("status") or {}).get("resolution") or {}).get("at")
    try:
        return datetime.fromisoformat(str(at).replace("Z", "+00:00")) if at else None
    except ValueError:
        return None


def resolved_within(incident, at, grace):
    """Whether `incident` is Resolved less than `grace` seconds before `at`."""
    if (incident.get("status") or {}).get("state") != "Resolved":
        return False
    resolved = _resolved_at(incident)
    return bool(resolved) and (at - resolved).total_seconds() < grace


def _alert_incidents(ns, alert_ref):
    selector = quote(f"{LABEL_ALERT}={alert_ref}", safe="")
    return _k8s("GET", f"{_incidents(ns)}?labelSelector={selector}").get("items") or []


def _pick(alert, items, at, grace):
    """The incident a firing at `at` counts on, or None to open a new one.

    In order:
      1. the first open incident (any state but Resolved and Closed) with an analysis that the
         comparison agent judges the same problem, newest first;
      2. the newest open incident without an analysis (Analyzing, or its RCA failed): there is
         nothing to compare with, and a new incident would rerun the analysis;
      3. the alert's latest incident when it is Resolved less than `grace` seconds (one
         spec.interval) ago: a `where` alert keeps counting rows from before the fix for its
         lookback window, and those belong to the incident the fix resolved. A Closed incident
         never takes a firing.
    Raises compare.NoVerdict when a comparison gave no verdict and nothing above covers the
    firing: whether it is a new problem is then unknown, so nothing opens."""
    ns, alert_ref = alert["metadata"].get("namespace") or NAMESPACE, alert["metadata"]["name"]
    open_ = sorted((i for i in items if (i.get("status") or {}).get("state") not in ENDED),
                   key=lambda i: (i["metadata"].get("creationTimestamp", ""), i["metadata"]["name"]),
                   reverse=True)
    failed = None
    for incident in (i for i in open_ if compare.comparable(i)):
        name = incident["metadata"]["name"]
        try:
            equal, reason = a2a_compare(compare.build_prompt(alert, incident, at.isoformat()))
        except compare.NoVerdict as e:
            print(f"[compare] {ns}/{alert_ref} vs {name}: no verdict ({e})", flush=True)
            failed = e
            continue
        print(f"[compare] {ns}/{alert_ref} vs {name}: {'equal' if equal else 'different'} "
              f"({reason})", flush=True)
        if equal:
            return incident
    unanalyzed = [i for i in open_ if not compare.comparable(i)]
    if unanalyzed:
        return unanalyzed[0]
    latest = _newest(items)
    if latest is not None and resolved_within(latest, at, grace):
        return latest
    if failed is not None:
        raise failed
    return None


def _patch_status(ns, incident, status):
    """Merge `status` into the Incident's status, conditioned on the resourceVersion it was read
    at: the controller writes the same status, so a 409 means re-read and retry."""
    body = {"metadata": {"resourceVersion": incident["metadata"]["resourceVersion"]},
            "status": status}
    return _k8s("PATCH", _incidents(ns, incident["metadata"]["name"]), body, subresource="status")


def _count_on(ns, name, now):
    """firings++ and lastFiredAt on incident `name`, and nothing else, re-read on a lost race."""
    for _ in range(WRITE_ATTEMPTS):
        incident = _k8s("GET", _incidents(ns, name))
        st = incident.get("status") or {}
        try:
            _patch_status(ns, incident, {"firings": int(st.get("firings") or 0) + 1,
                                         "lastFiredAt": now})
        except requests.HTTPError as e:
            if _http_status(e) == 409:
                continue
            raise
        print(f"[incident] {ns}/{name}: firing counted ({st.get('state') or 'new'})", flush=True)
        return
    raise RuntimeError(f"incident {ns}/{name}: no firing write succeeded in {WRITE_ATTEMPTS} attempts")


def _open_or_count(ns, alert, prompt, at, grace):
    """One firing: count it on the incident _pick chooses, or create one.

    Returns the new Incident, or None when the firing was counted on an existing one."""
    alert_ref = alert["metadata"]["name"]
    now = at.isoformat()
    target = _pick(alert, _alert_incidents(ns, alert_ref), at, grace)
    if target is not None:
        _count_on(ns, target["metadata"]["name"], now)
        return None
    name = incident_name(alert_ref, at)
    body = {"apiVersion": f"{GROUP}/{VERSION}", "kind": "Incident",
            "metadata": {"name": name, "namespace": ns, "labels": {LABEL_ALERT: alert_ref}},
            "spec": {"alertRef": {"name": alert_ref, "namespace": ns}, "trigger": "alert",
                     "prompt": prompt, "triggeredAt": now}}
    try:
        created = _k8s("POST", _incidents(ns), body)
    except requests.HTTPError as e:
        if _http_status(e) != 409:
            raise
        _count_on(ns, name, now)  # a concurrent firing created it this second
        return None
    # Unconditioned: the controller may already have touched the new object, and no other
    # writer sets these fields yet.
    _k8s("PATCH", _incidents(ns, name),
         {"status": {"state": "Analyzing", "firings": 1, "lastFiredAt": now}},
         subresource="status")
    print(f"[incident] {ns}/{name}: opened", flush=True)
    return created


def _finish(ns, name, status):
    """Write the analysis. An incident still Analyzing becomes Open; in any other state (a human
    closed it, or applied a fix, while it was analyzing) the analysis is written without a state,
    since Closed is final and the controller owns the rest."""
    for _ in range(WRITE_ATTEMPTS):
        incident = _k8s("GET", _incidents(ns, name))
        body = dict(status)
        if (incident.get("status") or {}).get("state") in (None, "Analyzing"):
            body["state"] = "Open"
        try:
            _patch_status(ns, incident, body)
            return
        except requests.HTTPError as e:
            if _http_status(e) != 409:
                raise
    raise RuntimeError(f"incident {ns}/{name}: no status write succeeded in {WRITE_ATTEMPTS} attempts")


INTERRUPTED = "The analysis was interrupted: the alert-provider restarted before it finished."


def recover_interrupted(ns=NAMESPACE):
    """Open every incident a restart left Analyzing (or before its first status write), with the
    reason in `error`.

    An Analyzing incident takes every firing of its alert that no analyzed incident covers, and is
    never checked. Open with `error`, it says why it has no scripts and can be closed, and the next
    firing then opens a fresh one. An analysis still running in another replica overwrites `error`
    when it finishes."""
    try:
        items = _k8s("GET", f"{_incidents(ns)}?labelSelector={quote(LABEL_ALERT, safe='')}")
    except Exception as e:  # noqa: BLE001 — no Incident CRD yet, or no apiserver: nothing to recover
        print(f"[incident] recovery skipped ({e})", flush=True)
        return
    for incident in items.get("items") or []:
        if (incident.get("status") or {}).get("state") not in (None, "Analyzing"):
            continue
        try:
            _patch_status(ns, incident, {"state": "Open", "error": INTERRUPTED})
            print(f"[incident] {ns}/{incident['metadata']['name']}: interrupted, opened", flush=True)
        except Exception as e:  # noqa: BLE001 — a 409 means another writer moved it
            print(f"[incident] {ns}/{incident['metadata']['name']}: recovery skipped ({e})",
                  flush=True)


def _part_type(part):
    """A DataPart's ADK type (`function_call`, `function_response`, …). Both kagent runtimes put it
    in the part's METADATA, not its data: the Go runtime as `adk_type`, the Python one as
    `kagent_type`."""
    meta = part.get("metadata")
    if not isinstance(meta, dict):
        return ""
    return str(meta.get("adk_type") or meta.get("kagent_type") or "")


def _result_text(resp):
    """The text a tool returned. The Go runtime wraps it as `{output}` or `{error}`; the Python
    runtime passes the MCP result through as `{content: [{type, text}], isError}`."""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        content = resp.get("content")
        if isinstance(content, list):
            texts = [c["text"] for c in content
                     if isinstance(c, dict) and isinstance(c.get("text"), str)]
            if texts:
                return "\n".join(texts)
        for key in ("error", "output", "result"):
            value = resp.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, dict):
                return _result_text(value)
    return json.dumps(resp, default=str)


def _tool_results(parts):
    """Every tool RESULT in one A2A message, as report_v2's ledger entry shape.

    THE SHAPE IS report_v2._from_tool_ledger's CONTRACT — `name`, `payload`, `failed` — and it is
    written here to match, not approximated.

    kagent mirrors every non-partial ADK event onto the status stream, so each tool result arrives
    as a DataPart typed `function_response` (see _part_type) whose data is the GenAI
    FunctionResponse, `{id, name, response}`. This is the ground truth report_v2 bounds confidence
    by (#30).

    Defensive by construction: kagent's exact part shape has changed before and this must never be
    the reason an analysis fails. Anything unrecognised yields nothing and the report degrades to
    model-declared retrieval."""
    out = []
    for p in parts or []:
        if not isinstance(p, dict):
            continue
        data = p.get("data")
        if not isinstance(data, dict) or _part_type(p) != "function_response":
            continue
        resp = data.get("response")
        # `failed` says the CALL errored, which is what lets report_v2 tell a refusal we suffered
        # from a refusal we are REPORTING. The runtimes flag it differently (`error` vs `isError`);
        # the text classifier settles denied-vs-errored.
        failed = bool(isinstance(resp, dict) and (resp.get("error") or resp.get("isError")))
        out.append({"name": str(data.get("name") or ""), "payload": _result_text(resp),
                    "failed": failed})
    return out


def a2a_analyze(prompt, context_id=None):
    """(text, tool_ledger) from the RCA agent (AUTOPILOT_A2A_URL, incident-agent).

    `context_id` names the kagent thread, the incident's own (omitted = a fresh thread). `tool_ledger` is what the agent's tools ACTUALLY returned; report_v2 uses it
    to bound confidence rather than trusting the model's account of its own evidence (#30)."""
    return _a2a(AUTOPILOT_A2A, prompt, context_id=context_id, timeout=A2A_TIMEOUT)


def a2a_compare(prompt):
    """(equal, reason) from the comparison agent (COMPARE_A2A_URL, autopilot).

    Each call is a fresh kagent thread, so a verdict rests on its prompt alone. Raises
    compare.NoVerdict on any failure, a 429 from the gateway's incident-compare limit included."""
    try:
        text, _ = _a2a(COMPARE_A2A, prompt, timeout=COMPARE_TIMEOUT, headers=COMPARE_HEADERS)
    except requests.HTTPError as e:
        if _http_status(e) == 429:
            raise compare.NoVerdict("rate-limited") from e
        raise compare.NoVerdict(f"the call failed: {str(e)[:200]}") from e
    except Exception as e:  # noqa: BLE001 — a timeout or a broken stream is no verdict either
        raise compare.NoVerdict(f"the call failed: {str(e)[:200]}") from e
    return compare.parse_verdict(text)


def _a2a(url, prompt, context_id=None, timeout=A2A_TIMEOUT, headers=None):
    """(text, tool_ledger) of one A2A `message/stream` call to `url`."""
    message = {"kind": "message", "messageId": str(uuid.uuid4()), "role": "user",
               "parts": [{"kind": "text", "text": prompt}]}
    if context_id:
        message["contextId"] = context_id
    body = {"id": 1, "jsonrpc": "2.0", "method": "message/stream", "params": {"message": message}}
    out = ""
    ledger, seen = [], set()
    headers = {"Accept": "text/event-stream", "Content-Type": "application/json", **(headers or {})}
    # The service JWT: the agentgateway authenticates it, and the agent propagates it to its gated
    # MCP tools and sub-agents.
    jwt = _service_jwt()
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    with requests.post(url, json=body, stream=True, timeout=timeout, headers=headers) as resp:
        resp.raise_for_status()
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("data:"):
                continue
            try:
                payload = json.loads(raw[len("data:"):].strip())
            except json.JSONDecodeError:
                continue
            result = payload.get("result") or {}
            msg = result.get("status", {}).get("message") or result.get("message") or {}
            if msg.get("role") != "agent":
                continue
            parts = msg.get("parts", [])
            # Collected BEFORE the `if not text: continue` below: a message carrying only tool
            # results has no text at all, and those are the very events that record a denial.
            # The stream re-sends cumulative snapshots, so de-duplicate by (name, payload).
            for tr in _tool_results(parts):
                key = (tr["name"], tr["payload"])
                if key not in seen:
                    seen.add(key)
                    ledger.append(tr)
            text = "".join(p["text"] for p in parts
                           if p.get("kind") == "text" and p.get("text"))
            if not text:
                continue
            # kagent's A2A stream re-sends cumulative snapshots of the message (and repeats the
            # final one), so blindly appending every event duplicated the whole report. Replace
            # when the new text extends what we already have (a snapshot), skip an exact-duplicate
            # tail, else append (a genuine delta) — correct for snapshot-, delta-, and repeat streams.
            if text.startswith(out):
                out = text
            elif not out.endswith(text):
                out += text
    return out.strip(), ledger


def build_prompt(alert_name, alert_state, where=None, message=None):
    """The user message carries the INCIDENT; the agent's system prompt carries the METHOD.

    THE COUPLING THIS CREATES: the method lives in ONE place, so AUTOPILOT_A2A_URL must point at an
    agent whose prompt carries it (incident-agent does; a bare generalist does not). Point this at a
    different agent and you must put the method back.
    """
    scope = ""
    if where:
        scope = (
            f"\n\nIt fired on log records matching `{where}`"
            + (f" — intent: {message}" if message else "")
            + ". That query is your entry point, and the workload those rows name is what you "
            "diagnose."
        )
    return (
        f'The HyperDX alert "{alert_name}" has fired (state {alert_state}) on this Krateo '
        "PlatformOps cluster." + scope +
        "\n\nRoot-cause it: the single most likely cause, the composition or component affected, "
        "and how to fix it."
        + report_v2.STRUCTURED_OUTPUT_INSTRUCTIONS
    )


def process(payload):
    """A HyperDX notification. It opens nothing: the reconciler mirrors every alert's state on
    each pass and evaluates the firing ones (fire), so a notification would only fire twice. The
    webhook exists because a HyperDX alert needs a channel; the body is
    hyperdx_v2.DEFAULT_WEBHOOK_BODY."""
    title = (payload.get("alertName") or payload.get("title") or payload.get("name")
             or (payload.get("alert") or {}).get("name") or "")
    state = str(payload.get("state") or payload.get("status") or "").upper()
    print(f"[webhook] {title!r} {state or '?'}: the reconciler evaluates it on its next pass",
          flush=True)


def fire(alert):
    """One evaluation of a firing Alert CR, from the reconciler's pass (about every 60 s).

    The firing counts on the incident _pick chooses, or opens a new one whose RCA then runs in
    this call. `alert` is the CR: its metadata.name keys the incidents and their label, its
    namespace holds them, spec.interval is the Resolved grace window. One evaluation per alert
    runs at a time: while one is still comparing, the alert's next firing is skipped."""
    meta, spec = alert.get("metadata") or {}, alert.get("spec") or {}
    alert_ref = meta.get("name", "")
    ns = meta.get("namespace") or NAMESPACE
    if len(alert_ref) > 63:
        print(f"[incident] alert {alert_ref!r}: a name over 63 characters cannot label an "
              "Incident; skipping", flush=True)
        return
    key = (ns, alert_ref)
    with _firing_lock:
        if key in _firing:
            print(f"[incident] alert {ns}/{alert_ref}: the previous evaluation is still running; "
                  "skipping this firing", flush=True)
            return
        _firing.add(key)
    alert = {**alert, "metadata": {**meta, "namespace": ns}}
    prompt = build_prompt(spec.get("displayName") or alert_ref, "ALERT", spec.get("where"),
                          spec.get("message"))
    try:
        created = _open_or_count(ns, alert, prompt, datetime.now(timezone.utc),
                                 interval_seconds(spec.get("interval")))
    except compare.NoVerdict as e:
        print(f"[incident] alert {ns}/{alert_ref}: no comparison verdict ({e}); the next pass "
              "retries", flush=True)
        return
    except Exception as e:  # noqa: BLE001 — a failed write loses this firing, not the next one
        print(f"[err] alert {ns}/{alert_ref}: firing not recorded ({e})", flush=True)
        return
    finally:
        with _firing_lock:
            _firing.discard(key)
    if created is not None:
        run_analysis(ns, created["metadata"]["name"], prompt)


def run_analysis(ns, name, prompt):
    """The RCA of a new incident, then its one status write: the analysis and state Open.

    `error` says why an incident has no howToFix: the call failed, the answer was empty or
    unstructured, or its scripts were unusable. It is cleared when howToFix is written."""
    status = {}
    try:
        raw, tool_ledger = a2a_analyze(prompt, _context_id(name))
        print(f"[a2a] {ns}/{name}: {len(raw)} chars, {len(tool_ledger)} tool results", flush=True)
        prose, v2 = report_v2.parse_structured_report(raw, tool_ledger)
        if prose.strip():
            status["report"] = prose
        status.update({k: v2[k] for k in report_v2.V2_STATUS_KEYS if k in v2})
        if "howToFix" in v2:
            status["error"] = None
        elif not prose.strip() and not v2:
            status["error"] = "The analysis returned no output."
        elif not v2:
            status["error"] = ("The analysis returned no structured block, so the incident has no "
                               "scripts to check or fix it.")
        else:
            status["error"] = ("The analysis returned no usable howToFix, so the incident has no "
                               "scripts to check or fix it.")
    except Exception as e:  # noqa: BLE001 — a failed RCA still opens the incident
        status["error"] = f"The analysis failed: {str(e)[:500]}"
    status["completedAt"] = _now()
    try:
        _finish(ns, name, status)
        print(f"[ok] incident {ns}/{name}: analysis written "
              f"(howToFix={'yes' if status.get('howToFix') else 'no'})", flush=True)
    except Exception as e:  # noqa: BLE001 — recover_interrupted opens it after a restart
        print(f"[err] incident {ns}/{name}: analysis not written ({e})", flush=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # health
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()
        self.wfile.write(b"ok" if self.path == "/healthz" else b"")

    def do_POST(self):
        # Accept any POST path as a webhook: HyperDX redacts the webhook URL path to `/****` in
        # its API and may deliver to a redacted/normalised path, so we don't gate on "/webhook".
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {"raw": raw.decode("utf-8", "replace")}
        process(payload)
        self.send_response(202); self.end_headers(); self.wfile.write(b"accepted")

    def log_message(self, *args):  # quieter logs
        pass


if __name__ == "__main__":
    # Before any firing can open an incident, so only incidents a previous process left are swept.
    recover_interrupted()
    # Background: reconcile Alert CRs -> HyperDX (config + status) and fire the firing ones.
    if os.environ.get("RECONCILER_ENABLED", "true").lower() == "true":
        import reconciler  # imported here so the webhook path has no hard dep on it
        threading.Thread(target=reconciler.run_forever, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"krateo-alert-provider listening on :{port} → RCA {AUTOPILOT_A2A}, compare "
          f"{COMPARE_A2A}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()

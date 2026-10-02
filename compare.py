"""The incident comparison: which open Incident of an alert, if any, covers the alert's firing now?

handler.fire asks it once per firing (about every 60 s while an alert fires), in one LLM call over
all the alert's open, analyzed incidents. This module owns both sides of that exchange so they
cannot drift:
  * SYSTEM and build_prompt(alert, incidents, rows) — the alert, the records it matches now, and
    each incident's root cause and howToFix scripts;
  * parse_verdict(text, names) — the answer's {"match": <incident number> | null, "reason": str}
    object, or NoVerdict.

Incidents are numbered in the prompt, not named: the gateway's PhoneNumber guard masks the
timestamp in an incident's name, so the model could not repeat it.

Stdlib only (json/os/re), unit-testable without the cluster.
"""
import json
import os
import re

# Newest open incidents compared; older ones never take a firing through the comparison.
MAX_CANDIDATES = max(1, int(os.environ.get("MAX_COMPARE_CANDIDATES", "50")))
MAX_ROWS = 20         # record groups quoted, the most frequent first
ROW_CHARS = 300
DESCRIPTION_CHARS = 1000
SCRIPT_CHARS = 1500
REASON_CHARS = 300
SCRIPTS = ("precondition", "apply", "verify")

# One HyperDX groupBy expression: a line per distinct record, naming its object. A k8s event names
# its involvedObject, reason and message; any other log only its service and pod, so the groups
# stay as few as the pods. HyperDX nulls a group whose expression holds `[` or `=`, hence
# arrayElement and equals.
ROW_GROUP = (
    "if(equals(arrayElement(ResourceAttributes, 'telemetry.source'), 'k8s-events'), "
    "concat(JSONExtractString(Body, 'object', 'involvedObject', 'kind'), ' ', "
    "JSONExtractString(Body, 'object', 'involvedObject', 'namespace'), '/', "
    "JSONExtractString(Body, 'object', 'involvedObject', 'name'), ': ', "
    "JSONExtractString(Body, 'object', 'reason'), ' ', "
    "JSONExtractString(Body, 'object', 'message')), "
    "concat(ServiceName, ' ', arrayElement(ResourceAttributes, 'k8s.namespace.name'), '/', "
    "arrayElement(ResourceAttributes, 'k8s.pod.name')))")

SYSTEM = ("You deduplicate incidents of a Kubernetes platform's alerts. Given the log records an "
          "alert matches now and its open incidents, name the incident whose root cause produces "
          "those records, or none.")


class NoVerdict(Exception):
    """No usable answer: the call failed or was rate-limited, or it carried no verdict object."""


def comparable(incident):
    """Whether an open incident has an analysis to compare a firing with: a root cause, or a report
    from an analysis that did not fail. An incident still Analyzing has neither, and a failed one
    (`error` set, no root cause) holds at most the failure's text in `report`."""
    st = incident.get("status") or {}
    if st.get("state") == "Analyzing":
        return False
    if (st.get("rootCause") or {}).get("statement"):
        return True
    return not st.get("error") and bool((st.get("report") or "").strip())


def _cut(text, limit):
    text = str(text or "").strip()
    return text if len(text) <= limit else text[:limit] + " …(truncated)"


def _incident(number, incident):
    meta, st = incident.get("metadata") or {}, incident.get("status") or {}
    rc = st.get("rootCause") or {}
    lines = [f"### Incident {number} ({st.get('state', '?')}, opened "
             f"{meta.get('creationTimestamp', '?')})",
             f"Root cause: {_cut(rc.get('statement') or st.get('report'), DESCRIPTION_CHARS)}"]
    how = st.get("howToFix") or {}
    for script in SCRIPTS:
        if (how.get(script) or "").strip():
            lines.append(f"{script}:\n```bash\n{_cut(how[script], SCRIPT_CHARS)}\n```")
    return "\n".join(lines)


def _rows(rows):
    if not rows:
        return "No record matches now."
    lines = [f"- {count}× {_cut(text, ROW_CHARS)}" for text, count in rows[:MAX_ROWS]]
    if len(rows) > MAX_ROWS:
        lines.append(f"- … and {len(rows) - MAX_ROWS} more distinct records")
    return "\n".join(lines)


def build_prompt(alert, incidents, rows):
    """The user message for one firing: `incidents` are the open, analyzed ones, newest first;
    `rows` are (record, count) pairs, the most frequent first. Generic: one prompt serves every
    alert."""
    meta, spec = alert.get("metadata") or {}, alert.get("spec") or {}
    intent = f" Its intent: {spec['message']}." if spec.get("message") else ""
    return (
        f'Alert "{spec.get("displayName") or meta.get("name", "?")}" counts the log records '
        f"matching `{spec.get('where', '')}` over the last {spec.get('interval') or '5m'} and fires "
        f"when that count is {spec.get('thresholdType') or 'above'} {spec.get('threshold', 1)}."
        f"{intent}\n\n"
        f"It fires now. The records it matches, by count:\n{_rows(rows)}\n\n"
        "Its open incidents, newest first:\n\n"
        + "\n\n".join(_incident(n, i) for n, i in enumerate(incidents, 1))
        + "\n\nAnswer with only a JSON object: "
        '{"match": <incident number>, "reason": "<one sentence>"}. "match" is the newest incident '
        "whose root cause produces any of these records, or null when none of them does."
    )


_FENCED = re.compile(r"```(?:json)?[ \t]*\r?\n(.*?)\r?\n?```", re.S)


def parse_verdict(text, names):
    """(name, reason) from the answer: its last fenced block, or the whole answer, that is a JSON
    object whose "match" is null or the number of one of `names`, in prompt order. name is None
    for "none of them". Raises NoVerdict otherwise, never a guess."""
    text = (text or "").strip()
    for body in [m.group(1) for m in _FENCED.finditer(text)][::-1] + [text]:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict) or "match" not in data:
            continue
        match = data["match"]
        if match is None:
            return None, _cut(data.get("reason"), REASON_CHARS)
        if type(match) is int and 1 <= match <= len(names):
            return names[match - 1], _cut(data.get("reason"), REASON_CHARS)
    raise NoVerdict('the answer has no {"match": <an incident number> | null} object')

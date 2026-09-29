"""The incident comparison: is the problem an Alert fires on now the problem an open Incident of
that alert describes?

handler.fire asks it once per open, analyzed incident of a firing alert, newest first, on each
reconciler pass (about every 60 s). The comparison agent (config.compareA2aUrl, autopilot by
default) answers. This module owns both sides of that exchange so they cannot drift:
  * build_prompt(alert, incident, at) — incident A is the open one, incident B the one the firing
    would open;
  * parse_verdict(text) — the answer's {"equal": bool, "reason": str} block, or NoVerdict.

Stdlib only (json/re), unit-testable without the cluster.
"""
import json
import re

REPORT_CHARS = 2000   # how much of incident A's report the prompt quotes
EXCERPT_CHARS = 300   # per evidence excerpt
MAX_SOURCES = 5
MAX_RESOURCES = 10
REASON_CHARS = 300


class NoVerdict(Exception):
    """No usable answer: the call failed or was rate-limited, or it carried no verdict block."""


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


def _last_precondition(status):
    """The sentence on incident A's latest precondition run."""
    runs = [c for c in status.get("checks") or [] if c.get("script") == "precondition"]
    if not runs:
        return "Its precondition has not run yet."
    last = runs[-1]
    exit_code = last.get("exit")
    shown = "with no exit code (unknown)" if exit_code is None else f"{exit_code}"
    return (f"Its precondition, a script that exits 1 while that root cause holds and 0 once it is "
            f"gone, last exited {shown} at {last.get('at', '?')}.")


def _incident_a(incident):
    meta, spec = incident.get("metadata") or {}, incident.get("spec") or {}
    st = incident.get("status") or {}
    lines = [f"Incident A is open: {meta.get('name', '?')}, opened {spec.get('triggeredAt', '?')}, "
             f"state {st.get('state', '?')}, {st.get('firings', 0)} firings, the last at "
             f"{st.get('lastFiredAt', '?')}."]
    rc = st.get("rootCause") or {}
    if rc.get("statement"):
        lines.append(f"Its root cause: {_cut(rc['statement'], EXCERPT_CHARS * 2)} (category "
                     f"{rc.get('category') or 'unknown'}).")
    resources = [r for r in st.get("analyzedResources") or [] if isinstance(r, dict)]
    if resources:
        shown = "; ".join(
            f"{r.get('gvr', '?')} {r.get('namespace') + '/' if r.get('namespace') else ''}"
            f"{r.get('name', '?')}" for r in resources[:MAX_RESOURCES])
        lines.append(f"The objects its analysis read: {shown}.")
    sources = [s for s in st.get("sources") or [] if isinstance(s, dict)]
    if sources:
        lines.append("Its evidence:")
        lines += [f"- [{s.get('type', 'object')}] {_cut(s.get('ref'), EXCERPT_CHARS)}: "
                  f"{_cut(s.get('excerpt'), EXCERPT_CHARS)}" for s in sources[:MAX_SOURCES]]
    lines.append(_last_precondition(st))
    if (st.get("report") or "").strip():
        lines.append(f"Its report begins:\n{_cut(st['report'], REPORT_CHARS)}")
    return "\n".join(lines)


def build_prompt(alert, incident, at):
    """The question for one pair: open incident A, and incident B that the alert's firing at `at`
    (an ISO timestamp) would open. Generic: one prompt serves every alert."""
    meta, spec = alert.get("metadata") or {}, alert.get("spec") or {}
    name = meta.get("name", "?")
    display = spec.get("displayName") or name
    intent = f" Its intent: {spec['message']}." if spec.get("message") else ""
    return (
        "Two incidents of the same Krateo alert: decide whether they are the same incident.\n\n"
        f'The alert "{display}" ({meta.get("namespace", "?")}/{name}) counts the log records '
        f"matching `{spec.get('where', '')}` over the last {spec.get('interval') or '5m'} and fires "
        f"when that count is {spec.get('thresholdType') or 'above'} "
        f"{spec.get('threshold', 1)}.{intent}\n\n"
        f"{_incident_a(incident)}\n\n"
        f"Incident B would open now, {at}: the alert is firing, and B is the problem its current "
        "matching records show.\n\n"
        "A and B are the same incident when one root cause on one object explains both: the "
        "records the alert matches now come from the workload and the failure A names. They are "
        "different incidents when those records name another workload, namespace or failure, or "
        "when A's root cause no longer holds while the alert still fires. Read the alert's current "
        "matching records and the objects A names to decide. Only read: change nothing.\n\n"
        "End your answer with exactly one fenced ```json block and nothing after it:\n"
        '{"equal": true, "reason": "<one sentence>"}\n'
        'with "equal" false when they are different incidents.'
    )


_FENCED = re.compile(r"```(?:json)?[ \t]*\r?\n(.*?)\r?\n?```", re.S)


def parse_verdict(text):
    """(equal, reason) from the agent's answer: its last fenced block, or the whole answer, that is
    a JSON object with a boolean "equal". Raises NoVerdict otherwise, never a guess."""
    text = (text or "").strip()
    for body in [m.group(1) for m in _FENCED.finditer(text)][::-1] + [text]:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("equal"), bool):
            return data["equal"], _cut(data.get("reason"), REASON_CHARS)
    raise NoVerdict("the answer has no {\"equal\": true|false} block")

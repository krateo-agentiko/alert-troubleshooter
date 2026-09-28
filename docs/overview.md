---
type: Architecture
title: alert-troubleshooter — architecture
description: How a firing alert becomes Incidents, one per problem, each with an incident-agent root-cause analysis.
tags: [observability, alerts, autopilot]
timestamp: 2026-08-20T00:00:00Z
---

# alert-troubleshooter

A controller (not an agent). The reconciler mirrors each `Alert`'s HyperDX state about every
60 s (`config.reconcileInterval`), and each pass that finds it ALERT is one firing. A firing is
recorded on an `Incident` (`observability.krateo.io/v1alpha1`, the CRD incident-controller ships):
an open incident of the same problem counts it, or a new incident opens and **incident-agent**
root-causes it over A2A. The **autopilot** agent judges whether two incidents are the same. Firings
and analyses run off the reconcile thread. HyperDX's webhook (`POST /webhook`) is acked 202 and
only logged: a HyperDX alert needs a channel, and the reconciler already fires it.

It lives in `krateo-platformops` (not `krateo-agentiko`) because it is observability
plumbing keyed on the platform `observability.krateo.io` API group and rendered by the
portal — it *calls* an agent, it is not one.

## Alert identity

One `Alert` CR is one HyperDX alert and its own incidents, keyed on the CR's `metadata.name`.
`spec.displayName` is only a label and may repeat.

- The reconciler names each HyperDX alert after its CR's `metadata.name`, on a single-tile
  dashboard `krateo-alert-<name>` that no other alert evaluates. An alert claimed by several CRs
  stays with the CR it is named after; the others create their own.
- HyperDX's webhook template has no alert id. The shared webhook body is
  `{"alertName":"{{title}}","state":"{{state}}","source":"hyperdx-alert"}`, and the title is a state
  emoji plus the HyperDX alert name. The reconciler updates an existing webhook whose body differs.
- A firing is the CR the reconciler just mirrored, so it is never matched to an `Alert` by name.
- Its incidents carry the label `observability.krateo.io/alert: <metadata.name>` and
  `spec.alertRef {name, namespace}`. A name over 63 characters cannot be a label value, so such an
  `Alert` opens no incident.

## Incidents

An alert has an incident per problem, and several may be open at once; an incident is open in any
state but `Resolved` and `Closed`. For each firing, `handler.fire`:

1. lists the Incidents in the Alert's namespace labelled with the Alert's name;
2. asks the comparison agent about each open incident that has an analysis (a root cause or a
   report), newest first, whether it and the incident this firing would open are the same (see
   [Incident comparison](#incident-comparison)). The first one judged equal takes the firing: one
   more `status.firings`, a new `status.lastFiredAt`, no RCA. The incident controller writes the
   same status, so the write is conditioned on the resourceVersion it read and retried on a
   conflict;
3. else counts the firing on the newest open incident without an analysis (still `Analyzing`, or
   its RCA failed): there is nothing to compare with, and a new incident would rerun the analysis;
4. else, if the alert's latest incident is `Resolved` and its `status.resolution.at` is less than
   one `spec.interval` ago (5m when unset), counts the firing on that incident the same way, and it
   stays `Resolved`. A `where` alert keeps counting the rows from before the fix for its lookback
   window, and those firings belong to the incident the fix resolved. A `Closed` incident gets no
   such window: after a human close, the next firing opens a new one;
5. else, when a comparison gave no verdict, records nothing: whether the firing is a new problem
   is unknown, and the next pass asks again;
6. otherwise creates `<alert>-<yyyymmdd-hhmmss>` (the firing's UTC time) with the label and
   `spec.alertRef`, `trigger: alert`, `prompt` and `triggeredAt`, in state `Analyzing` with
   `firings: 1`;
7. runs the RCA on the incident's own kagent thread (contextId = uuid5 of its name), then writes
   the analysis, `howToFix` and `state: Open` in one status write.

- One evaluation per alert runs at a time: while one is still comparing, the alert's next firing
  is skipped. The RCA runs after that evaluation ends, and its incident takes the firings that
  arrive meanwhile (step 3).
- An RCA that fails, or whose answer is empty, unstructured or has no usable `howToFix`, still
  opens the incident, with `status.error` saying why it has no scripts.
- An incident a human closed while it was analyzing stays `Closed`, which is final: the analysis
  is written without a state.
- At startup the handler opens every incident a restart left `Analyzing`, with the reason in
  `error`, so it can be closed and the next firing opens a fresh one.
- The alert returning to OK changes nothing. From `Open` on, the incident controller runs its
  scripts and moves it, or a human closes it.

## Incident comparison

`compare.py` holds both sides of it: the prompt and the verdict parser.

- One A2A call per compared incident, to `config.compareA2aUrl` (default: the autopilot agent), on
  a fresh kagent thread, with the service JWT and the header `X-Krateo-Purpose: incident-compare`.
  It times out after `COMPARE_TIMEOUT` (120 s).
- The prompt describes incident A, the open one: its root cause, the objects its analysis read,
  its evidence, its latest precondition exit and the start of its report. Incident B is the one
  this firing would open. A and B are the same when one root cause on one object explains both.
  The agent may read the alert's current rows and the objects A names, and is told to change
  nothing.
- The answer ends with `{"equal": true|false, "reason": "…"}`. A failed or timed-out call, a 429,
  or an answer without that block is no verdict.
- Behind the agentgateway, agentgateway-policies routes requests carrying the header to its
  `incidentCompare` route, whose rate limit bounds these calls. Its 429 is no verdict, so the
  limit delays a new incident and never opens an extra one.
- A firing alert with K analyzed open incidents costs up to K calls per pass.

## Alert status

The reconciler mirrors the HyperDX alert's `state` onto `status.state` every cycle, and writes
`status.okSince` in the same patch: the time the alert last turned OK, kept while it stays OK and
unset in any other state. It is for display ("OK for 13 min") and never closes anything.

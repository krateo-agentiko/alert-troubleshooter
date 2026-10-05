---
type: Architecture
title: alert-provider — architecture
description: How a firing alert becomes Incidents, one per problem, each with an incident-agent root-cause analysis.
tags: [observability, alerts]
timestamp: 2026-08-20T00:00:00Z
---

# alert-provider

A controller (not an agent). The reconciler mirrors each `Alert`'s HyperDX state about every
60 s (`config.reconcileInterval`), and each pass that finds it ALERT is one firing. A firing is
recorded on an `Incident` (`observability.krateo.io/v1alpha1`, the CRD incident-controller ships):
an open incident of the same problem counts it, or a new incident opens and **incident-agent**
root-causes it over A2A. One LLM call per firing, on the fleet's model, names the open incident it
belongs to. Firings
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
2. asks the comparison model, in one call over the open incidents that have an analysis (a root
   cause, or a report from an RCA that did not fail), which one causes the alert's current
   records (see [Incident comparison](#incident-comparison)). That one takes the firing: one
   more `status.firings`, a new `status.lastFiredAt`, no RCA. The incident controller writes the
   same status, so the write is conditioned on the resourceVersion it read and retried on a
   conflict;
3. else counts the firing on the newest open incident without an analysis: one still
   `Analyzing`, or one whose RCA failed (whatever text the failure left in `status.report`) less
   than `config.failedAnalysisHold` (1800 s) after its `status.completedAt`. There is nothing to
   compare with, and a new incident would rerun the analysis. Past the hold, a failed incident
   takes no more firings and stays `Open` until a person closes it, so the next firing nothing
   else covers opens a new incident with a fresh RCA;
4. else, if the alert's latest incident is `Resolved` and its `status.resolution.at` is less than
   one `spec.interval` ago (5m when unset), counts the firing on that incident the same way, and it
   stays `Resolved`. A `where` alert keeps counting the rows from before the fix for its lookback
   window, and those firings belong to the incident the fix resolved. A `Closed` incident gets no
   such window: after a human close, the next firing opens a new one;
5. else, when the comparison gave no verdict, records nothing: whether the firing is a new problem
   is unknown, and the next pass asks again;
6. otherwise creates `<alert>-<yyyymmdd-hhmmss>` (the firing's UTC time) with the label and
   `spec.alertRef`, `trigger: alert`, `prompt` and `triggeredAt`, in state `Analyzing` with
   `firings: 1`;
7. runs the RCA on the incident's own kagent thread (contextId = uuid5 of its name), retargets a
   `howToFix` that writes an object a composition renders at the composition's spec (one
   follow-up on the same thread, see [api](api.md#a-fix-for-an-object-a-composition-renders)),
   then writes the analysis, `howToFix` and `state: Open` in one status write.

- One evaluation per alert runs at a time: while one is still comparing, the alert's next firing
  is skipped. The RCA runs after that evaluation ends, and its incident takes the firings that
  arrive meanwhile (step 3).
- At most `MAX_CONCURRENT_ANALYSES` RCAs (2) run at once, so alerts that fire together do not
  spend the model's per-minute token quota at once and fail every RCA; a new incident waits in
  `Analyzing` for a slot.
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

- One chat completion per firing, with no agent and no tools, on the model of the kagent
  ModelConfig `config.compareModelConfig` (default `gemini-flash`): provider OpenAI at its
  `baseUrl` (behind the agentgateway, its `/llm/v1` route, keyed by the service JWT under
  `apiKeyPassthrough`), or provider Gemini with its `apiKeySecret`. It times out after
  `COMPARE_TIMEOUT` (60 s).
- The system prompt is two sentences. The user message holds the alert, its current records and
  the `config.maxCompareCandidates` (50) newest open analyzed incidents, newest first, each as its root cause and its
  precondition, apply and verify scripts.
- The records are the alert's `where` rows over one `spec.interval`, from HyperDX's
  `/api/v2/charts/series` grouped by `compare.ROW_GROUP`: a line per distinct record (a k8s
  event's object, reason and message; any other log's service and pod), with its
  count, the 20 most frequent quoted. No row is no verdict: HyperDX's `ALERT` comes from its last
  evaluation, and the window read later can have aged past every row.
- The answer is `{"match": <incident number> | null, "reason": "…"}`: the newest incident whose
  root cause produces any of the records, or null for none. The prompt numbers the incidents
  rather than naming them, because the gateway's PhoneNumber guard masks the timestamp in a name.
  A failed or timed-out call, a 429, or an answer whose `match` is not null or a candidate's
  number is no verdict.
- A firing alert costs at most one call per pass, whatever the number of its open incidents.

## Alert status

The reconciler mirrors the HyperDX alert's `state` onto `status.state` every cycle, and writes
`status.okSince` in the same patch: the time the alert last turned OK, kept while it stays OK and
unset in any other state. It is for display ("OK for 13 min") and never closes anything.

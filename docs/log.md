---
type: Log
title: Log
description: Notable changes.
tags: [observability, alerts]
timestamp: 2026-08-20T00:00:00Z
---

# Log

## 2026-08-20
- Moved `krateo-agentiko` -> `krateo-platformops` (observability plumbing, not an agent) and standardized: wrapped the raw manifests in a helm chart, bare-semver + `CHART_VERSION`, owner-derived image build (was pinned at `krateo-agentiko` `v0.2.17`), public security caller, preflight, OKF docs.

## 2026-09-28
- Renamed alert-troubleshooter to **alert-provider**: charts `alert-provider` and `alert-provider-crds`, image `ghcr.io/krateo-platformops/alert-provider`, Deployment/Service/ServiceAccount `krateo-alert-provider`, authn identity `krateo-alert-provider` (group `krateo:alert-provider`), HyperDX webhook `krateo-alert-provider`. The GitHub repo keeps its name.
- An alert has an incident per problem: every reconciler pass that finds it ALERT is a firing, which counts on the open incident autopilot judges the same problem, or opens a new one. The HyperDX webhook only logs.
- `Alert.spec.apiRef` and `status.value` are gone; `howToFix` gains an optional `rollback`.
- `howToFix` gains an optional `applyAction`, the single Kubernetes write the portal's Apply button sends as the clicking user.
- A failed RCA's error text in `status.report` no longer makes its incident comparable, so it takes the alert's firings uncompared instead of opening a new incident each pass. At most 2 RCAs run at once (`MAX_CONCURRENT_ANALYSES`).
- The chart takes `imagePullSecrets` for its private image, set on the `krateo-alert-provider` ServiceAccount.

## 2026-09-30
- A firing is compared with all its alert's open incidents in one chat completion on the model of `config.compareModelConfig` (default `gemini-flash`), with a two-sentence system prompt, the alert's current records from HyperDX, and each incident's root cause and scripts. `config.compareA2aUrl` is gone.

## 2026-10-01
- A comparison weighs the 50 newest open analyzed incidents, set by `config.maxCompareCandidates`.
- An incident whose RCA failed takes its alert's firings for `config.failedAnalysisHold` (1800 s) after the failure, then no more: the next firing nothing else covers opens a new incident with a fresh RCA. An interrupted RCA stamps `completedAt` too.

## 2026-10-05
- The seeded `krateo-composition-reconcile-error` excludes `incident-controller`: its own "Reconciler error" lines are about Incidents, and on krateo-057 they were ~21k rows a day that kept the alert firing every minute. Seeding only creates an absent Alert, so an existing one keeps its old `where` until it is edited or deleted and reseeded.
- An Alert whose spec push succeeds again clears the previous `SpecDrift` `error`.
- An `applyAction` may name a Krateo composition's dashed version (`composition.krateo.io/v1-12-36`); the parser used to drop it, so a fix that patches a composition's spec had no Apply button.

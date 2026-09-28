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

---
type: Configuration
title: Configuration
description: Environment and values that tune the controller.
tags: [observability, alerts]
timestamp: 2026-08-20T00:00:00Z
---

# Configuration

| key | default | meaning |
|---|---|---|
| `image.repository` | `ghcr.io/krateo-platformops/alert-troubleshooter` | controller image |
| `image.tag` | chart appVersion | image tag; pin to override |
| `config.autopilotA2aUrl` | `http://incident-agent.krateo-system.svc:8080/` | the RCA agent's A2A endpoint |
| `config.compareA2aUrl` | `http://autopilot.krateo-system.svc:8080/` | the agent that judges whether a firing is an open incident's problem; behind the agentgateway, its `/api/a2a/<namespace>/autopilot` path, so the `incidentCompare` rate limit applies |
| `config.authnUrl` | `""` | authn, for the service JWT on both A2A calls; empty = unauthenticated |
| `config.reconcileInterval` | `60` | seconds between reconciler passes; each pass that finds an alert ALERT is one firing |

Runtime env (set on the Deployment) carries these, plus `A2A_TIMEOUT` (180 s, the RCA) and
`COMPARE_TIMEOUT` (120 s, one comparison). See `helm/alert-troubleshooter/templates/deployment.yaml`.

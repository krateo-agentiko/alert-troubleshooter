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
| `image.repository` | `ghcr.io/krateo-platformops/alert-provider` | controller image |
| `image.tag` | chart appVersion | image tag; pin to override |
| `config.autopilotA2aUrl` | `http://incident-agent.krateo-system.svc:8080/` | the RCA agent's A2A endpoint |
| `config.compareModelConfig` | `gemini-flash` | the kagent ModelConfig whose model names the open incident that covers a firing; provider OpenAI or Gemini |
| `config.authnUrl` | `""` | authn, for the service JWT on both A2A calls; empty = unauthenticated |
| `config.reconcileInterval` | `60` | seconds between reconciler passes; each pass that finds an alert ALERT is one firing |

Runtime env (set on the Deployment) carries these, plus `A2A_TIMEOUT` (180 s, the RCA) and
`COMPARE_TIMEOUT` (60 s, one comparison). See `helm/alert-provider/templates/deployment.yaml`.

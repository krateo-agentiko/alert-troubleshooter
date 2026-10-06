---
type: API
title: API
description: The Alert CRD this controller owns, the Incident fields it writes, the RCA output contract and the HTTP surface.
tags: [observability, alerts]
timestamp: 2026-08-20T00:00:00Z
---

# API

- **`Alert`** (`observability.krateo.io/v1alpha1`) — the inbound alert shape (see `helm/alert-provider-crds/templates/crd.alert.yaml`). `spec.where` is the ClickHouse SQL whose rows HyperDX counts. `status.state` mirrors HyperDX; `status.okSince` is when it last turned OK, unset while it is anything else (display only). `status.conditions` are provider-runtime's `Ready` and `Synced`. The annotation `krateo.io/paused: "true"` skips its firings (see [usage](usage.md#pause-an-alert)).
- **`Incident`** (`observability.krateo.io/v1alpha1`) — written here, owned by incident-controller, whose chart ships the CRD. The provider creates `<alert>-<yyyymmdd-hhmmss>` with the label `observability.krateo.io/alert` and `spec.alertRef`, `trigger`, `prompt`, `triggeredAt`, and writes status `state` (`Analyzing`, then `Open`), `firings`, `lastFiredAt`, `howToFix`, `error`, `completedAt` and the analysis fields below. It also counts firings (`firings`, `lastFiredAt`) on a `Resolved` incident for one `spec.interval` after its `resolution.at`. See [overview](overview.md#incidents).

HTTP: `POST /webhook` (acked 202); `GET /healthz`. The webhook body is
`{"alertName":"<emoji> <Alert metadata.name>","state":"ALERT|OK","source":"hyperdx-alert"}`, the
template the reconciler installs on its HyperDX webhook. The provider only logs it: the reconciler's
pass fires alerts.

## Comparison contract

`internal/compare` holds both sides of it. Each firing is one OpenAI chat-completions call
(`<baseUrl>/chat/completions`) on the model of the ModelConfig `config.compareModelConfig`, with
`compare.System` and the prompt. The answer is one object `{"match": <incident number> | null,
"reason": "<one sentence>"}`, the number in prompt order. Anything else, a failed call, a 429, or no record matching the alert is no verdict. See
[overview](overview.md#incident-comparison).

## RCA output contract

`internal/report` holds both sides of it: the instructions appended to every RCA prompt, and the
parser of the agent's answer. The answer ends with one `json` block. The parser keeps the
`report.StatusKeys` it finds there, sanitized, and falls back to a prose-only report when there is no
usable block.

`howToFix` is the fix as four bash scripts:

| Script | Run by | Exit codes |
|---|---|---|
| `precondition` | the incident controller, in a read-only sandbox, first right after the analysis | `1` the incident holds, `0` it is gone; its first run must exit `1` |
| `apply` | a human, after reviewing it | none; it may write and is idempotent |
| `verify` | the incident controller, in the sandbox, after precondition `0` or an applied fix | `0` the fix worked, `1` the incident still holds |
| `rollback` | a human, to undo an applied fix | none; it restores what apply changed and is idempotent |

Any other exit code, or a timeout, is unknown and changes nothing. The sandbox has bash, kubectl
and jq, a ServiceAccount that reads but never writes and cannot read Secrets, egress to the API
server only, and a 60 s deadline. The precondition tests the root-cause object, never the alert's
rows, so it tells whether that cause is gone while the alert fires for another.

The parser keeps `howToFix` only when precondition, apply and verify are non-empty strings of at
most 16384 characters (a list of lines is joined). Otherwise it drops `howToFix` whole, keeps the
rest of the report and, when there is a root cause, appends to `missingContext` why there are no
scripts. A rollback that fails the same test is left out alone, and `missingContext` says so.

`howToFix.applyAction` is optional: apply as one Kubernetes API write, when it is one. The portal's
Apply button sends it as the person who clicks, with their RBAC, then sets `spec.applied`.

| Field | Value |
|---|---|
| `verb` | `patch` (payload is a JSON merge patch), `create` (payload is the whole object) or `delete` (no payload) |
| `apiVersion`, `resource` | the target's `v1` or `<group>/<version>` (a Krateo composition's version is dashed, `v1-12-36`), and its lowercase plural |
| `namespace`, `name` | the target; `namespace` is absent for a cluster-scoped object |
| `payload` | an object; for `create` its apiVersion and metadata match the target |

The parser keeps it only alongside the three scripts. One that is malformed, deletes a Namespace,
Node or CustomResourceDefinition, or carries a payload over 16384 characters is left out alone,
and `missingContext` says so.

The provider writes the `report.StatusKeys` onto the Incident. The parser's `evidence` (the
retrieval ledger behind the confidence cap) is not stored; its sentence is already in the report
and `missingContext`.

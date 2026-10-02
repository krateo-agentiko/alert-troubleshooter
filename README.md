# krateo-alert-provider

## What is this
Turns a firing Krateo observability **Alert** into **Incidents**, one per problem, each with an
**incident-agent root-cause analysis**, in the background — no browser required.

```
every 60 s, Alert is ALERT in HyperDX → krateo-alert-provider
    → an open incident of the same problem? (one LLM call)        yes → status.firings++
                                                                  no  → new Incident → A2A call to incident-agent
                                                                        → status: analysis + howToFix scripts, state Open
```

## What it does
The reconciler mirrors each Alert's HyperDX state every pass; a pass that finds it ALERT is a
firing, and the handler:
1. asks the comparison model, in one call over the Alert's open analyzed `Incident`s
   (`observability.krateo.io/v1alpha1`), which one causes its current records, and counts the
   firing on it,
2. else creates one in state `Analyzing` and calls incident-agent over A2A (JSON-RPC
   `message/stream`) with the incident's prompt,
3. writes the analysis and its `howToFix` scripts to the Incident's status, in state `Open`.

The incident controller (incident-controller) runs the scripts from there. See
[docs/overview.md](docs/overview.md#incidents).

HyperDX's webhook is acked (202) and logged; the reconciler's pass is what fires an alert.

## Build
Image is built + pushed by CI (`.github/workflows/release.yaml`) to
`ghcr.io/krateo-platformops/alert-provider` on push to `main` / tags. No local docker push.

## Deploy
```sh
```
The reconciler creates the HyperDX webhook and alerts from the `Alert` CRs.

## Config (env)
- `NAMESPACE` (default `krateo-system`) — the namespace of its Alerts and their Incidents.
- `AUTOPILOT_A2A_URL` — the RCA agent (chart default `http://incident-agent.krateo-system.svc:8080/`).
- `A2A_TIMEOUT` (default `180`s).
- `COMPARE_MODEL_CONFIG` — the kagent ModelConfig whose model compares incidents (default `gemini-flash`).
- `COMPARE_TIMEOUT` (default `60`s).

## Install
```sh
helm install alert-provider oci://ghcr.io/krateo-platformops/charts/alert-provider --version <tag> -n krateo-system
```

## Configure
See [docs/configuration.md](docs/configuration.md).

## Examples
See [examples/webhook/](examples/webhook/).

## Docs
[docs/index.md](docs/index.md) — overview, usage, API, configuration, release, log.

## Develop & release
Tag a bare semver; CI builds the image and publishes the chart. See [docs/release.md](docs/release.md).

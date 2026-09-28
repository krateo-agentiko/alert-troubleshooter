# krateo-alert-troubleshooter

## What is this
Turns a firing Krateo observability **Alert** into **Incidents**, one per problem, each with an
**incident-agent root-cause analysis**, in the background — no browser required.

```
every 60 s, Alert is ALERT in HyperDX → krateo-alert-troubleshooter
    → an open incident of the same problem? (autopilot compares)  yes → status.firings++
                                                                  no  → new Incident → A2A call to incident-agent
                                                                        → status: analysis + howToFix scripts, state Open
```

## What it does
The reconciler mirrors each Alert's HyperDX state every pass; a pass that finds it ALERT is a
firing, and the handler:
1. asks autopilot, per open analyzed `Incident` (`observability.krateo.io/v1alpha1`) of the
   Alert, whether it is the same problem, and counts the firing on the first that is,
2. else creates one in state `Analyzing` and calls incident-agent over A2A (JSON-RPC
   `message/stream`) with the incident's prompt,
3. writes the analysis and its `howToFix` scripts to the Incident's status, in state `Open`.

The incident controller (incident-controller) runs the scripts from there. See
[docs/overview.md](docs/overview.md#incidents).

HyperDX's webhook is acked (202) and logged; the reconciler's pass is what fires an alert.

## Build
Image is built + pushed by CI (`.github/workflows/release.yaml`) to
`ghcr.io/krateo-platformops/alert-troubleshooter` on push to `main` / tags. No local docker push.

## Deploy
```sh
```
The reconciler creates the HyperDX webhook and alerts from the `Alert` CRs.

## Config (env)
- `NAMESPACE` (default `krateo-system`) — the namespace of its Alerts and their Incidents.
- `AUTOPILOT_A2A_URL` — the RCA agent (chart default `http://incident-agent.krateo-system.svc:8080/`).
- `A2A_TIMEOUT` (default `180`s).
- `COMPARE_A2A_URL` — the agent that compares incidents (default `http://autopilot.krateo-system.svc:8080/`).
- `COMPARE_TIMEOUT` (default `120`s).

## Install
```sh
helm install alert-troubleshooter oci://ghcr.io/krateo-platformops/charts/alert-troubleshooter --version <tag> -n krateo-system
```

## Configure
See [docs/configuration.md](docs/configuration.md).

## Examples
See [examples/webhook/](examples/webhook/).

## Docs
[docs/index.md](docs/index.md) — overview, usage, API, configuration, release, log.

## Develop & release
Tag a bare semver; CI builds the image and publishes the chart. See [docs/release.md](docs/release.md).

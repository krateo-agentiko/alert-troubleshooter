---
type: Example
title: Webhook example
description: A sample HyperDX notification payload.
tags: [observability, alerts]
timestamp: 2026-08-20T00:00:00Z
---

# Webhook example

```sh
curl -XPOST http://krateo-alert-provider.krateo-system.svc:8080/webhook -d @alert.json
```

`alert.json` is the body HyperDX sends: `alertName` is the notification title, a state emoji plus
the HyperDX alert name, which is the `Alert` CR's `metadata.name`. The handler logs it and opens
nothing: the reconciler's pass fires an `Alert` whose HyperDX state is ALERT, and that firing opens
an `Incident` or counts on an open one (see [overview](../../docs/overview.md#incidents)).

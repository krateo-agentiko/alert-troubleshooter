"""A fix for an object a Krateo composition manages goes through the composition's values.

The composition-dynamic-controller renders every object of a composition from the composition's
spec, labels it krateo.io/composition-id (the composition's uid), and on each reconcile reverts any
other change to it. An RCA's howToFix that patches such an object therefore flaps: verify passes,
then the next reconcile restores the broken value. handler._fix_through_composition finds the
composition behind the object howToFix writes and asks the RCA agent, on the incident's own
thread, which spec value renders the broken field. This module owns that exchange:
  * written_targets(how_to_fix) — the objects apply and applyAction write;
  * build_prompt(...) and parse_choice(text) — the question and the {"path", "value"} answer;
  * retarget(...) — the howToFix whose apply, rollback and applyAction merge-patch one top-level
    key of the composition's spec, or why the choice is unusable;
  * reverted(...) — the howToFix kept as it was, saying that the composition will revert it.

Stdlib only (copy/json/re/shlex), unit-testable without the cluster.
"""
import copy
import json
import re
import shlex

import report_v2

GROUP = "composition.krateo.io"
LABEL_ID = "krateo.io/composition-id"
# The rest of the CDC's labels on a managed object name the composition directly.
LABEL_RESOURCE = "krateo.io/composition-resource"
LABEL_NAME = "krateo.io/composition-name"
LABEL_NAMESPACE = "krateo.io/composition-namespace"
LABEL_VERSION = "krateo.io/composition-installed-version"
LABEL_GROUP = "krateo.io/composition-group"
HELM_RELEASE = "meta.helm.sh/release-name"
HELM_NAMESPACE = "meta.helm.sh/release-namespace"

SPEC_CHARS = 16384     # the composition's current spec, quoted
SCHEMA_CHARS = 32768   # its spec's JSON schema, quoted
REASON_CHARS = 300

# Built-in kinds a script names, by every name kubectl takes for them: (apiVersion, plural).
# Secrets are left out: reading one to find its owner reads its data.
BUILTIN = {}
for _api, _plural, _names in (
        ("v1", "pods", ("pod", "po")),
        ("v1", "services", ("service", "svc")),
        ("v1", "configmaps", ("configmap", "cm")),
        ("v1", "serviceaccounts", ("serviceaccount", "sa")),
        ("v1", "persistentvolumeclaims", ("persistentvolumeclaim", "pvc")),
        ("apps/v1", "deployments", ("deployment", "deploy")),
        ("apps/v1", "statefulsets", ("statefulset", "sts")),
        ("apps/v1", "daemonsets", ("daemonset", "ds")),
        ("apps/v1", "replicasets", ("replicaset", "rs")),
        ("batch/v1", "jobs", ("job",)),
        ("batch/v1", "cronjobs", ("cronjob", "cj")),
        ("networking.k8s.io/v1", "ingresses", ("ingress", "ing")),
        ("autoscaling/v2", "horizontalpodautoscalers", ("horizontalpodautoscaler", "hpa")),
        ("policy/v1", "poddisruptionbudgets", ("poddisruptionbudget", "pdb"))):
    _group = _api.rpartition("/")[0]
    for _n in (_plural,) + _names:
        BUILTIN[_n] = (_api, _plural)
        if _group:
            BUILTIN[f"{_n}.{_group}"] = (_api, _plural)
# An ownerReference names a kind; the plural of the ones a workload chain passes through.
KIND_PLURAL = {"ReplicaSet": "replicasets", "Deployment": "deployments", "StatefulSet": "statefulsets",
               "DaemonSet": "daemonsets", "Job": "jobs", "CronJob": "cronjobs", "Pod": "pods"}

# kubectl verbs that change an object's desired state, the ones a reconcile reverts. A delete (a
# Pod or a Job the controller recreates) and a rollout restart are not reverted, and stay as written.
_WRITE_VERBS = ("patch", "set", "scale", "edit", "label", "annotate", "replace", "apply")
# kubectl flags whose value is the next word.
_VALUE_FLAGS = {"-n", "--namespace", "-c", "--containers", "--container", "-p", "--patch", "--type",
                "--replicas", "--current-replicas", "-l", "--selector", "-f", "--filename",
                "--patch-file", "--limits", "--requests", "-o", "--output", "--field-manager",
                "--resource-version", "--timeout", "-e", "--env", "--from", "--prefix", "--keys"}


class NoChoice(Exception):
    """The agent's answer named no usable spec value."""


def _words(script):
    """The words of each logical line of a bash script, continuations joined."""
    for line in re.sub(r"\\\r?\n", " ", script or "").splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            yield shlex.split(line)
        except ValueError:
            continue


def _kubectl_target(words):
    """(apiVersion, plural, namespace, name) of the object one kubectl write names, or None."""
    for i, w in enumerate(words):
        if w == "kubectl" or w.endswith("/kubectl"):
            words = words[i + 1:]
            break
    else:
        return None
    namespace, positional, skip = "", [], False
    for i, w in enumerate(words):
        if skip:
            skip = False
            continue
        if w in ("-n", "--namespace"):
            namespace = words[i + 1] if i + 1 < len(words) else ""
            skip = True
        elif w.startswith("--namespace="):
            namespace = w.partition("=")[2]
        elif w.startswith("-n") and len(w) > 2 and not w.startswith("--"):
            namespace = w[2:]
        elif w in _VALUE_FLAGS:
            skip = True
        elif w.startswith("-"):
            continue
        elif w in ("|", "||", "&&", ";"):
            break
        else:
            positional.append(w)
    if not positional or positional[0] not in _WRITE_VERBS:
        return None
    rest = positional[2:] if positional[0] == "set" else positional[1:]
    if not rest:
        return None
    kind, _, name = rest[0].partition("/")
    if not name:
        name = rest[1] if len(rest) > 1 else ""
    known = BUILTIN.get(kind.lower())
    if not known or not name or "=" in name:
        return None
    return known[0], known[1], namespace, name


def written_targets(how_to_fix):
    """(apiVersion, plural, namespace, name) of every object howToFix's applyAction or apply script
    writes, applyAction first, without repeats. A delete or a create writes no managed value, so it
    is not one."""
    out = []
    action = (how_to_fix or {}).get(report_v2.HOW_TO_FIX_ACTION) or {}
    if action.get("verb") == "patch":
        out.append((action["apiVersion"], action["resource"], action.get("namespace", ""),
                    action["name"]))
    for words in _words((how_to_fix or {}).get("apply")):
        target = _kubectl_target(words)
        if target and target not in out:
            out.append(target)
    return [t for t in out if t[0].partition("/")[0] != GROUP]


def label_ref(obj):
    """The composition the CDC labels name on `obj`: (group, version, resource, namespace, name,
    uid), with "" for a label that is absent, or None when obj carries no composition-id."""
    meta = obj.get("metadata") or {}
    labels, notes = meta.get("labels") or {}, meta.get("annotations") or {}
    uid = labels.get(LABEL_ID)
    if not uid:
        return None
    return (labels.get(LABEL_GROUP) or GROUP, labels.get(LABEL_VERSION, ""),
            labels.get(LABEL_RESOURCE, ""),
            labels.get(LABEL_NAMESPACE) or notes.get(HELM_NAMESPACE) or meta.get("namespace", ""),
            labels.get(LABEL_NAME) or notes.get(HELM_RELEASE, ""), uid)


def controller_owner(obj):
    """(apiVersion, plural) and name of the ownerReference that controls `obj`, or None."""
    refs = (obj.get("metadata") or {}).get("ownerReferences") or []
    ref = next((r for r in refs if r.get("controller")), refs[0] if refs else None)
    if not ref or not ref.get("name") or not ref.get("apiVersion"):
        return None
    plural = KIND_PLURAL.get(ref.get("kind"))
    if not plural:
        return None
    return ref["apiVersion"], plural, ref["name"]


def describe(obj):
    meta = obj.get("metadata") or {}
    return f"{obj.get('kind') or 'object'} {meta.get('namespace', '')}/{meta.get('name', '')}"


def _resource(composition, plural):
    """The kubectl name of the composition's kind at its own version: plural.version.group."""
    version = composition["apiVersion"].partition("/")[2]
    return f"{plural}.{version}.{GROUP}"


def _cut_json(value, limit):
    text = json.dumps(value, indent=1, sort_keys=True)
    return text if len(text) <= limit else text[:limit] + "\n…(truncated)"


def build_prompt(managed, composition, schema, how_to_fix, parent=None):
    """The follow-up on the incident's thread, once the object apply writes (`managed`, the
    labelled one) turns out to be rendered by `composition`. `schema` is the JSON schema of the
    composition's spec, or None when it could not be read."""
    meta = composition.get("metadata") or {}
    schema_text = (f"The JSON schema of its spec:\n```json\n{_cut_json(schema, SCHEMA_CHARS)}\n```"
                   if schema else "Its spec's JSON schema could not be read.")
    nested = (f"\n\n{describe(composition)} is itself rendered by {describe(parent)}, so a value "
              "that composition sets for it can override yours on a later reconcile; name it in "
              "your reason if the spec value you pick is one."
              if parent else "")
    return (
        f"Your fix writes {describe(managed)}, but that object is managed by the Krateo "
        f"composition {composition.get('kind')} {meta.get('namespace', '')}/{meta.get('name', '')} "
        f"({composition.get('apiVersion')}): the composition controller renders it from the "
        "composition's spec and reverts any other change on its next reconcile. The fix has to be "
        "made through the composition's values instead.\n\n"
        "The composition's current spec:\n"
        f"```json\n{_cut_json(composition.get('spec') or {}, SPEC_CHARS)}\n```\n\n"
        f"{schema_text}{nested}\n\n"
        f"The apply you wrote:\n```bash\n{(how_to_fix.get('apply') or '').strip()}\n```\n\n"
        "Which value of the composition's spec renders the field your fix changes? Answer with "
        "ONLY one fenced ```json block: {\"path\": [\"<top-level spec key>\", \"<nested key>\", "
        "...], \"value\": <the new value at that path>, \"reason\": \"<one sentence>\"}. path starts "
        "at a key of spec (not \"spec\" itself) and goes down to the one value to change; an "
        "integer step indexes a list. When no value of this composition renders that field, "
        "answer {\"path\": null, \"reason\": \"<why>\"}."
    )


_FENCED = re.compile(r"```(?:json)?[ \t]*\r?\n(.*?)\r?\n?```", re.S)


def parse_choice(text):
    """(path, value, reason) from the answer's last fenced block, or the whole answer, that is a
    JSON object with a "path". Raises NoChoice for a null path or no such object."""
    text = (text or "").strip()
    for body in [m.group(1) for m in _FENCED.finditer(text)][::-1] + [text]:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict) or "path" not in data:
            continue
        reason = str(data.get("reason") or "").strip()[:REASON_CHARS]
        path = data["path"]
        if path is None:
            raise NoChoice("the analysis found no spec value that renders it "
                           f"({reason or 'no reason given'})")
        if not isinstance(path, list) or not path or not isinstance(path[0], str) \
                or not all(isinstance(p, str) or type(p) is int for p in path):
            raise NoChoice("the answer's path is not a list of keys starting at a spec key")
        if "value" not in data:
            raise NoChoice("the answer gives no value")
        return path, data["value"], reason
    raise NoChoice('the answer has no {"path": [...], "value": ...} object')


def _top_level_keys(schema):
    return set(((schema or {}).get("properties") or {}).keys())


def _unknown_step(schema, path):
    """The first step of `path` the spec's schema has no field for, or None. A field the schema
    does not declare is pruned on write, so a patch to it would change nothing. Below an object
    that keeps unknown fields, or with no schema, every step is accepted."""
    node = schema
    for i, step in enumerate(path):
        if not isinstance(node, dict) or node.get("x-kubernetes-preserve-unknown-fields"):
            return None
        if type(step) is int:
            node = node.get("items")
        elif step in (node.get("properties") or {}):
            node = node["properties"][step]
        elif isinstance(node.get("additionalProperties"), dict):
            node = node["additionalProperties"]
        elif node.get("additionalProperties") is True or "properties" not in node and i:
            return None
        else:
            return "spec." + ".".join(map(str, path[:i + 1]))
    return None


def _set(base, path, value):
    """`base` with the value at `path` replaced (maps created on the way), or NoChoice."""
    if not path:
        return copy.deepcopy(value)
    step, rest = path[0], path[1:]
    if type(step) is int:
        if not isinstance(base, list) or not 0 <= step < len(base):
            raise NoChoice(f"list index {step} is not in the current value")
        out = copy.deepcopy(base)
        out[step] = _set(out[step], rest, value)
        return out
    if base is None:
        base = {}
    if not isinstance(base, dict):
        raise NoChoice(f"{step!r} is under a value that is not an object")
    out = copy.deepcopy(base)
    out[step] = _set(out.get(step), rest, value)
    return out


def _patch_script(comment, resource, ns, name, payload):
    target = f"{resource} {name}" + (f" -n {ns}" if ns else "")
    return (f"#!/usr/bin/env bash\n# {comment}\nset -euo pipefail\n"
            f"kubectl patch {target} --type merge \\\n"
            f"  -p {shlex.quote(json.dumps(payload, separators=(',', ':')))}\n")


def retarget(how_to_fix, managed, composition, plural, schema, path, value, reason=""):
    """(howToFix, None) whose apply, rollback and applyAction merge-patch the one top-level key of
    the composition's spec that `path` starts at, carrying that key's whole current value with
    the one field at `path` changed; precondition and verify are kept, since they test the
    workload. (None, why) when the choice is unusable: its key is in neither the spec's schema nor
    the spec, or it changes nothing."""
    spec = composition.get("spec") or {}
    key = path[0]
    if key not in _top_level_keys(schema) and key not in spec:
        known = sorted(_top_level_keys(schema) | set(spec))
        return None, (f"the analysis chose spec.{key}, which is not a key of the composition's spec"
                      + (f" ({', '.join(known[:40])})" if known else ""))
    unknown = _unknown_step(schema, path) if key in _top_level_keys(schema) else None
    if unknown:
        return None, (f"the analysis chose {unknown}, which the composition's schema does not "
                      "declare, so the apiserver would prune it")
    if key in spec:
        current = spec[key]
    else:
        current = ((schema or {}).get("properties") or {}).get(key, {}).get("default")
    try:
        new = _set(current, path[1:], value)
    except NoChoice as e:
        return None, f"spec.{'.'.join(map(str, path))}: {e}"
    if new == current:
        return None, f"spec.{'.'.join(map(str, path))} already holds that value"
    meta = composition["metadata"]
    ns, name = meta.get("namespace", ""), meta["name"]
    resource = _resource(composition, plural)
    where = f"spec.{'.'.join(map(str, path))}"
    why = f" {reason.rstrip('.')}." if reason else ""
    payload = {"spec": {key: new}}
    undo = {"spec": {key: spec.get(key)}}
    if len(json.dumps(payload)) > report_v2.SCRIPT_MAX_CHARS:
        return None, f"spec.{key} is over {report_v2.SCRIPT_MAX_CHARS} characters as one patch"
    out = {k: v for k, v in how_to_fix.items() if k in report_v2.HOW_TO_FIX_SCRIPTS}
    out["apply"] = _patch_script(
        f"Set {where} on {composition.get('kind')} {ns}/{name}, which renders {describe(managed)}: "
        f"a change to that object itself is reverted on the composition's next reconcile.{why}",
        resource, ns, name, payload)
    out[report_v2.HOW_TO_FIX_ROLLBACK] = _patch_script(
        f"Undo apply: put spec.{key} of {composition.get('kind')} {ns}/{name} back to the value "
        "read before the fix" + ("." if key in spec else " (it was unset)."),
        resource, ns, name, undo)
    action = {"verb": "patch", "apiVersion": composition["apiVersion"], "resource": plural,
              "namespace": ns, "name": name, "payload": payload}
    action, bad = report_v2._apply_action(action)
    if bad:
        return None, f"the composition patch is not a usable applyAction ({bad})"
    out[report_v2.HOW_TO_FIX_ACTION] = action
    return out, None


def reverted_note(managed, composition, why):
    """The missingContext line for a fix kept on an object its composition reverts."""
    meta = composition.get("metadata") or {}
    return (f"{describe(managed)} is managed by the composition {composition.get('kind')} "
            f"{meta.get('namespace', '')}/{meta.get('name', '')} ({composition.get('apiVersion')}), "
            f"which reverts this fix on its next reconcile; make the change in that composition's "
            f"spec instead. It was not retargeted: {why}.")


def reverted(how_to_fix, managed, composition):
    """howToFix as it was, its apply and rollback saying first that the composition reverts them."""
    meta = composition.get("metadata") or {}
    warning = (f"# WARNING: {describe(managed)} is rendered by the composition "
               f"{composition.get('kind')} {meta.get('namespace', '')}/{meta.get('name', '')}, whose "
               "next reconcile reverts this change; make it in that composition's spec to keep it.")
    out = dict(how_to_fix)
    for k in ("apply", report_v2.HOW_TO_FIX_ROLLBACK):
        script = out.get(k)
        if not script:
            continue
        first, nl, rest = script.partition("\n")
        out[k] = (f"{first}\n{warning}\n{rest}" if first.startswith("#!") and nl
                  else f"{warning}\n{script}")
    return out

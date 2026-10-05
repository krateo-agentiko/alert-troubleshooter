"""A fix for an object a composition renders goes through the composition's values.

The objects in fixtures/composition_objects.json are shaped like a live cluster's: the CDC labels
krateo.io/composition-* on the Deployment it renders, not on its ReplicaSet or Pods, and the
composition's CRD serves one dashed chart version. Incident writes go to tests/fake_k8s.FakeK8s;
every other GET is served from the fixture; the RCA and its follow-up are canned answers.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

import composition_fix  # noqa: E402
import handler  # noqa: E402
import report_v2  # noqa: E402
from fake_k8s import FakeK8s, http_error  # noqa: E402

NS, INCIDENT = "krateo-system", "web-oom-20261005-100000"
with open(os.path.join(HERE, "fixtures", "composition_objects.json")) as f:
    OBJECTS = json.load(f)["objects"]

PRE = ("#!/usr/bin/env bash\n# Holds while web still has the 128Mi memory limit it was OOMKilled at.\n"
       "d=$(kubectl get deployment web -n shop -o json) || exit 2\n"
       "jq -e '.spec.template.spec.containers[] | select(.name == \"web\")"
       " | .resources.limits.memory == \"128Mi\"' <<<\"$d\" >/dev/null\n"
       "case $? in 0) exit 1 ;; 1) exit 0 ;; *) exit 2 ;; esac\n")
VERIFY = ("#!/usr/bin/env bash\n# Fixed once web is off the 128Mi limit and every replica is available.\n"
          "d=$(kubectl get deployment web -n shop -o json) || exit 2\n"
          "jq -e '.status.availableReplicas == .spec.replicas' <<<\"$d\" >/dev/null\n"
          "case $? in 0) exit 0 ;; 1) exit 1 ;; *) exit 2 ;; esac\n")
SET_RESOURCES = {
    "precondition": PRE, "verify": VERIFY,
    "apply": ("#!/usr/bin/env bash\n# Raise web's memory limit from 128Mi to 512Mi.\nset -euo pipefail\n"
              "kubectl set resources deployment web -n shop -c web --limits=memory=512Mi\n"),
    "rollback": ("#!/usr/bin/env bash\n# Undo apply.\nset -euo pipefail\n"
                 "kubectl set resources deployment web -n shop -c web --limits=memory=128Mi\n")}


def _path(obj):
    api, meta = obj["apiVersion"], obj["metadata"]
    plural = {"Deployment": "deployments", "ReplicaSet": "replicasets", "Pod": "pods",
              "WebApp": "webapps", "Platform": "platforms",
              "CustomResourceDefinition": "customresourcedefinitions"}[obj["kind"]]
    return handler._object_path(api, plural, meta.get("namespace", ""), meta["name"])


class Api(FakeK8s):
    """FakeK8s for Incidents, the fixture objects and composition.krateo.io discovery for the rest."""

    def __init__(self, objects=OBJECTS):
        super().__init__()
        self.objects = {_path(o): o for o in objects}
        self.reads = []

    def __call__(self, method, path, body=None, subresource=""):
        if "/incidents" in path:
            return super().__call__(method, path, body, subresource)
        assert method == "GET", (method, path)
        self.reads.append(path)
        if path == "/apis/composition.krateo.io":
            return {"versions": [{"groupVersion": "composition.krateo.io/v0-3-1"},
                                 {"groupVersion": "composition.krateo.io/v1-4-2"}]}
        if path == "/apis/composition.krateo.io/v1-4-2":
            return {"resources": [{"name": "webapps"}, {"name": "webapps/status"}]}
        if path == "/apis/composition.krateo.io/v0-3-1":
            return {"resources": [{"name": "platforms"}]}
        if path not in self.objects:
            raise http_error(404)
        return json.loads(json.dumps(self.objects[path]))


def report(how_to_fix):
    block = {"sources": [{"type": "object", "ref": "pod shop/web-679dc47cb6-z72m5",
                          "excerpt": "lastState.terminated.reason: OOMKilled"}],
             "missingContext": ["the container's memory use before it was killed"],
             "rootCause": {"statement": "web is OOMKilled at its 128Mi memory limit",
                           "confidence": 0.8, "category": "capacity"},
             "howToFix": how_to_fix}
    return f"## Root cause\nOOMKilled.\n\n```json\n{json.dumps(block)}\n```"


def choice(path, value, reason="the chart renders resources from spec.resources"):
    return f"```json\n{json.dumps({'path': path, 'value': value, 'reason': reason})}\n```"


class Case(unittest.TestCase):
    def setUp(self):
        self.api = Api()
        self.api.put(NS, INCIDENT, "web-oom", state="Analyzing")
        self.answers, self.prompts = [], []
        self._orig = (handler._k8s, handler.a2a_analyze)
        handler._k8s, handler.a2a_analyze = self.api, self._a2a

    def tearDown(self):
        handler._k8s, handler.a2a_analyze = self._orig

    def _a2a(self, prompt, context_id=None):
        self.prompts.append((prompt, context_id))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer, []

    def analyze(self, how_to_fix, *follow_up):
        self.answers = [report(how_to_fix), *follow_up]
        handler.run_analysis(NS, INCIDENT, "the prompt")
        return self.api.incidents[(NS, INCIDENT)]["status"]


class TestRetargeted(Case):
    def test_a_composition_owned_deployment_is_fixed_by_a_merge_patch_of_the_compositions_spec(self):
        st = self.analyze(SET_RESOURCES, choice(["resources", "limits", "memory"], "512Mi"))
        how = st["howToFix"]
        # The whole top-level key as read, with the one field changed.
        resources = {"limits": {"memory": "512Mi"}, "requests": {"cpu": "50m", "memory": "64Mi"}}
        self.assertEqual(how["applyAction"], {
            "verb": "patch", "apiVersion": "composition.krateo.io/v1-4-2", "resource": "webapps",
            "namespace": "shop", "name": "web", "payload": {"spec": {"resources": resources}}})
        self.assertIn("kubectl patch webapps.v1-4-2.composition.krateo.io web -n shop --type merge",
                      how["apply"])
        self.assertIn(json.dumps({"spec": {"resources": resources}}, separators=(",", ":")),
                      how["apply"])
        self.assertIn('"limits":{"memory":"128Mi"}', how["rollback"])
        self.assertTrue(how["apply"].startswith("#!/usr/bin/env bash\n# Set spec.resources.limits"
                                                ".memory on WebApp shop/web"))
        # The checks still test the workload's recovery.
        self.assertEqual((how["precondition"], how["verify"]), (PRE, VERIFY))
        self.assertNotIn("error", st)
        self.assertEqual(st["state"], "Open")

    def test_the_follow_up_runs_on_the_incidents_thread_with_the_spec_and_its_schema(self):
        self.analyze(SET_RESOURCES, choice(["resources", "limits", "memory"], "512Mi"))
        (_, first), (prompt, second) = self.prompts
        self.assertEqual(first, second)
        self.assertEqual(second, handler._context_id(INCIDENT))
        self.assertIn("Deployment shop/web", prompt)
        self.assertIn("WebApp shop/web (composition.krateo.io/v1-4-2)", prompt)
        self.assertIn('"128Mi"', prompt)                       # the current spec
        self.assertIn('"startupProbe"', prompt)                # the v1-4-2 schema, not vacuum's
        self.assertIn("Platform shop/platform", prompt)        # its own parent composition
        self.assertIn("kubectl set resources deployment web", prompt)

    def test_a_pod_is_walked_up_its_owners_to_the_labelled_deployment(self):
        how = {**SET_RESOURCES,
               "apply": ("#!/usr/bin/env bash\n# Label the pod.\nset -euo pipefail\n"
                         "kubectl label pod web-679dc47cb6-z72m5 -n shop tier=web\n"),
               "applyAction": {"verb": "patch", "apiVersion": "v1", "resource": "pods",
                               "namespace": "shop", "name": "web-679dc47cb6-z72m5",
                               "payload": {"metadata": {"labels": {"tier": "web"}}}}}
        st = self.analyze(how, choice(["startupProbe", "initialDelaySeconds"], 5))
        reads = self.api.reads
        self.assertLess(reads.index("/api/v1/namespaces/shop/pods/web-679dc47cb6-z72m5"),
                        reads.index("/apis/apps/v1/namespaces/shop/replicasets/web-679dc47cb6"))
        self.assertIn("/apis/apps/v1/namespaces/shop/deployments/web", reads)
        # spec.startupProbe is unset: the schema's default is the value the change is made to.
        self.assertEqual(st["howToFix"]["applyAction"]["payload"], {"spec": {"startupProbe": {
            "httpGet": {"path": "/health", "port": "http"}, "periodSeconds": 1,
            "initialDelaySeconds": 5}}})
        self.assertIn('-p \'{"spec":{"startupProbe":null}}\'', st["howToFix"]["rollback"])

    def test_without_the_labels_naming_it_the_composition_is_found_by_its_uid(self):
        dep = next(o for o in OBJECTS if o["kind"] == "Deployment" and o["metadata"]["name"] == "web")
        dep = json.loads(json.dumps(dep))
        labels = dep["metadata"]["labels"]
        for k in [k for k in labels if k.startswith("krateo.io/") and k != composition_fix.LABEL_ID]:
            del labels[k]
        self.api.objects[_path(dep)] = dep
        st = self.analyze(SET_RESOURCES, choice(["resources", "limits", "memory"], "512Mi"))
        self.assertEqual(st["howToFix"]["applyAction"]["resource"], "webapps")
        self.assertIn("/apis/composition.krateo.io", self.api.reads)       # discovery
        self.assertIn("/apis/composition.krateo.io/v1-4-2/namespaces/shop/webapps/web",
                      self.api.reads)


class TestKept(Case):
    def test_an_unowned_deployment_keeps_its_fix_and_asks_nothing_more(self):
        how = {k: v.replace("deployment web", "deployment api") for k, v in SET_RESOURCES.items()}
        st = self.analyze(how)
        self.assertEqual(st["howToFix"], how)
        self.assertEqual(len(self.prompts), 1)
        self.assertNotIn("composition", " ".join(st["missingContext"]))

    def test_a_key_the_composition_does_not_have_keeps_the_fix_and_says_it_is_reverted(self):
        action = {"verb": "patch", "apiVersion": "apps/v1", "resource": "deployments",
                  "namespace": "shop", "name": "web", "payload": {"spec": {"replicas": 3}}}
        how = {**SET_RESOURCES, "applyAction": action}
        st = self.analyze(how, choice(["memoryLimit"], "512Mi"))
        out = st["howToFix"]
        self.assertEqual(out["applyAction"], action)
        self.assertEqual((out["precondition"], out["verify"]), (PRE, VERIFY))
        for script in ("apply", "rollback"):
            first, second, rest = out[script].split("\n", 2)
            self.assertEqual(first, "#!/usr/bin/env bash")
            self.assertTrue(second.startswith("# WARNING: Deployment shop/web is rendered by the "
                                              "composition WebApp shop/web"), second)
            self.assertEqual(f"{first}\n{rest}", how[script])
        note = st["missingContext"][-1]
        self.assertIn("WebApp shop/web (composition.krateo.io/v1-4-2)", note)
        self.assertIn("spec.memoryLimit, which is not a key of the composition's spec", note)
        self.assertIn("the container's memory use before it was killed", st["missingContext"])

    def test_no_spec_value_and_a_failed_follow_up_keep_the_fix_with_the_warning(self):
        for follow_up, why in ((json.dumps({"path": None, "reason": "set by the parent"}),
                                "found no spec value"),
                               (RuntimeError("stream closed"), "follow-up analysis failed")):
            with self.subTest(why=why):
                self.api = handler._k8s = Api()
                self.api.put(NS, INCIDENT, "web-oom", state="Analyzing")
                st = self.analyze(SET_RESOURCES, follow_up)
                self.assertIn("# WARNING:", st["howToFix"]["apply"])
                self.assertIn(why, st["missingContext"][-1])

    def test_a_delete_is_not_retargeted(self):
        how = {**SET_RESOURCES,
               "apply": ("#!/usr/bin/env bash\n# Restart the pod.\nset -euo pipefail\n"
                         "kubectl delete pod web-679dc47cb6-z72m5 -n shop --ignore-not-found\n")}
        how.pop("rollback")
        st = self.analyze(how)
        self.assertEqual(st["howToFix"], how)
        self.assertEqual(len(self.prompts), 1)

    def test_an_unreadable_target_keeps_the_fix(self):
        handler._k8s = lambda m, p, b=None, subresource="": (
            self.api(m, p, b, subresource) if "/incidents" in p else (_ for _ in ()).throw(http_error(403)))
        st = self.analyze(SET_RESOURCES)
        self.assertEqual(st["howToFix"], SET_RESOURCES)


class TestScriptTargets(unittest.TestCase):
    def targets(self, apply, action=None):
        how = {"apply": apply} | ({"applyAction": action} if action else {})
        return composition_fix.written_targets(how)

    def test_kubectl_writes_are_read_off_the_apply_script(self):
        cases = {
            "kubectl set resources deployment web -n shop -c web --limits=memory=512Mi":
                ("apps/v1", "deployments", "shop", "web"),
            "kubectl set image deploy/web web=ghcr.io/example/web:1.4.3 --namespace=shop":
                ("apps/v1", "deployments", "shop", "web"),
            "kubectl -n shop patch statefulsets.apps db --type strategic \\\n  -p '{\"spec\":{}}'":
                ("apps/v1", "statefulsets", "shop", "db"),
            "kubectl scale sts db --replicas=3 -n shop": ("apps/v1", "statefulsets", "shop", "db"),
        }
        for line, want in cases.items():
            with self.subTest(line=line):
                self.assertEqual(self.targets(f"#!/usr/bin/env bash\nset -e\n{line}\n"), [want])

    def test_reads_deletes_restarts_and_composition_writes_are_not_targets(self):
        apply = ("#!/usr/bin/env bash\n"
                 "d=$(kubectl get deployment web -n shop -o json)\n"
                 "kubectl delete pod web-1 -n shop\n"
                 "kubectl rollout restart deployment/web -n shop\n"
                 "kubectl patch webapps.composition.krateo.io web -n shop --type merge -p '{}'\n"
                 "# kubectl patch deployment web -n shop\n")
        self.assertEqual(self.targets(apply), [])

    def test_the_apply_action_comes_first_without_repeats(self):
        action = {"verb": "patch", "apiVersion": "apps/v1", "resource": "deployments",
                  "namespace": "shop", "name": "web", "payload": {"spec": {"replicas": 3}}}
        self.assertEqual(self.targets("kubectl scale deployment web -n shop --replicas=3", action),
                         [("apps/v1", "deployments", "shop", "web")])


class TestChoice(unittest.TestCase):
    COMPOSITION = next(o for o in OBJECTS if o["kind"] == "WebApp")
    SCHEMA = next(o for o in OBJECTS if o["kind"] == "CustomResourceDefinition")[
        "spec"]["versions"][1]["schema"]["openAPIV3Schema"]["properties"]["spec"]

    def retarget(self, path, value):
        return composition_fix.retarget(SET_RESOURCES, {"kind": "Deployment"}, self.COMPOSITION,
                                        "webapps", self.SCHEMA, path, value)

    def test_the_last_fenced_object_with_a_path_is_the_answer(self):
        text = "First ```json\n{\"x\": 1}\n``` then\n" + choice(["image", "tag"], "1.4.3", "r")
        self.assertEqual(composition_fix.parse_choice(text), (["image", "tag"], "1.4.3", "r"))

    def test_an_unusable_answer_is_no_choice(self):
        for text in ("no json", '{"path": "image.tag", "value": 1}', '{"path": ["image"]}',
                     '{"path": [], "value": 1}', '{"path": null, "reason": "none"}'):
            with self.subTest(text=text), self.assertRaises(composition_fix.NoChoice):
                composition_fix.parse_choice(text)

    def test_a_key_in_the_schema_but_unset_in_the_spec_is_usable(self):
        how, why = self.retarget(["replicaCount"], 3)
        self.assertIsNone(why)
        self.assertEqual(how["applyAction"]["payload"], {"spec": {"replicaCount": 3}})

    def test_a_field_the_schema_does_not_declare_is_unusable(self):
        how, why = self.retarget(["startupProbe", "timeoutSeconds"], 3)
        self.assertIsNone(how)
        self.assertIn("spec.startupProbe.timeoutSeconds, which the composition's schema does not "
                      "declare", why)
        # Below a field that keeps unknown fields, any key is one.
        self.assertIsNone(self.retarget(["resources", "limits", "cpu"], "500m")[1])

    def test_a_change_to_nothing_or_into_a_scalar_is_unusable(self):
        self.assertIn("already holds", self.retarget(["resources", "limits", "memory"], "128Mi")[1])
        self.assertIn("not an object", self.retarget(["image", "tag", "x"], "1")[1])

    def test_the_composition_apiversion_is_a_usable_apply_action(self):
        action = {"verb": "patch", "apiVersion": "composition.krateo.io/v1-12-36",
                  "resource": "webapps", "namespace": "shop", "name": "web",
                  "payload": {"spec": {"replicaCount": 3}}}
        self.assertEqual(report_v2._apply_action(action), (action, None))
        self.assertEqual(report_v2._apply_action({**action, "apiVersion": "x/v1-"})[1],
                         "bad apiVersion")

    def test_the_prompt_says_a_managed_resource_is_fixed_through_its_composition(self):
        self.assertIn("A RESOURCE A COMPOSITION MANAGES IS FIXED THROUGH THE COMPOSITION'S VALUES",
                      handler.build_prompt("a", "ALERT"))


if __name__ == "__main__":
    unittest.main()

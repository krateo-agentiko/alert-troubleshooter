package v1alpha1

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"sigs.k8s.io/yaml"
)

// jsonFields are the JSON field names of a struct type, inline structs flattened.
func jsonFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" {
			out = append(out, jsonFields(f.Type)...)
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func keys(m map[string]apiextensionsv1.JSONSchemaProps) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTheCRDCarriesEveryField holds the hand-written CRD to these types: a status field the schema
// lacks is pruned by the apiserver, silently.
func TestTheCRDCarriesEveryField(t *testing.T) {
	data, err := os.ReadFile("../../../helm/alert-provider-crds/templates/crd.alert.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(data, &crd); err != nil {
		t.Fatal(err)
	}
	if len(crd.Spec.Versions) != 1 || crd.Spec.Versions[0].Name != Version || crd.Spec.Group != Group {
		t.Fatalf("versions %v", crd.Spec.Versions)
	}
	props := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties
	for _, c := range []struct {
		name string
		typ  reflect.Type
	}{{"spec", reflect.TypeOf(AlertSpec{})}, {"status", reflect.TypeOf(AlertStatus{})}} {
		if got, want := keys(props[c.name].Properties), jsonFields(c.typ); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: CRD %v, types %v", c.name, got, want)
		}
	}
}

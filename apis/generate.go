//go:build generate
// +build generate

// Generate the deepcopy methodsets. The Alert CRD is written by hand, in helm/alert-provider-crds;
// crd_test.go holds it to these types.
//go:generate go run -tags generate sigs.k8s.io/controller-tools/cmd/controller-gen object:headerFile=../hack/boilerplate.go.txt paths=./...

package apis

import (
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen" //nolint:typecheck
)

// Package apis contains the Kubernetes API groups of the alert provider.
package apis

import (
	"k8s.io/apimachinery/pkg/runtime"

	alertv1alpha1 "github.com/krateo-platformops/alert-troubleshooter/apis/alert/v1alpha1"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes,
		alertv1alpha1.SchemeBuilder.AddToScheme,
	)
}

// AddToSchemes may be used to add all resources defined in the project to a Scheme
var AddToSchemes runtime.SchemeBuilder

// AddToScheme adds all Resources to the Scheme
func AddToScheme(s *runtime.Scheme) error {
	return AddToSchemes.AddToScheme(s)
}

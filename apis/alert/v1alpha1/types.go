package v1alpha1

import (
	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	prv1 "github.com/krateo-platformops/provider-runtime/apis/common/v1"
	"github.com/krateo-platformops/provider-runtime/pkg/meta"
	"github.com/krateo-platformops/provider-runtime/pkg/resource"
)

// AnnotationPaused, "true" on an Alert, skips its firings: no incident opens and none is counted.
// The spec is still pushed to HyperDX and the state still mirrored. It is provider-runtime's pause
// annotation, which stops a whole reconcile, so the Alert keeps it out of provider-runtime's view
// (see GetAnnotations).
const AnnotationPaused = meta.AnnotationKeyReconciliationPaused

// Phases of an Alert's reconcile (status.phase).
const (
	// PhasePending: no HyperDX alert yet.
	PhasePending = "Pending"
	// PhaseInvalid: the threshold can only have one outcome.
	PhaseInvalid = "Invalid"
	// PhaseSynced: the spec is the live HyperDX alert.
	PhaseSynced = "Synced"
	// PhaseSpecDrift: the spec could not be pushed, so the live alert does not match it.
	PhaseSpecDrift = "SpecDrift"
	// PhaseError: the reconcile failed.
	PhaseError = "Error"
)

// AlertSpec is what to alert on. The CRD (helm/alert-provider-crds) carries the schema.
type AlertSpec struct {
	// DisplayName is shown in the portal and in the RCA prompt; metadata.name when empty.
	DisplayName string `json:"displayName,omitempty"`

	// Where is the ClickHouse SQL boolean expression over the logs source the alert counts.
	Where string `json:"where,omitempty"`

	// Interval is the evaluation window.
	Interval string `json:"interval,omitempty"`

	// Threshold is the value the count is compared with, as the JSON number it was written as.
	Threshold json.Number `json:"threshold,omitempty"`

	// ThresholdType is how the count is compared with the threshold.
	ThresholdType string `json:"thresholdType,omitempty"`

	// Message is the notification message.
	Message string `json:"message,omitempty"`
}

// AlertStatus mirrors the live HyperDX alert.
type AlertStatus struct {
	prv1.ConditionedStatus `json:",inline"`

	HyperdxAlertID     string `json:"hyperdxAlertId,omitempty"`
	HyperdxDashboardID string `json:"hyperdxDashboardId,omitempty"`

	// State is the live HyperDX alert state (OK / ALERT / PENDING).
	State string `json:"state,omitempty"`

	// OkSince is when the alert last turned OK; empty while state is anything but OK.
	OkSince string `json:"okSince,omitempty"`

	// Phase is the reconcile phase: Pending, Invalid, Synced, SpecDrift or Error.
	Phase string `json:"phase,omitempty"`

	Error        string `json:"error,omitempty"`
	LastSyncedAt string `json:"lastSyncedAt,omitempty"`
}

// +kubebuilder:object:root=true

// An Alert is a desired HyperDX alert; its status mirrors the live one.
type Alert struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AlertSpec   `json:"spec"`
	Status AlertStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AlertList contains a list of Alert.
type AlertList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Alert `json:"items"`
}

var (
	_ resource.Managed     = &Alert{}
	_ resource.ManagedList = &AlertList{}
)

// Paused says the Alert's firings are skipped.
func (mg *Alert) Paused() bool {
	return mg.Annotations[AnnotationPaused] == "true"
}

// GetAnnotations returns the annotations without AnnotationPaused. provider-runtime reads the
// pause through this method and would skip the Alert's whole reconcile; an Alert's pause skips
// only its firings, which read it through Paused.
func (mg *Alert) GetAnnotations() map[string]string {
	if _, ok := mg.Annotations[AnnotationPaused]; !ok {
		return mg.Annotations
	}
	out := make(map[string]string, len(mg.Annotations)-1)
	for k, v := range mg.Annotations {
		if k != AnnotationPaused {
			out[k] = v
		}
	}
	return out
}

// SetAnnotations sets the annotations and keeps AnnotationPaused, which GetAnnotations hides from
// the callers that set them back.
func (mg *Alert) SetAnnotations(a map[string]string) {
	paused, ok := mg.Annotations[AnnotationPaused]
	mg.Annotations = a
	if ok {
		if mg.Annotations == nil {
			mg.Annotations = map[string]string{}
		}
		mg.Annotations[AnnotationPaused] = paused
	}
}

// GetCondition of this Alert.
func (mg *Alert) GetCondition(ct prv1.ConditionType) prv1.Condition {
	return mg.Status.GetCondition(ct)
}

// SetConditions of this Alert.
func (mg *Alert) SetConditions(c ...prv1.Condition) {
	mg.Status.SetConditions(c...)
}

// GetItems of this AlertList.
func (l *AlertList) GetItems() []resource.Managed {
	items := make([]resource.Managed, len(l.Items))
	for i := range l.Items {
		items[i] = &l.Items[i]
	}
	return items
}

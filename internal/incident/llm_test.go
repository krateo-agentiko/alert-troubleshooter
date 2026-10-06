package incident

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/krateo-platformops/alert-troubleshooter/internal/compare"
)

var names = []string{"a", "b"}

type completion struct {
	url, auth string
	body      map[string]any
}

// llmCase is a Comparer over a fake apiserver holding spec as the ModelConfig, and a fake
// chat-completions endpoint answering with content, or with status.
func llmCase(t *testing.T, spec func(url string) map[string]any, status int, content string, objs ...runtime.Object) (*Comparer, *[]completion) {
	t.Helper()
	var got []completion
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = append(got, completion{r.URL.String(), r.Header.Get("Authorization"), body})
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}}}})
	}))
	t.Cleanup(srv.Close)
	mc := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kagent.dev/v1alpha2", "kind": "ModelConfig",
		"metadata": map[string]any{"name": "gemini-flash", "namespace": ns}, "spec": spec(srv.URL)}}
	reader := fake.NewClientBuilder().WithRuntimeObjects(append(objs, mc)...).Build()
	return &Comparer{Reader: reader, Namespace: ns, ModelConfig: "gemini-flash", Timeout: time.Second,
		JWT: func(context.Context) string { return "service-jwt" }}, &got
}

func gateway(url string) map[string]any {
	return map[string]any{"provider": "OpenAI", "model": "gemini-3.8-flash", "apiKeyPassthrough": true,
		"openAI": map[string]any{"baseUrl": url + "/llm/v1/"}}
}

func TestOneChatCompletionOnTheModelConfigWithTheServiceJWT(t *testing.T) {
	c, got := llmCase(t, gateway, 0, `{"match": 1, "reason": "r"}`)
	match, reason, err := c.Compare(context.Background(), "p", names)
	eq(t, "verdict", []any{match, reason, err}, []any{"a", "r", nil})
	g := (*got)[0]
	eq(t, "url", g.url, "/llm/v1/chat/completions")
	eq(t, "auth", g.auth, "Bearer service-jwt")
	eq(t, "body", g.body, map[string]any{"model": "gemini-3.8-flash", "messages": []any{
		map[string]any{"role": "system", "content": compare.System}, map[string]any{"role": "user", "content": "p"}}})
}

func TestAGeminiModelConfigUsesItsKeySecret(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "k", Namespace: ns}, Data: map[string][]byte{"apiKey": []byte("AIza-key")}}
	c, _ := llmCase(t, func(string) map[string]any {
		return map[string]any{"provider": "Gemini", "model": "m", "apiKeySecret": "k", "apiKeySecretKey": "apiKey"}
	}, 0, "", secret)
	url, model, key, err := c.endpoint(context.Background())
	eq(t, "endpoint", []any{url, model, key, err}, []any{GeminiOpenAIURL, "m", "AIza-key", nil})
}

func TestAnUnsupportedProviderIsNoVerdict(t *testing.T) {
	c, got := llmCase(t, func(string) map[string]any { return map[string]any{"provider": "GeminiVertexAI", "model": "m"} }, 0, `{"match": 1}`)
	_, _, err := c.Compare(context.Background(), "p", names)
	if !compare.IsNoVerdict(err) || !strings.Contains(err.Error(), "GeminiVertexAI") {
		t.Fatalf("err %v", err)
	}
	eq(t, "calls", len(*got), 0)
}

func TestA429IsNoVerdictRateLimited(t *testing.T) {
	c, _ := llmCase(t, gateway, http.StatusTooManyRequests, "")
	_, _, err := c.Compare(context.Background(), "p", names)
	if !compare.IsNoVerdict(err) || err.Error() != "rate-limited" {
		t.Fatalf("err %v", err)
	}
}

func TestAnyOtherFailureIsNoVerdict(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusBadRequest} {
		c, _ := llmCase(t, gateway, status, "")
		_, _, err := c.Compare(context.Background(), "p", names)
		if !compare.IsNoVerdict(err) || !strings.HasPrefix(err.Error(), "the call failed") {
			t.Fatalf("%d: err %v", status, err)
		}
	}
	c, _ := llmCase(t, func(string) map[string]any { return gateway("http://127.0.0.1:1") }, 0, "")
	if _, _, err := c.Compare(context.Background(), "p", names); !compare.IsNoVerdict(err) || !strings.HasPrefix(err.Error(), "the call failed") {
		t.Fatalf("unreachable: err %v", err)
	}
}

func TestAnAnswerWithoutAVerdictIsNoVerdict(t *testing.T) {
	c, _ := llmCase(t, gateway, 0, "I think they are the same.")
	if _, _, err := c.Compare(context.Background(), "p", names); !compare.IsNoVerdict(err) {
		t.Fatalf("err %v", err)
	}
}

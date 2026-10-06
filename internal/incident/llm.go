package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/krateo-platformops/alert-provider/internal/compare"
	"github.com/krateo-platformops/alert-provider/internal/httpx"
	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// GeminiOpenAIURL is Gemini's OpenAI-compatible endpoint, for a ModelConfig of provider Gemini.
const GeminiOpenAIURL = "https://generativelanguage.googleapis.com/v1beta/openai"

var modelConfigGVK = schema.GroupVersionKind{Group: "kagent.dev", Version: "v1alpha2", Kind: "ModelConfig"}

// Comparer is the comparison model: one chat completion per firing, with no agent and no tools.
type Comparer struct {
	// Reader reads the ModelConfig and its key Secret, past any cache.
	Reader client.Reader
	// Namespace and ModelConfig name the kagent ModelConfig whose model judges which open incident
	// covers a firing.
	Namespace   string
	ModelConfig string
	Timeout     time.Duration
	JWT         func(context.Context) string
}

// endpoint is the chat-completions URL, model and key the ModelConfig names, as kagent resolves
// it: provider OpenAI at its baseUrl (with apiKeyPassthrough, the key is the caller's JWT, here the
// service JWT), or provider Gemini at its OpenAI-compatible endpoint. The key comes from the
// ModelConfig's apiKeySecret otherwise.
func (c *Comparer) endpoint(ctx context.Context) (string, any, string, error) {
	mc := &unstructured.Unstructured{}
	mc.SetGroupVersionKind(modelConfigGVK)
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: c.ModelConfig}, mc); err != nil {
		return "", nil, "", err
	}
	spec, _ := mc.Object["spec"].(map[string]any)
	var url string
	switch provider := spec["provider"]; provider {
	case "OpenAI":
		openAI, _ := spec["openAI"].(map[string]any)
		url, _ = openAI["baseUrl"].(string)
		if url == "" {
			url = "https://api.openai.com/v1"
		}
	case "Gemini":
		url = GeminiOpenAIURL
	default:
		return "", nil, "", fmt.Errorf("ModelConfig %s: provider %s has no chat-completions endpoint here",
			c.ModelConfig, pyfmt.Str(provider))
	}
	key := ""
	if pyfmt.Truthy(spec["apiKeyPassthrough"]) {
		key = c.JWT(ctx)
	} else if name, _ := spec["apiKeySecret"].(string); name != "" {
		secret := &corev1.Secret{}
		if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: name}, secret); err != nil {
			return "", nil, "", err
		}
		k := pyfmt.Str(spec["apiKeySecretKey"])
		v, ok := secret.Data[k]
		if !ok {
			return "", nil, "", fmt.Errorf("'%s'", k)
		}
		key = string(v)
	}
	return strings.TrimRight(url, "/"), spec["model"], key, nil
}

func failed(err error) error {
	return &compare.NoVerdict{Reason: "the call failed: " + pyfmt.Cut(err.Error(), 200)}
}

// Compare is one chat completion, compare.System then prompt, and its verdict: the matched name,
// "" for none, and the reason. Any failure, a 429 from the gateway's LLM rate limit included, is a
// compare.NoVerdict.
func (c *Comparer) Compare(ctx context.Context, prompt string, names []string) (string, string, error) {
	url, model, key, err := c.endpoint(ctx)
	if err != nil {
		return "", "", failed(err)
	}
	body, err := json.Marshal(map[string]any{"model": model, "messages": []any{
		map[string]any{"role": "system", "content": compare.System},
		map[string]any{"role": "user", "content": prompt}}})
	if err != nil {
		return "", "", failed(err)
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", "", failed(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", failed(err)
	}
	defer resp.Body.Close()
	if err := httpx.Check(resp); err != nil {
		if httpx.Code(err) == http.StatusTooManyRequests {
			return "", "", &compare.NoVerdict{Reason: "rate-limited"}
		}
		return "", "", failed(err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", failed(err)
	}
	text, err := completionText(data)
	if err != nil {
		return "", "", failed(err)
	}
	return compare.ParseVerdict(text, names)
}

// completionText is choices[0].message.content of a chat completion.
func completionText(data []byte) (string, error) {
	v, err := pyfmt.Decode(data)
	if err != nil {
		return "", err
	}
	m, _ := v.(map[string]any)
	choices, ok := m["choices"].([]any)
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("the completion has no choices")
	}
	choice, _ := choices[0].(map[string]any)
	msg, ok := choice["message"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("the completion has no message")
	}
	content, ok := msg["content"]
	if !ok {
		return "", fmt.Errorf("'content'")
	}
	s, _ := content.(string)
	return s, nil
}

package incident

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/krateo-platformops/provider-runtime/pkg/logging"

	"github.com/krateo-platformops/alert-provider/internal/httpx"
)

// ServiceJWT is the alert provider's service identity, for intra-service auth. The alert-to-RCA
// pipeline is autonomous and carries no user JWT, but incident-agent's MCP tools sit behind
// agentgateway, whose authz allows /mcp only with a valid Krateo JWT. So the provider exchanges
// its projected ServiceAccount token (audience "authn") at authn's /serviceaccount/login for a
// Krateo JWT and presents it on the A2A call; incident-agent (KAGENT_PROPAGATE_TOKEN=true) then
// propagates it to the gateway on the MCP tool calls. It is opt-in and graceful: with no URL or no
// projected token mounted the exchange is skipped and the calls go unauthenticated.
type ServiceJWT struct {
	// URL is authn's base URL; empty disables the exchange.
	URL string
	// TokenFile is the projected ServiceAccount token, audience "authn".
	TokenFile string
	Log       logging.Logger

	mu    sync.Mutex // serializes the exchange so concurrent calls reuse one JWT
	token string
	exp   float64
}

var authnHTTP = &http.Client{Timeout: 15 * time.Second}

// Get is the JWT, cached until shortly before its own expiry, or "" when the exchange is disabled
// or fails: the caller then proceeds unauthenticated, so an auth hiccup never breaks the RCA.
func (s *ServiceJWT) Get(ctx context.Context) string {
	url := strings.TrimRight(s.URL, "/")
	if url == "" {
		return ""
	}
	if _, err := os.Stat(s.TokenFile); err != nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && float64(time.Now().UnixNano())/1e9 < s.exp-60 {
		return s.token
	}
	jwt, exp, err := s.exchange(ctx, url)
	if err != nil {
		s.Log.Info(fmt.Sprintf("[authn] service-JWT exchange failed (%s); continuing without a JWT", err))
		return ""
	}
	s.token, s.exp = jwt, exp
	return jwt
}

func (s *ServiceJWT) exchange(ctx context.Context, url string) (string, float64, error) {
	sa, err := os.ReadFile(s.TokenFile)
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/serviceaccount/login", bytes.NewReader(nil))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(sa)))
	resp, err := authnHTTP.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if err := httpx.Check(resp); err != nil {
		return "", 0, err
	}
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", 0, err
	}
	if body.AccessToken == "" {
		return "", 0, fmt.Errorf("authn response had no accessToken")
	}
	// Cached until the JWT's own exp, read off its base64url payload.
	parts := strings.Split(body.AccessToken, ".")
	if len(parts) < 2 {
		return "", 0, fmt.Errorf("the accessToken is not a JWT")
	}
	seg, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", 0, err
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(seg, &claims); err != nil {
		return "", 0, err
	}
	exp := claims.Exp
	if exp == 0 {
		exp = float64(time.Now().Unix() + 300)
	}
	return body.AccessToken, exp, nil
}

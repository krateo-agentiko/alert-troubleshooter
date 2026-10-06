// Package bootstrap provisions the HyperDX API keys into a Secret, headlessly. The installer runs
// it as a Job. HyperDX has no key endpoint outside its UI, so it drives the UI's own endpoints:
//
//	GET  /api/installation                 is a team already set up? (idempotency)
//	  false -> POST /api/register/password (create the first admin and team)
//	  true  -> POST /api/login/password    (log in)
//	GET  /api/team, /api/me                team.apiKey, user.accessKey (the /api/v2 key)
//	-> written into the hyperdx-api-token Secret.
//
// Auth notes (ClickStack v2.27):
//   - register enforces a password policy: at least 12 characters with upper, lower, digit and
//     special, and a matching confirmPassword. The admin-creds Secret must satisfy it.
//   - HyperDX runs with FRONTEND_URL=http://localhost:3000, so a failed login redirects to
//     http://localhost:3000/login?err=authFail, unreachable from the pod. Redirects are not
//     followed: the status and Location decide success.
//   - A successful login or register answers 303 with set-cookie: connect.sid=...;
//     Domain=localhost. No HTTP client sends a Domain=localhost cookie back to the in-cluster
//     service host, so the connect.sid value is lifted from the raw Set-Cookie header and sent
//     explicitly.
//
// It is idempotent and retry-friendly: the Job's backoffLimit covers HyperDX still booting.
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/krateo-platformops/alert-provider/internal/httpx"
	"github.com/krateo-platformops/alert-provider/internal/pyfmt"
)

// Config is the HyperDX to log in to, its admin, and the Secret to write.
type Config struct {
	URL, Email, Password  string
	Namespace, SecretName string
	// Tries and Wait pace the wait for HyperDX to answer.
	Tries int
	Wait  time.Duration
	Logf  func(format string, args ...any)
}

var sidRE = regexp.MustCompile(`connect\.sid=([^;]+)`)

type session struct {
	cfg  Config
	http *http.Client
}

func (s *session) do(ctx context.Context, method, path string, body any, headers map[string]string, timeout time.Duration) (*http.Response, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, s.cfg.URL+path, rd)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp, data, err
}

// authOK: success is a 2xx, or a 3xx whose Location is not an error redirect (failures redirect to
// .../login?err=authFail). The redirect is never followed.
func authOK(resp *http.Response) bool {
	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return !strings.Contains(loc, "err") && !strings.Contains(loc, "authFail")
	}
	return resp.StatusCode < 400
}

// sid is connect.sid off the raw Set-Cookie header (see the package doc).
func sid(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	if m := sidRE.FindStringSubmatch(strings.Join(resp.Header.Values("Set-Cookie"), ", ")); m != nil {
		return m[1]
	}
	return ""
}

// waitForHyperDX polls /api/installation while HyperDX boots, and says whether a team exists.
func (s *session) waitForHyperDX(ctx context.Context) (bool, error) {
	for i := range s.cfg.Tries {
		resp, data, err := s.do(ctx, http.MethodGet, "/api/installation", nil, nil, 5*time.Second)
		if err == nil && resp.StatusCode < 400 {
			var body map[string]any
			if json.Unmarshal(data, &body) == nil {
				existing, _ := body["isTeamExisting"].(bool)
				return existing, nil
			}
		}
		s.cfg.Logf("[wait] HyperDX not ready yet (%d/%d)", i+1, s.cfg.Tries)
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(s.cfg.Wait):
		}
	}
	return false, fmt.Errorf("HyperDX /api/installation never became ready")
}

func excerpt(data []byte, n int) string {
	return pyfmt.Repr(pyfmt.Cut(string(data), n))
}

// register creates the first admin and team, and returns the successful response.
func (s *session) register(ctx context.Context) *http.Response {
	resp, data, err := s.do(ctx, http.MethodPost, "/api/register/password",
		map[string]any{"email": s.cfg.Email, "password": s.cfg.Password, "confirmPassword": s.cfg.Password}, nil, 30*time.Second)
	if err != nil {
		s.cfg.Logf("[register] %s", err)
		return nil
	}
	if !authOK(resp) {
		s.cfg.Logf("[register] %d loc=%s body=%s", resp.StatusCode, pyfmt.Repr(resp.Header.Get("Location")), excerpt(data, 300))
		return nil
	}
	return resp
}

// login tries the email field, then username, and returns the successful response.
func (s *session) login(ctx context.Context) *http.Response {
	for _, field := range []string{"email", "username"} {
		resp, data, err := s.do(ctx, http.MethodPost, "/api/login/password",
			map[string]any{field: s.cfg.Email, "password": s.cfg.Password}, nil, 30*time.Second)
		if err != nil {
			s.cfg.Logf("[login] %s", err)
			continue
		}
		if authOK(resp) {
			return resp
		}
		s.cfg.Logf("[login] %d loc=%s body=%s", resp.StatusCode, pyfmt.Repr(resp.Header.Get("Location")), excerpt(data, 150))
	}
	return nil
}

// apiKeys are team.apiKey (GET /api/team, the legacy internal API) and user.accessKey (GET
// /api/me, the v2 external API since HyperDX 2.28). Both are stored, so consumers can migrate
// without a re-bootstrap.
func (s *session) apiKeys(ctx context.Context, sid string) (string, string, error) {
	headers := map[string]string{}
	if sid != "" {
		headers["Cookie"] = "connect.sid=" + sid
	}
	resp, data, err := s.do(ctx, http.MethodGet, "/api/team", nil, headers, 30*time.Second)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", "", fmt.Errorf("/api/team redirected to %s — not authenticated", pyfmt.Repr(resp.Header.Get("Location")))
	}
	if err := httpx.Check(resp); err != nil {
		return "", "", err
	}
	v, err := pyfmt.Decode(data)
	if err != nil {
		return "", "", err
	}
	if l, ok := v.([]any); ok {
		v = map[string]any{}
		if len(l) > 0 {
			v = l[0]
		}
	}
	team, _ := v.(map[string]any)
	teamKey, _ := team["apiKey"].(string)
	if teamKey == "" {
		return "", "", fmt.Errorf("no apiKey in /api/team response: %s", pyfmt.Cut(pyfmt.Dumps(v), 200))
	}

	resp, data, err = s.do(ctx, http.MethodGet, "/api/me", nil, headers, 30*time.Second)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return "", "", fmt.Errorf("/api/me redirected — not authenticated")
	}
	if err := httpx.Check(resp); err != nil {
		return "", "", err
	}
	v, err = pyfmt.Decode(data)
	if err != nil {
		return "", "", err
	}
	me, _ := v.(map[string]any)
	userKey, _ := me["accessKey"].(string)
	if userKey == "" {
		s.cfg.Logf("[warn] no accessKey in /api/me response (HyperDX < 2.28?): %s", pyfmt.Cut(pyfmt.Dumps(v), 200))
	}
	return teamKey, userKey, nil
}

// writeSecret creates or updates the Secret: token is team.apiKey (the legacy internal API),
// accessKey is user.accessKey (the v2 external API's Bearer auth).
func writeSecret(ctx context.Context, kube kubernetes.Interface, cfg Config, teamKey, userKey string) error {
	data := map[string]string{"token": teamKey}
	if userKey != "" {
		data["accessKey"] = userKey
	}
	secrets := kube.CoreV1().Secrets(cfg.Namespace)
	_, err := secrets.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: cfg.SecretName, Namespace: cfg.Namespace},
		StringData: data,
	}, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	patch, err := json.Marshal(map[string]any{"stringData": data})
	if err != nil {
		return err
	}
	_, err = secrets.Patch(ctx, cfg.SecretName, types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// Run provisions the keys into the Secret.
func Run(ctx context.Context, cfg Config, kube kubernetes.Interface) error {
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	s := &session{cfg: cfg, http: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}

	existing, err := s.waitForHyperDX(ctx)
	if err != nil {
		return err
	}
	var resp *http.Response
	if existing {
		cfg.Logf("team exists -> logging in")
		if resp = s.login(ctx); resp == nil {
			return fmt.Errorf("login failed for %s", cfg.Email)
		}
	} else {
		cfg.Logf("no team -> registering first admin %s", cfg.Email)
		if resp = s.register(ctx); resp == nil {
			// someone registered between the check and now: fall back to login
			cfg.Logf("register failed; trying login")
			if resp = s.login(ctx); resp == nil {
				return fmt.Errorf("register and login both failed for %s", cfg.Email)
			}
		}
	}
	id := sid(resp)
	if id == "" {
		// the auth response carried no cookie: an explicit login gets a fresh session
		cfg.Logf("no connect.sid on auth response; performing explicit login")
		id = sid(s.login(ctx))
	}
	teamKey, userKey, err := s.apiKeys(ctx, id)
	if err != nil {
		return err
	}
	if err := writeSecret(ctx, kube, cfg, teamKey, userKey); err != nil {
		return err
	}
	keys := []string{"token"}
	if userKey != "" {
		keys = append(keys, "accessKey")
	}
	cfg.Logf("[ok] wrote Secret %s/%s keys=%s", cfg.Namespace, cfg.SecretName, pyfmt.Repr(toAny(keys)))
	return nil
}

func toAny(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

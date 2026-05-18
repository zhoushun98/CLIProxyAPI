package quotapark

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// codexProbeEndpoint is the canonical upstream endpoint for codex inference.
// Kept as a constant rather than reaching into the executor so quotapark can
// run without importing internal/runtime/executor.
const codexProbeEndpoint = "https://chatgpt.com/backend-api/codex/responses"

// codexProbeRefreshSkew is the minimum lifetime remaining on the access token
// before a refresh is forced. Keeping it small avoids refreshing on every probe.
const codexProbeRefreshSkew = 2 * time.Minute

// codexAuthFile is the minimal subset of the on-disk JSON the probe needs.
// Other fields are ignored.
type codexAuthFile struct {
	Type         string `json:"type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	AccountID    string `json:"account_id"`
	Expired      string `json:"expired"`
	Email        string `json:"email"`
	Disabled     bool   `json:"disabled"`
}

// CodexProber probes a parked codex auth by sending a minimal inference request
// to the upstream and classifying the HTTP response.
type CodexProber struct {
	cfg     *config.Config
	prompt  string
	model   string
	maxTok  int
	connDial time.Duration
}

// NewCodexProber constructs a CodexProber bound to cfg.QuotaPark.Probe.
func NewCodexProber(cfg *config.Config) *CodexProber {
	probe := cfg.QuotaPark.Probe
	prompt := probe.Prompt
	if prompt == "" {
		prompt = "Say hi"
	}
	model := probe.Model
	if model == "" {
		model = "gpt-5-codex-mini"
	}
	maxTok := probe.MaxOutputTokens
	if maxTok <= 0 {
		maxTok = 1
	}
	return &CodexProber{
		cfg:      cfg,
		prompt:   prompt,
		model:    model,
		maxTok:   maxTok,
		connDial: 30 * time.Second,
	}
}

// Probe implements ProbeFunc. It only handles codex-type auth files; other
// providers return ProbeSkipUnsupported so the caller can decide what to do.
func (p *CodexProber) Probe(ctx context.Context, info ParkedInfo) (ProbeResult, error) {
	raw, err := os.ReadFile(info.ParkedAbsPath)
	if err != nil {
		return ProbeError, fmt.Errorf("read parked file: %w", err)
	}

	var af codexAuthFile
	if errUnmarshal := json.Unmarshal(raw, &af); errUnmarshal != nil {
		return ProbeError, fmt.Errorf("parse parked json: %w", errUnmarshal)
	}
	if strings.ToLower(strings.TrimSpace(af.Type)) != "codex" {
		return ProbeSkipUnsupported, nil
	}
	if af.AccessToken == "" && af.RefreshToken == "" {
		return ProbeError, fmt.Errorf("parked auth has neither access nor refresh token")
	}

	access := strings.TrimSpace(af.AccessToken)
	// Refresh proactively if the token is missing or near expiry. Token refresh
	// is allowed to use timeouts per AGENTS.md (credential acquisition phase).
	needsRefresh := access == ""
	if !needsRefresh && af.Expired != "" {
		if exp, errParse := time.Parse(time.RFC3339, af.Expired); errParse == nil {
			if time.Until(exp) < codexProbeRefreshSkew {
				needsRefresh = true
			}
		}
	}
	if needsRefresh {
		if af.RefreshToken == "" {
			return ProbeAuthError, fmt.Errorf("token expired and no refresh_token available")
		}
		refreshed, errRefresh := p.refreshToken(ctx, af.RefreshToken)
		if errRefresh != nil {
			return ProbeError, fmt.Errorf("refresh token: %w", errRefresh)
		}
		access = refreshed.AccessToken
		// Persist the refreshed tokens back to the parked JSON so the next probe
		// does not re-refresh and so the unparked auth resumes with fresh creds.
		if errPersist := p.persistRefreshed(info.ParkedAbsPath, raw, refreshed); errPersist != nil {
			// Persist failure is non-fatal; we can still probe with the new token.
			_ = errPersist
		}
	}
	if access == "" {
		return ProbeError, fmt.Errorf("no access token available after refresh")
	}

	body := p.buildBody()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, codexProbeEndpoint, bytes.NewReader(body))
	if err != nil {
		return ProbeError, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+access)
	if af.AccountID != "" {
		req.Header.Set("chatgpt-account-id", af.AccountID)
	}
	if ua := strings.TrimSpace(p.cfg.CodexHeaderDefaults.UserAgent); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	if betas := strings.TrimSpace(p.cfg.CodexHeaderDefaults.BetaFeatures); betas != "" {
		req.Header.Set("OpenAI-Beta", betas)
	}

	client := p.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		return ProbeError, fmt.Errorf("http do: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ProbeRecovered, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return ProbeStillExhausted, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ProbeAuthError, fmt.Errorf("upstream returned %d", resp.StatusCode)
	default:
		return ProbeError, fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
}

// buildBody returns the minimal Codex responses-API request payload.
func (p *CodexProber) buildBody() []byte {
	type inputContent struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type inputMessage struct {
		Role    string         `json:"role"`
		Content []inputContent `json:"content"`
	}
	type reqBody struct {
		Model           string         `json:"model"`
		Input           []inputMessage `json:"input"`
		MaxOutputTokens int            `json:"max_output_tokens"`
		Store           bool           `json:"store"`
		Stream          bool           `json:"stream"`
	}
	b := reqBody{
		Model: p.model,
		Input: []inputMessage{{
			Role:    "user",
			Content: []inputContent{{Type: "input_text", Text: p.prompt}},
		}},
		MaxOutputTokens: p.maxTok,
		Store:           false,
		Stream:          false,
	}
	out, _ := json.Marshal(b)
	return out
}

// refreshToken delegates to the existing codex auth refresh helper. The probe
// does not have access to the per-auth proxy URL once parked, so it uses the
// global proxy (if any) from cfg.
func (p *CodexProber) refreshToken(ctx context.Context, refreshToken string) (*codex.CodexTokenData, error) {
	proxyURL := ""
	if p.cfg != nil {
		proxyURL = p.cfg.ProxyURL
	}
	svc := codex.NewCodexAuthWithProxyURL(p.cfg, proxyURL)
	return svc.RefreshTokensWithRetry(ctx, refreshToken, 3)
}

// persistRefreshed writes the refreshed tokens back into the parked JSON file,
// preserving any fields not modified.
func (p *CodexProber) persistRefreshed(path string, original []byte, td *codex.CodexTokenData) error {
	if td == nil {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(original, &raw); err != nil {
		return err
	}
	if td.AccessToken != "" {
		raw["access_token"] = td.AccessToken
	}
	if td.RefreshToken != "" {
		raw["refresh_token"] = td.RefreshToken
	}
	if td.IDToken != "" {
		raw["id_token"] = td.IDToken
	}
	if td.AccountID != "" {
		raw["account_id"] = td.AccountID
	}
	if td.Email != "" {
		raw["email"] = td.Email
	}
	if td.Expire != "" {
		raw["expired"] = td.Expire
	}
	raw["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	encoded, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}

// httpClient builds an HTTP client that honors the global proxy from cfg.
// Connection-establishment uses a bounded dial timeout; once the upstream
// connection is established, there is no body timeout (AGENTS.md rule).
func (p *CodexProber) httpClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: (&net.Dialer{
			Timeout:   p.connDial,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if p.cfg != nil && strings.TrimSpace(p.cfg.ProxyURL) != "" {
		if u, errParse := url.Parse(p.cfg.ProxyURL); errParse == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Transport: transport}
}

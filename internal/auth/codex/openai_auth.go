// Package codex provides authentication and token management for OpenAI's Codex API.
// It handles the OAuth2 flow, including generating authorization URLs, exchanging
// authorization codes for tokens, and refreshing expired tokens. The package also
// defines data structures for storing and managing Codex authentication credentials.
package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
)

// OAuth configuration constants for OpenAI Codex
const (
	AuthURL     = "https://auth.openai.com/oauth/authorize"
	TokenURL    = "https://auth.openai.com/oauth/token"
	ClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	RedirectURI = "http://localhost:1455/auth/callback"
)

// CodexAuth handles the OpenAI OAuth2 authentication flow.
// It manages the HTTP client and provides methods for generating authorization URLs,
// exchanging authorization codes for tokens, and refreshing access tokens.
type CodexAuth struct {
	httpClient *http.Client
}

var codexRefreshGroup singleflight.Group

// NewCodexAuth creates a new CodexAuth service instance.
// It initializes an HTTP client with proxy settings from the provided configuration.
func NewCodexAuth(cfg *config.Config) *CodexAuth {
	return NewCodexAuthWithProxyURL(cfg, "")
}

// NewCodexAuthWithProxyURL creates a new CodexAuth service instance.
// proxyURL takes precedence over cfg.ProxyURL when non-empty.
func NewCodexAuthWithProxyURL(cfg *config.Config, proxyURL string) *CodexAuth {
	effectiveProxyURL := strings.TrimSpace(proxyURL)
	var sdkCfg config.SDKConfig
	if cfg != nil {
		sdkCfg = cfg.SDKConfig
		if effectiveProxyURL == "" {
			effectiveProxyURL = strings.TrimSpace(cfg.ProxyURL)
		}
	}
	sdkCfg.ProxyURL = effectiveProxyURL
	return &CodexAuth{
		httpClient: util.SetProxy(&sdkCfg, &http.Client{}),
	}
}

// GenerateAuthURL creates the OAuth authorization URL with PKCE (Proof Key for Code Exchange).
// It constructs the URL with the necessary parameters, including the client ID,
// response type, redirect URI, scopes, and PKCE challenge.
func (o *CodexAuth) GenerateAuthURL(state string, pkceCodes *PKCECodes) (string, error) {
	if pkceCodes == nil {
		return "", fmt.Errorf("PKCE codes are required")
	}

	params := url.Values{
		"client_id":                  {ClientID},
		"response_type":              {"code"},
		"redirect_uri":               {RedirectURI},
		"scope":                      {"openid email profile offline_access"},
		"state":                      {state},
		"code_challenge":             {pkceCodes.CodeChallenge},
		"code_challenge_method":      {"S256"},
		"prompt":                     {"login"},
		"id_token_add_organizations": {"true"},
		"codex_cli_simplified_flow":  {"true"},
	}

	authURL := fmt.Sprintf("%s?%s", AuthURL, params.Encode())
	return authURL, nil
}

// ExchangeCodeForTokens exchanges an authorization code for access and refresh tokens.
// It performs an HTTP POST request to the OpenAI token endpoint with the provided
// authorization code and PKCE verifier.
func (o *CodexAuth) ExchangeCodeForTokens(ctx context.Context, code string, pkceCodes *PKCECodes) (*CodexAuthBundle, error) {
	return o.ExchangeCodeForTokensWithRedirect(ctx, code, RedirectURI, pkceCodes)
}

// ExchangeCodeForTokensWithRedirect exchanges an authorization code for tokens using
// a caller-provided redirect URI. This supports alternate auth flows such as device
// login while preserving the existing token parsing and storage behavior.
func (o *CodexAuth) ExchangeCodeForTokensWithRedirect(ctx context.Context, code, redirectURI string, pkceCodes *PKCECodes) (*CodexAuthBundle, error) {
	if pkceCodes == nil {
		return nil, fmt.Errorf("PKCE codes are required for token exchange")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return nil, fmt.Errorf("redirect URI is required for token exchange")
	}

	// Prepare token exchange request
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {ClientID},
		"code":          {code},
		"redirect_uri":  {strings.TrimSpace(redirectURI)},
		"code_verifier": {pkceCodes.CodeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	// log.Debugf("Token response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Extract account ID from ID token
	claims, err := ParseJWTToken(tokenResp.IDToken)
	if err != nil {
		log.Warnf("Failed to parse ID token: %v", err)
	}

	accountID := ""
	email := ""
	if claims != nil {
		accountID = claims.GetAccountID()
		email = claims.GetUserEmail()
	}

	// Create token data
	tokenData := CodexTokenData{
		IDToken:      tokenResp.IDToken,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		AccountID:    accountID,
		Email:        email,
		Expire:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}

	// Create auth bundle
	bundle := &CodexAuthBundle{
		TokenData:   tokenData,
		LastRefresh: time.Now().Format(time.RFC3339),
	}

	return bundle, nil
}

// RefreshTokens refreshes an access token using a refresh token.
// This method is called when an access token has expired. It makes a request to the
// token endpoint to obtain a new set of tokens.
func (o *CodexAuth) RefreshTokens(ctx context.Context, refreshToken string) (*CodexTokenData, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	result, err, _ := codexRefreshGroup.Do(refreshToken, func() (interface{}, error) {
		return o.refreshTokensSingleFlight(context.WithoutCancel(ctx), refreshToken)
	})
	if err != nil {
		return nil, err
	}
	tokenData, ok := result.(*CodexTokenData)
	if !ok || tokenData == nil {
		return nil, fmt.Errorf("token refresh failed: invalid single-flight result")
	}
	return tokenData, nil
}

func (o *CodexAuth) refreshTokensSingleFlight(ctx context.Context, refreshToken string) (*CodexTokenData, error) {
	data := url.Values{
		"client_id":     {ClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"scope":         {"openid profile email"},
	}

	req, errReq := http.NewRequestWithContext(ctx, "POST", TokenURL, strings.NewReader(data.Encode()))
	if errReq != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", errReq)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, errDo := o.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("token refresh request failed: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("token refresh response body close error: %v", errClose)
		}
	}()

	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", errRead)
	}

	if resp.StatusCode != http.StatusOK {
		// Attempt to parse a structured OAuth error body so callers can distinguish
		// "refresh_token genuinely revoked" (invalid_grant / refresh_token_reused /
		// invalid_request / unauthorized_client) from transient HTTP failures. The
		// returned *OAuthError still carries the raw status code and description for
		// log fidelity.
		if oauthErr := parseOAuthErrorBody(body, resp.StatusCode); oauthErr != nil {
			return nil, oauthErr
		}
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}

	if errUnmarshal := json.Unmarshal(body, &tokenResp); errUnmarshal != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", errUnmarshal)
	}

	// Extract account ID from ID token
	claims, errParseJWT := ParseJWTToken(tokenResp.IDToken)
	if errParseJWT != nil {
		log.Warnf("Failed to parse refreshed ID token: %v", errParseJWT)
	}

	accountID := ""
	email := ""
	if claims != nil {
		accountID = claims.GetAccountID()
		email = claims.Email
	}

	return &CodexTokenData{
		IDToken:      tokenResp.IDToken,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		AccountID:    accountID,
		Email:        email,
		Expire:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339),
	}, nil
}

// CreateTokenStorage creates a new CodexTokenStorage from a CodexAuthBundle.
// It populates the storage struct with token data, user information, and timestamps.
func (o *CodexAuth) CreateTokenStorage(bundle *CodexAuthBundle) *CodexTokenStorage {
	storage := &CodexTokenStorage{
		IDToken:      bundle.TokenData.IDToken,
		AccessToken:  bundle.TokenData.AccessToken,
		RefreshToken: bundle.TokenData.RefreshToken,
		AccountID:    bundle.TokenData.AccountID,
		LastRefresh:  bundle.LastRefresh,
		Email:        bundle.TokenData.Email,
		Expire:       bundle.TokenData.Expire,
	}

	return storage
}

// RefreshTokensWithRetry refreshes tokens with a built-in retry mechanism.
// It attempts to refresh the tokens up to a specified maximum number of retries,
// with an exponential backoff strategy to handle transient network errors.
func (o *CodexAuth) RefreshTokensWithRetry(ctx context.Context, refreshToken string, maxRetries int) (*CodexTokenData, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		tokenData, err := o.RefreshTokens(ctx, refreshToken)
		if err == nil {
			return tokenData, nil
		}
		if isNonRetryableRefreshErr(err) {
			log.Warnf("Token refresh attempt %d failed with non-retryable error: %v", attempt+1, err)
			return nil, err
		}

		lastErr = err
		log.Warnf("Token refresh attempt %d failed: %v", attempt+1, err)
	}

	return nil, fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
}

// IsNonRetryableRefreshErr reports whether err describes a refresh-token failure
// that must not be retried — i.e. the credential has been revoked or rejected by
// the OAuth server. Exported so sdk/cliproxy/auth's codex_guard can classify
// refresh probes without duplicating the parsing rules.
func IsNonRetryableRefreshErr(err error) bool {
	return isNonRetryableRefreshErr(err)
}

func isNonRetryableRefreshErr(err error) bool {
	if err == nil {
		return false
	}
	// Prefer the structured OAuth error code when available — it survives wrapping
	// via fmt.Errorf("%w", ...) and is far less fragile than substring matching.
	//
	// Note: invalid_request is intentionally NOT in this list. RFC 6749 §5.2
	// defines invalid_request as a protocol-level error that may signal a
	// transient server-side issue (mis-formed handler, partial outage), not a
	// revoked credential — auto-deleting credentials on invalid_request would
	// risk wiping the auths/ directory during a recoverable upstream blip.
	if code := oauthErrorCode(err); code != "" {
		switch code {
		case "invalid_grant",
			"refresh_token_reused",
			"unauthorized_client",
			"invalid_client":
			return true
		}
		// Fall through to substring fallback rather than returning false: a
		// future OAuth server might wrap a true revocation inside a code we
		// don't yet recognize (e.g. "error":"server_error","error_description":
		// "refresh_token_reused encountered"), and the substring check is
		// our safety net.
	}
	// Fallback for legacy error messages that don't carry a structured code (e.g.
	// raw string-formatted refresh failures from before parseOAuthErrorBody existed),
	// or for unfamiliar OAuth codes that still embed a known revocation phrase.
	raw := strings.ToLower(err.Error())
	return strings.Contains(raw, "refresh_token_reused") ||
		strings.Contains(raw, "invalid_grant")
}

// parseOAuthErrorBody tries to decode a TokenURL error body into an *OAuthError.
// Returns nil when the body is empty, not JSON, or lacks the canonical "error"
// field — letting callers fall back to a generic error message that preserves
// the full status + body in the error string.
func parseOAuthErrorBody(body []byte, statusCode int) *OAuthError {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil
	}
	var oauthErr OAuthError
	if err := json.Unmarshal(body, &oauthErr); err != nil {
		return nil
	}
	if strings.TrimSpace(oauthErr.Code) == "" {
		return nil
	}
	oauthErr.HTTPStatus = statusCode
	// Preserve the raw body for diagnostic logs. Cap at a small ceiling so a
	// pathological upstream cannot inflate per-error memory.
	const maxRawBody = 512
	if len(body) > maxRawBody {
		oauthErr.RawBody = string(body[:maxRawBody]) + "...(truncated)"
	} else {
		oauthErr.RawBody = string(body)
	}
	return &oauthErr
}

// oauthErrorCode returns the OAuth error code of err when err (or any wrapped
// error in its chain) is an *OAuthError. Returns "" otherwise.
func oauthErrorCode(err error) string {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) && oauthErr != nil {
		return strings.TrimSpace(oauthErr.Code)
	}
	return ""
}

// UpdateTokenStorage updates an existing CodexTokenStorage with new token data.
// This is typically called after a successful token refresh to persist the new credentials.
func (o *CodexAuth) UpdateTokenStorage(storage *CodexTokenStorage, tokenData *CodexTokenData) {
	storage.IDToken = tokenData.IDToken
	storage.AccessToken = tokenData.AccessToken
	storage.RefreshToken = tokenData.RefreshToken
	storage.AccountID = tokenData.AccountID
	storage.LastRefresh = time.Now().Format(time.RFC3339)
	storage.Email = tokenData.Email
	storage.Expire = tokenData.Expire
}

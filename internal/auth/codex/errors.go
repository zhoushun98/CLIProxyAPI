package codex

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// OAuthError represents an OAuth-specific error.
type OAuthError struct {
	// Code is the OAuth error code.
	Code string `json:"error"`
	// Description is a human-readable description of the error.
	Description string `json:"error_description,omitempty"`
	// URI is a URI identifying a human-readable web page with information about the error.
	URI string `json:"error_uri,omitempty"`
	// HTTPStatus is the HTTP status code associated with the error. The field is
	// named HTTPStatus (not StatusCode) so the type can also expose a StatusCode()
	// method below — needed by sdk/cliproxy/auth/conductor.go's statusCoder
	// interface for HTTP-aware error classification.
	HTTPStatus int `json:"-"`
	// RawBody preserves the original response body for diagnostic logs, capped to
	// a small size so a misbehaving upstream cannot blow up memory.
	RawBody string `json:"-"`
}

// Error returns a string representation of the OAuth error. The format keeps
// the HTTP status code and either the structured description or a truncated
// raw body so an operator reading LastError.Message can triage non-401
// refresh failures without having to inspect upstream OAuth logs.
func (e *OAuthError) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("OAuth error")
	if e.HTTPStatus > 0 {
		fmt.Fprintf(&b, " (status %d)", e.HTTPStatus)
	}
	if e.Code != "" {
		b.WriteString(": ")
		b.WriteString(e.Code)
	}
	switch {
	case e.Description != "":
		b.WriteString(": ")
		b.WriteString(e.Description)
	case e.RawBody != "":
		b.WriteString(": ")
		b.WriteString(e.RawBody)
	}
	return b.String()
}

// StatusCode satisfies the SDK-side statusCoder interface
// (sdk/cliproxy/auth/conductor.go's statusCodeFromError). Without this method,
// refresh-token failures returning *OAuthError would be classified as
// "unknown status" by the auto-refresh loop, defeating the unauthorized-skip
// logic in hasUnauthorizedAuthFailure.
func (e *OAuthError) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.HTTPStatus
}

// NewOAuthError creates a new OAuth error with the specified code, description, and status code.
func NewOAuthError(code, description string, statusCode int) *OAuthError {
	return &OAuthError{
		Code:        code,
		Description: description,
		HTTPStatus:  statusCode,
	}
}

// AuthenticationError represents authentication-related errors.
type AuthenticationError struct {
	// Type is the type of authentication error.
	Type string `json:"type"`
	// Message is a human-readable message describing the error.
	Message string `json:"message"`
	// Code is the HTTP status code associated with the error.
	Code int `json:"code"`
	// Cause is the underlying error that caused this authentication error.
	Cause error `json:"-"`
}

// Error returns a string representation of the authentication error.
func (e *AuthenticationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Common authentication error types.
var (
	// ErrTokenExpired = &AuthenticationError{
	// 	Type:    "token_expired",
	// 	Message: "Access token has expired",
	// 	Code:    http.StatusUnauthorized,
	// }

	// ErrInvalidState represents an error for invalid OAuth state parameter.
	ErrInvalidState = &AuthenticationError{
		Type:    "invalid_state",
		Message: "OAuth state parameter is invalid",
		Code:    http.StatusBadRequest,
	}

	// ErrCodeExchangeFailed represents an error when exchanging authorization code for tokens fails.
	ErrCodeExchangeFailed = &AuthenticationError{
		Type:    "code_exchange_failed",
		Message: "Failed to exchange authorization code for tokens",
		Code:    http.StatusBadRequest,
	}

	// ErrServerStartFailed represents an error when starting the OAuth callback server fails.
	ErrServerStartFailed = &AuthenticationError{
		Type:    "server_start_failed",
		Message: "Failed to start OAuth callback server",
		Code:    http.StatusInternalServerError,
	}

	// ErrPortInUse represents an error when the OAuth callback port is already in use.
	ErrPortInUse = &AuthenticationError{
		Type:    "port_in_use",
		Message: "OAuth callback port is already in use",
		Code:    13, // Special exit code for port-in-use
	}

	// ErrCallbackTimeout represents an error when waiting for OAuth callback times out.
	ErrCallbackTimeout = &AuthenticationError{
		Type:    "callback_timeout",
		Message: "Timeout waiting for OAuth callback",
		Code:    http.StatusRequestTimeout,
	}

	// ErrBrowserOpenFailed represents an error when opening the browser for authentication fails.
	ErrBrowserOpenFailed = &AuthenticationError{
		Type:    "browser_open_failed",
		Message: "Failed to open browser for authentication",
		Code:    http.StatusInternalServerError,
	}
)

// NewAuthenticationError creates a new authentication error with a cause based on a base error.
func NewAuthenticationError(baseErr *AuthenticationError, cause error) *AuthenticationError {
	return &AuthenticationError{
		Type:    baseErr.Type,
		Message: baseErr.Message,
		Code:    baseErr.Code,
		Cause:   cause,
	}
}

// IsAuthenticationError checks if an error is an authentication error.
func IsAuthenticationError(err error) bool {
	var authenticationError *AuthenticationError
	ok := errors.As(err, &authenticationError)
	return ok
}

// IsOAuthError checks if an error is an OAuth error.
func IsOAuthError(err error) bool {
	var oAuthError *OAuthError
	ok := errors.As(err, &oAuthError)
	return ok
}

// GetUserFriendlyMessage returns a user-friendly error message based on the error type.
func GetUserFriendlyMessage(err error) string {
	switch {
	case IsAuthenticationError(err):
		var authErr *AuthenticationError
		errors.As(err, &authErr)
		switch authErr.Type {
		case "token_expired":
			return "Your authentication has expired. Please log in again."
		case "token_invalid":
			return "Your authentication is invalid. Please log in again."
		case "authentication_required":
			return "Please log in to continue."
		case "port_in_use":
			return "The required port is already in use. Please close any applications using port 3000 and try again."
		case "callback_timeout":
			return "Authentication timed out. Please try again."
		case "browser_open_failed":
			return "Could not open your browser automatically. Please copy and paste the URL manually."
		default:
			return "Authentication failed. Please try again."
		}
	case IsOAuthError(err):
		var oauthErr *OAuthError
		errors.As(err, &oauthErr)
		switch oauthErr.Code {
		case "access_denied":
			return "Authentication was cancelled or denied."
		case "invalid_request":
			return "Invalid authentication request. Please try again."
		case "server_error":
			return "Authentication server error. Please try again later."
		default:
			return fmt.Sprintf("Authentication failed: %s", oauthErr.Description)
		}
	default:
		return "An unexpected error occurred. Please try again."
	}
}

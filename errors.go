package meshguard

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure modes.
var (
	// ErrAuthentication indicates an invalid or expired token (HTTP 401).
	ErrAuthentication = errors.New("meshguard: invalid or expired token")

	// ErrPolicyDenied indicates an action was denied by policy (HTTP 403).
	ErrPolicyDenied = errors.New("meshguard: action denied by policy")

	// ErrRateLimit indicates the rate limit has been exceeded (HTTP 429).
	ErrRateLimit = errors.New("meshguard: rate limit exceeded")
)

// PolicyDeniedError provides detailed information about a policy denial.
// It wraps ErrPolicyDenied, so errors.Is(err, ErrPolicyDenied) returns true.
type PolicyDeniedError struct {
	// Action is the action that was denied.
	Action string

	// Policy is the policy that denied the action.
	Policy string

	// Rule is the specific rule that matched.
	Rule string

	// Reason is a human-readable explanation for the denial.
	Reason string

	// Decision contains the full policy decision, if available.
	Decision *PolicyDecision
}

// Error returns a human-readable description of the denial.
func (e *PolicyDeniedError) Error() string {
	msg := fmt.Sprintf("action %q denied", e.Action)
	if e.Policy != "" {
		msg += fmt.Sprintf(" by policy %q", e.Policy)
	}
	if e.Rule != "" {
		msg += fmt.Sprintf(" (rule: %s)", e.Rule)
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// Unwrap returns ErrPolicyDenied so callers can use errors.Is.
func (e *PolicyDeniedError) Unwrap() error {
	return ErrPolicyDenied
}

// APIError represents an unexpected HTTP error from the gateway.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int

	// Body is the raw response body.
	Body string
}

// Error returns a description of the API error.
func (e *APIError) Error() string {
	return fmt.Sprintf("meshguard: request failed: %d %s", e.StatusCode, e.Body)
}

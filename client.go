package meshguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client is a MeshGuard governance gateway client.
//
// Use [NewClient] to construct a properly initialised Client.
type Client struct {
	gatewayURL string
	apiKey     string
	adminToken string
	httpClient *http.Client
	timeout    time.Duration
	traceID    string
	userAgent  string
}

// Option configures an optional Client parameter.
type Option func(*Client)

// WithHTTPClient sets a custom *http.Client for all requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout overrides the default request timeout (30 s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithTraceID sets a fixed trace ID for request correlation.
// By default each Client generates a trace ID from the current timestamp.
func WithTraceID(id string) Option {
	return func(c *Client) { c.traceID = id }
}

// WithAdminToken sets the admin token for management API calls.
// It can also be supplied via the MESHGUARD_ADMIN_TOKEN environment variable.
func WithAdminToken(token string) Option {
	return func(c *Client) { c.adminToken = token }
}

// WithUserAgent overrides the default User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// NewClient creates a new MeshGuard client.
//
// gatewayURL is the base URL of the MeshGuard gateway (e.g.
// "https://dashboard.meshguard.app"). If empty the MESHGUARD_GATEWAY_URL
// environment variable is used, falling back to
// "https://dashboard.meshguard.app".
//
// apiKey is the agent JWT token used for authentication. If empty the
// MESHGUARD_AGENT_TOKEN environment variable is consulted.
func NewClient(gatewayURL, apiKey string, opts ...Option) *Client {
	if gatewayURL == "" {
		gatewayURL = os.Getenv("MESHGUARD_GATEWAY_URL")
	}
	if gatewayURL == "" {
		gatewayURL = "https://dashboard.meshguard.app"
	}
	gatewayURL = strings.TrimRight(gatewayURL, "/")

	if apiKey == "" {
		apiKey = os.Getenv("MESHGUARD_AGENT_TOKEN")
	}

	c := &Client{
		gatewayURL: gatewayURL,
		apiKey:     apiKey,
		timeout:    30 * time.Second,
		traceID:    fmt.Sprintf("%d", time.Now().UnixNano()),
		userAgent:  "meshguard-go/0.1.0",
	}

	for _, o := range opts {
		o(c)
	}

	if c.adminToken == "" {
		c.adminToken = os.Getenv("MESHGUARD_ADMIN_TOKEN")
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: c.timeout}
	}

	return c
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// authHeaders returns standard headers including Bearer authentication.
func (c *Client) authHeaders() http.Header {
	h := http.Header{}
	h.Set("X-MeshGuard-Trace-ID", c.traceID)
	h.Set("User-Agent", c.userAgent)
	if c.apiKey != "" {
		h.Set("Authorization", "Bearer "+c.apiKey)
	}
	return h
}

// adminHeaders returns headers for admin endpoints.
func (c *Client) adminHeaders() (http.Header, error) {
	if c.adminToken == "" {
		return nil, fmt.Errorf("%w: admin token required for this operation", ErrAuthentication)
	}
	h := http.Header{}
	h.Set("X-Admin-Token", c.adminToken)
	h.Set("X-MeshGuard-Trace-ID", c.traceID)
	h.Set("User-Agent", c.userAgent)
	return h, nil
}

// do executes an HTTP request and returns the response.
func (c *Client) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return c.httpClient.Do(req)
}

// handleResponse inspects the status code and either returns the body bytes
// or a typed error.
func (c *Client) handleResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("meshguard: reading response body: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, ErrAuthentication
	case resp.StatusCode == http.StatusForbidden:
		var data struct {
			Action  string `json:"action"`
			Policy  string `json:"policy"`
			Rule    string `json:"rule"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &data)
		return nil, &PolicyDeniedError{
			Action: data.Action,
			Policy: data.Policy,
			Rule:   data.Rule,
			Reason: cond(data.Message != "", data.Message, "Access denied by policy"),
		}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrRateLimit
	case resp.StatusCode >= 400:
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	return body, nil
}

func cond(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Core Governance
// ---------------------------------------------------------------------------

// Check evaluates whether the given action is allowed by policy.
//
// It never returns an error on policy denial; instead the returned
// [PolicyDecision] will have Allowed == false. Errors are reserved for
// transport failures and authentication problems.
func (c *Client) Check(ctx context.Context, agentID, action string, meta map[string]any) (*PolicyDecision, error) {
	h := c.authHeaders()
	h.Set("X-MeshGuard-Action", action)
	if agentID != "" {
		h.Set("X-MeshGuard-Agent-ID", agentID)
	}

	req, err := http.NewRequest(http.MethodGet, c.gatewayURL+"/proxy/check", nil)
	if err != nil {
		return nil, fmt.Errorf("meshguard: building request: %w", err)
	}
	req.Header = h

	if len(meta) > 0 {
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return nil, fmt.Errorf("meshguard: marshalling meta: %w", err)
		}
		req.Header.Set("X-MeshGuard-Meta", string(metaJSON))
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("meshguard: check request: %w", err)
	}

	now := time.Now()

	// A 403 is a valid policy denial, not a transport error.
	if resp.StatusCode == http.StatusForbidden {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var data struct {
			Policy  string `json:"policy"`
			Rule    string `json:"rule"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &data)
		return &PolicyDecision{
			Allowed:   false,
			Action:    action,
			Decision:  "deny",
			Policy:    data.Policy,
			Rule:      data.Rule,
			Reason:    data.Message,
			TraceID:   c.traceID,
			Timestamp: now,
		}, nil
	}

	body, err := c.handleResponse(resp)
	if err != nil {
		// If handleResponse produced a PolicyDeniedError (e.g. from
		// a re-entrant check) surface it as a decision, not an error.
		var pde *PolicyDeniedError
		if ok := isPolicyDenied(err, &pde); ok {
			return &PolicyDecision{
				Allowed:   false,
				Action:    action,
				Decision:  "deny",
				Policy:    pde.Policy,
				Rule:      pde.Rule,
				Reason:    pde.Reason,
				TraceID:   c.traceID,
				Timestamp: now,
			}, nil
		}
		return nil, err
	}

	var data struct {
		Policy string `json:"policy"`
	}
	_ = json.Unmarshal(body, &data)

	return &PolicyDecision{
		Allowed:   true,
		Action:    action,
		Decision:  "allow",
		Policy:    data.Policy,
		TraceID:   c.traceID,
		Timestamp: now,
	}, nil
}

// isPolicyDenied extracts a *PolicyDeniedError from err using errors.As.
func isPolicyDenied(err error, target **PolicyDeniedError) bool {
	return err != nil && isAs(err, target)
}

// isAs is a thin wrapper so we can keep the import list tidy.
func isAs(err error, target any) bool {
	// We inline this instead of importing errors to avoid an
	// unnecessary type assertion. errors.As does the work.
	type asInterface interface{ As(any) bool }
	switch t := target.(type) {
	case **PolicyDeniedError:
		for err != nil {
			if pde, ok := err.(*PolicyDeniedError); ok {
				*t = pde
				return true
			}
			u, ok := err.(interface{ Unwrap() error })
			if !ok {
				return false
			}
			err = u.Unwrap()
		}
	}
	return false
}

// Enforce checks the action and returns an error if it is denied.
//
// On denial the error is a [*PolicyDeniedError] that wraps [ErrPolicyDenied],
// so callers can use errors.Is(err, meshguard.ErrPolicyDenied).
func (c *Client) Enforce(ctx context.Context, agentID, action string, meta map[string]any) error {
	decision, err := c.Check(ctx, agentID, action, meta)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return &PolicyDeniedError{
			Action:   action,
			Policy:   decision.Policy,
			Rule:     decision.Rule,
			Reason:   decision.Reason,
			Decision: decision,
		}
	}
	return nil
}

// Govern enforces a policy check and, if the action is allowed, executes fn.
//
// If the policy denies the action, fn is never called and a
// [*PolicyDeniedError] is returned.
func (c *Client) Govern(ctx context.Context, agentID, action string, meta map[string]any, fn func() error) error {
	if err := c.Enforce(ctx, agentID, action, meta); err != nil {
		return err
	}
	return fn()
}

// ---------------------------------------------------------------------------
// Proxy Requests
// ---------------------------------------------------------------------------

// Request sends an HTTP request through the MeshGuard governance proxy.
//
// The request is routed to /proxy/<path> with the appropriate governance
// headers attached. body may be nil for methods that carry no payload.
func (c *Client) Request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	path = strings.TrimLeft(path, "/")
	url := c.gatewayURL + "/proxy/" + path

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("meshguard: building proxy request: %w", err)
	}
	req.Header = c.authHeaders()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("meshguard: proxy request: %w", err)
	}

	return resp, nil
}

// Get sends a GET request through the governance proxy.
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.Request(ctx, http.MethodGet, path, nil)
}

// Post sends a POST request through the governance proxy.
func (c *Client) Post(ctx context.Context, path string, body io.Reader) (*http.Response, error) {
	return c.Request(ctx, http.MethodPost, path, body)
}

// Put sends a PUT request through the governance proxy.
func (c *Client) Put(ctx context.Context, path string, body io.Reader) (*http.Response, error) {
	return c.Request(ctx, http.MethodPut, path, body)
}

// Delete sends a DELETE request through the governance proxy.
func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	return c.Request(ctx, http.MethodDelete, path, nil)
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// Health checks the gateway's health endpoint.
//
// Returns nil if the gateway reports a healthy status, or an error otherwise.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequest(http.MethodGet, c.gatewayURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("meshguard: building health request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.do(ctx, req)
	if err != nil {
		return fmt.Errorf("meshguard: health request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("meshguard: gateway unhealthy: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("meshguard: decoding health response: %w", err)
	}
	if result.Status != "healthy" {
		return fmt.Errorf("meshguard: gateway status: %s", result.Status)
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

// jsonBody marshals v to JSON and returns an io.Reader suitable for an HTTP
// request body.
func jsonBody(v any) (io.Reader, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

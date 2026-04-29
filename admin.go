package meshguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// ---------------------------------------------------------------------------
// Admin Operations
//
// All methods in this file require an admin token, configured either through
// [WithAdminToken] or the MESHGUARD_ADMIN_TOKEN environment variable.
// ---------------------------------------------------------------------------

// ListAgents returns all agents registered in the gateway.
func (c *Client) ListAgents(ctx context.Context) ([]Agent, error) {
	h, err := c.adminHeaders()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, c.gatewayURL+"/admin/agents", nil)
	if err != nil {
		return nil, fmt.Errorf("meshguard: building list agents request: %w", err)
	}
	req.Header = h

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("meshguard: list agents request: %w", err)
	}

	body, err := c.handleResponse(resp)
	if err != nil {
		return nil, err
	}

	var result struct {
		Agents []Agent `json:"agents"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("meshguard: decoding agents response: %w", err)
	}
	return result.Agents, nil
}

// CreateAgent registers a new agent with the gateway.
func (c *Client) CreateAgent(ctx context.Context, r CreateAgentRequest) (*Agent, error) {
	h, err := c.adminHeaders()
	if err != nil {
		return nil, err
	}

	if r.TrustTier == "" {
		r.TrustTier = "verified"
	}

	body, err := jsonBody(r)
	if err != nil {
		return nil, fmt.Errorf("meshguard: marshalling create agent request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.gatewayURL+"/admin/agents", body)
	if err != nil {
		return nil, fmt.Errorf("meshguard: building create agent request: %w", err)
	}
	req.Header = h
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("meshguard: create agent request: %w", err)
	}

	respBody, err := c.handleResponse(resp)
	if err != nil {
		return nil, err
	}

	var agent Agent
	if err := json.Unmarshal(respBody, &agent); err != nil {
		return nil, fmt.Errorf("meshguard: decoding create agent response: %w", err)
	}
	return &agent, nil
}

// RevokeAgent deletes an agent by ID.
func (c *Client) RevokeAgent(ctx context.Context, agentID string) error {
	h, err := c.adminHeaders()
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, c.gatewayURL+"/admin/agents/"+agentID, nil)
	if err != nil {
		return fmt.Errorf("meshguard: building revoke agent request: %w", err)
	}
	req.Header = h

	resp, err := c.do(ctx, req)
	if err != nil {
		return fmt.Errorf("meshguard: revoke agent request: %w", err)
	}

	_, err = c.handleResponse(resp)
	return err
}

// ListPolicies returns all policies defined in the gateway.
func (c *Client) ListPolicies(ctx context.Context) ([]Policy, error) {
	h, err := c.adminHeaders()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, c.gatewayURL+"/admin/policies", nil)
	if err != nil {
		return nil, fmt.Errorf("meshguard: building list policies request: %w", err)
	}
	req.Header = h

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("meshguard: list policies request: %w", err)
	}

	body, err := c.handleResponse(resp)
	if err != nil {
		return nil, err
	}

	var result struct {
		Policies []Policy `json:"policies"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("meshguard: decoding policies response: %w", err)
	}
	return result.Policies, nil
}

// AuditLog retrieves audit log entries from the gateway.
//
// Pass a zero-value [AuditQueryOptions] for defaults (limit 50, no filters).
func (c *Client) AuditLog(ctx context.Context, opts AuditQueryOptions) ([]AuditEntry, error) {
	h, err := c.adminHeaders()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodGet, c.gatewayURL+"/admin/audit", nil)
	if err != nil {
		return nil, fmt.Errorf("meshguard: building audit log request: %w", err)
	}
	req.Header = h

	q := req.URL.Query()
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	q.Set("limit", strconv.Itoa(limit))
	if opts.Decision != "" {
		q.Set("decision", opts.Decision)
	}
	if opts.AgentID != "" {
		q.Set("agentId", opts.AgentID)
	}
	if opts.Action != "" {
		q.Set("action", opts.Action)
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("meshguard: audit log request: %w", err)
	}

	body, err := c.handleResponse(resp)
	if err != nil {
		return nil, err
	}

	var result struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("meshguard: decoding audit log response: %w", err)
	}
	return result.Entries, nil
}

package meshguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestServer returns an httptest.Server that responds based on the
// X-MeshGuard-Action header:
//
//	"allow:*"  -> 200 with {"policy":"test-policy"}
//	"deny:*"   -> 403 with denial details
//	"auth:*"   -> 401
//	"rate:*"   -> 429
//	anything else -> 200 with empty body
func newTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-MeshGuard-Action")

		// Health endpoint
		if r.URL.Path == "/health" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
			return
		}

		// Admin endpoints
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			handleAdmin(w, r)
			return
		}

		switch {
		case strings.HasPrefix(action, "allow:"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"policy": "test-policy"})

		case strings.HasPrefix(action, "deny:"):
			w.WriteHeader(http.StatusForbidden)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"action":  action,
				"policy":  "security-policy",
				"rule":    "block-external",
				"message": "external access not permitted",
			})

		case strings.HasPrefix(action, "auth:"):
			w.WriteHeader(http.StatusUnauthorized)

		case strings.HasPrefix(action, "rate:"):
			w.WriteHeader(http.StatusTooManyRequests)

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Admin-Token") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.URL.Path == "/admin/agents" && r.Method == http.MethodGet:
		json.NewEncoder(w).Encode(map[string]any{
			"agents": []map[string]any{
				{
					"id":        "agent-1",
					"name":      "test-agent",
					"trustTier": "verified",
					"tags":      []string{"prod"},
				},
			},
		})

	case r.URL.Path == "/admin/agents" && r.Method == http.MethodPost:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]any{
			"id":        "agent-new",
			"name":      body["name"],
			"trustTier": body["trustTier"],
			"tags":      body["tags"],
		})

	case strings.HasPrefix(r.URL.Path, "/admin/agents/") && r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})

	case r.URL.Path == "/admin/policies":
		json.NewEncoder(w).Encode(map[string]any{
			"policies": []map[string]any{
				{"id": "pol-1", "name": "default-policy"},
			},
		})

	case r.URL.Path == "/admin/audit":
		json.NewEncoder(w).Encode(map[string]any{
			"entries": []map[string]any{
				{
					"id":        "entry-1",
					"timestamp": "2025-01-15T10:30:00Z",
					"action":    "read:contacts",
					"decision":  "allow",
					"agentId":   "agent-1",
				},
			},
		})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestClient(serverURL string) *Client {
	return NewClient(serverURL, "test-token",
		WithAdminToken("test-admin-token"),
		WithTraceID("test-trace-id"),
	)
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

func TestCheck(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	tests := []struct {
		name       string
		action     string
		wantAllow  bool
		wantPolicy string
		wantErr    bool
	}{
		{
			name:       "allowed action",
			action:     "allow:read-contacts",
			wantAllow:  true,
			wantPolicy: "test-policy",
		},
		{
			name:       "denied action",
			action:     "deny:write-admin",
			wantAllow:  false,
			wantPolicy: "security-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := client.Check(ctx, "", tt.action, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if decision.Allowed != tt.wantAllow {
				t.Errorf("Allowed = %v, want %v", decision.Allowed, tt.wantAllow)
			}
			if decision.Policy != tt.wantPolicy {
				t.Errorf("Policy = %q, want %q", decision.Policy, tt.wantPolicy)
			}
			if decision.TraceID != "test-trace-id" {
				t.Errorf("TraceID = %q, want %q", decision.TraceID, "test-trace-id")
			}
		})
	}
}

func TestCheck_AuthError(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	_, err := client.Check(ctx, "", "auth:something", nil)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

func TestCheck_RateLimit(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	_, err := client.Check(ctx, "", "rate:something", nil)
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("expected ErrRateLimit, got %v", err)
	}
}

func TestCheck_WithMeta(t *testing.T) {
	var receivedMeta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMeta = r.Header.Get("X-MeshGuard-Meta")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"policy": "ok"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	ctx := context.Background()

	meta := map[string]any{"ip": "10.0.0.1", "count": 42}
	_, err := client.Check(ctx, "agent-1", "allow:read", meta)
	if err != nil {
		t.Fatal(err)
	}
	if receivedMeta == "" {
		t.Fatal("expected meta header to be set")
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(receivedMeta), &decoded); err != nil {
		t.Fatalf("invalid meta JSON: %v", err)
	}
	if decoded["ip"] != "10.0.0.1" {
		t.Errorf("meta[ip] = %v, want 10.0.0.1", decoded["ip"])
	}
}

// ---------------------------------------------------------------------------
// Enforce
// ---------------------------------------------------------------------------

func TestEnforce(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	tests := []struct {
		name    string
		action  string
		wantErr bool
		isDeny  bool
	}{
		{
			name:   "allowed",
			action: "allow:read",
		},
		{
			name:    "denied",
			action:  "deny:write",
			wantErr: true,
			isDeny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.Enforce(ctx, "", tt.action, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Enforce() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.isDeny {
				if !errors.Is(err, ErrPolicyDenied) {
					t.Errorf("expected ErrPolicyDenied, got %v", err)
				}
				var pde *PolicyDeniedError
				if !errors.As(err, &pde) {
					t.Fatal("expected *PolicyDeniedError")
				}
				if pde.Policy != "security-policy" {
					t.Errorf("Policy = %q, want %q", pde.Policy, "security-policy")
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Govern
// ---------------------------------------------------------------------------

func TestGovern(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	t.Run("allowed runs function", func(t *testing.T) {
		ran := false
		err := client.Govern(ctx, "", "allow:exec", nil, func() error {
			ran = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !ran {
			t.Error("function was not executed")
		}
	})

	t.Run("denied skips function", func(t *testing.T) {
		ran := false
		err := client.Govern(ctx, "", "deny:exec", nil, func() error {
			ran = true
			return nil
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if ran {
			t.Error("function should not have been executed")
		}
		if !errors.Is(err, ErrPolicyDenied) {
			t.Errorf("expected ErrPolicyDenied, got %v", err)
		}
	})

	t.Run("propagates function error", func(t *testing.T) {
		fnErr := errors.New("boom")
		err := client.Govern(ctx, "", "allow:exec", nil, func() error {
			return fnErr
		})
		if !errors.Is(err, fnErr) {
			t.Errorf("expected function error, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Proxy Methods
// ---------------------------------------------------------------------------

func TestProxyMethods(t *testing.T) {
	var (
		receivedMethod string
		receivedPath   string
		receivedBody   string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			receivedBody = string(b)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	ctx := context.Background()

	t.Run("Get", func(t *testing.T) {
		resp, err := client.Get(ctx, "/users")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if receivedMethod != "GET" {
			t.Errorf("method = %q, want GET", receivedMethod)
		}
		if receivedPath != "/proxy/users" {
			t.Errorf("path = %q, want /proxy/users", receivedPath)
		}
	})

	t.Run("Post", func(t *testing.T) {
		body := strings.NewReader(`{"name":"test"}`)
		resp, err := client.Post(ctx, "/users", body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if receivedMethod != "POST" {
			t.Errorf("method = %q, want POST", receivedMethod)
		}
		if receivedBody != `{"name":"test"}` {
			t.Errorf("body = %q, want %q", receivedBody, `{"name":"test"}`)
		}
	})

	t.Run("Put", func(t *testing.T) {
		body := strings.NewReader(`{"name":"updated"}`)
		resp, err := client.Put(ctx, "/users/1", body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if receivedMethod != "PUT" {
			t.Errorf("method = %q, want PUT", receivedMethod)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		resp, err := client.Delete(ctx, "/users/1")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if receivedMethod != "DELETE" {
			t.Errorf("method = %q, want DELETE", receivedMethod)
		}
	})
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	if err := client.Health(ctx); err != nil {
		t.Fatalf("Health() = %v, want nil", err)
	}
}

func TestHealth_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	if err := client.Health(ctx); err == nil {
		t.Fatal("expected error for unhealthy gateway")
	}
}

// ---------------------------------------------------------------------------
// Admin Operations
// ---------------------------------------------------------------------------

func TestListAgents(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	agents, err := client.ListAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("len(agents) = %d, want 1", len(agents))
	}
	if agents[0].ID != "agent-1" {
		t.Errorf("ID = %q, want %q", agents[0].ID, "agent-1")
	}
	if agents[0].Name != "test-agent" {
		t.Errorf("Name = %q, want %q", agents[0].Name, "test-agent")
	}
	if agents[0].TrustTier != "verified" {
		t.Errorf("TrustTier = %q, want %q", agents[0].TrustTier, "verified")
	}
}

func TestCreateAgent(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	agent, err := client.CreateAgent(ctx, CreateAgentRequest{
		Name:      "new-agent",
		TrustTier: "untrusted",
		Tags:      []string{"dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID != "agent-new" {
		t.Errorf("ID = %q, want %q", agent.ID, "agent-new")
	}
	if agent.Name != "new-agent" {
		t.Errorf("Name = %q, want %q", agent.Name, "new-agent")
	}
}

func TestRevokeAgent(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	if err := client.RevokeAgent(ctx, "agent-1"); err != nil {
		t.Fatal(err)
	}
}

func TestListPolicies(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	policies, err := client.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("len(policies) = %d, want 1", len(policies))
	}
	if policies[0].Name != "default-policy" {
		t.Errorf("Name = %q, want %q", policies[0].Name, "default-policy")
	}
}

func TestAuditLog(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := newTestClient(srv.URL)
	ctx := context.Background()

	entries, err := client.AuditLog(ctx, AuditQueryOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].Action != "read:contacts" {
		t.Errorf("Action = %q, want %q", entries[0].Action, "read:contacts")
	}
}

func TestAdmin_RequiresToken(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()
	client := NewClient(srv.URL, "test-token", WithTraceID("test"))
	ctx := context.Background()

	_, err := client.ListAgents(ctx)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

func TestNewClient_Defaults(t *testing.T) {
	c := NewClient("", "")
	if c.gatewayURL != "https://dashboard.meshguard.app" {
		t.Errorf("gatewayURL = %q", c.gatewayURL)
	}
	if c.timeout != 30*1e9 {
		t.Errorf("timeout = %v", c.timeout)
	}
}

func TestNewClient_TrailingSlash(t *testing.T) {
	c := NewClient("https://example.com///", "key")
	if c.gatewayURL != "https://example.com" {
		t.Errorf("gatewayURL = %q", c.gatewayURL)
	}
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

func TestPolicyDeniedError_ErrorString(t *testing.T) {
	err := &PolicyDeniedError{
		Action: "write:admin",
		Policy: "security-policy",
		Rule:   "no-admin-writes",
		Reason: "admin writes are disabled",
	}

	msg := err.Error()
	if !strings.Contains(msg, "write:admin") {
		t.Errorf("missing action in error: %s", msg)
	}
	if !strings.Contains(msg, "security-policy") {
		t.Errorf("missing policy in error: %s", msg)
	}
	if !strings.Contains(msg, "no-admin-writes") {
		t.Errorf("missing rule in error: %s", msg)
	}
	if !strings.Contains(msg, "admin writes are disabled") {
		t.Errorf("missing reason in error: %s", msg)
	}
}

func TestPolicyDeniedError_Unwrap(t *testing.T) {
	err := &PolicyDeniedError{Action: "test"}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Error("PolicyDeniedError should unwrap to ErrPolicyDenied")
	}
}

func TestAPIError_ErrorString(t *testing.T) {
	err := &APIError{StatusCode: 500, Body: "internal error"}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("missing status code: %s", err.Error())
	}
}

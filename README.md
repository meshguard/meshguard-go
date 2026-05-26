# meshguard-go

> **Ecosystem expansion:** this SDK remains a first-class MeshGuard path for Go agents and services. AGT-compatible policy and MeshGuard's AGT adapters add another path for teams that choose Microsoft Agent Governance Toolkit; they complement this SDK and the rest of the MeshGuard ecosystem.

Go SDK for the [MeshGuard](https://meshguard.app) governance gateway.

## Installation

```bash
go get github.com/meshguard/meshguard-go
```

Requires **Go 1.21+**. No external dependencies — only the standard library.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    meshguard "github.com/meshguard/meshguard-go"
)

func main() {
    client := meshguard.NewClient(
        "https://dashboard.meshguard.app",
        "your-agent-token",
    )

    ctx := context.Background()

    // Check if an action is allowed (never errors on deny)
    decision, err := client.Check(ctx, "agent-1", "read:contacts", nil)
    if err != nil {
        log.Fatal(err)
    }
    if decision.Allowed {
        fmt.Println("Access granted")
    } else {
        fmt.Printf("Denied: %s\n", decision.Reason)
    }
}
```

## Usage

### Check — Non-Throwing Policy Evaluation

`Check` returns a `*PolicyDecision` without returning an error on denial. Use this when you want to inspect the decision yourself.

```go
decision, err := client.Check(ctx, agentID, "write:email", map[string]any{
    "recipient": "user@example.com",
})
if err != nil {
    // Transport or auth error
    log.Fatal(err)
}
if !decision.Allowed {
    fmt.Printf("Blocked by policy %q: %s\n", decision.Policy, decision.Reason)
    return
}
```

### Enforce — Error on Deny

`Enforce` returns an error if the action is denied. The error is a `*PolicyDeniedError` that wraps `ErrPolicyDenied`.

```go
err := client.Enforce(ctx, agentID, "delete:records", nil)
if errors.Is(err, meshguard.ErrPolicyDenied) {
    var pde *meshguard.PolicyDeniedError
    errors.As(err, &pde)
    fmt.Printf("Denied by %s: %s\n", pde.Policy, pde.Reason)
    return
}
if err != nil {
    log.Fatal(err)
}
```

### Govern — Wrap a Function

`Govern` checks the policy and only calls your function if the action is allowed.

```go
err := client.Govern(ctx, agentID, "read:contacts", nil, func() error {
    contacts, err := db.FetchContacts()
    if err != nil {
        return err
    }
    fmt.Printf("Found %d contacts\n", len(contacts))
    return nil
})
if err != nil {
    log.Fatal(err)
}
```

### Proxy Requests

Route HTTP requests through the MeshGuard governance proxy.

```go
resp, err := client.Get(ctx, "/api/users")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

resp, err = client.Post(ctx, "/api/users", strings.NewReader(`{"name":"Alice"}`))
```

### Health Check

```go
if err := client.Health(ctx); err != nil {
    log.Printf("Gateway unhealthy: %v", err)
}
```

### Admin Operations

Admin methods require an admin token, set via `WithAdminToken` or the `MESHGUARD_ADMIN_TOKEN` environment variable.

```go
client := meshguard.NewClient(
    "https://dashboard.meshguard.app",
    "agent-token",
    meshguard.WithAdminToken("admin-token"),
)

// List agents
agents, _ := client.ListAgents(ctx)

// Create agent
agent, _ := client.CreateAgent(ctx, meshguard.CreateAgentRequest{
    Name:      "new-agent",
    TrustTier: "verified",
    Tags:      []string{"production"},
})

// Revoke agent
_ = client.RevokeAgent(ctx, "agent-id")

// List policies
policies, _ := client.ListPolicies(ctx)

// Query audit log
entries, _ := client.AuditLog(ctx, meshguard.AuditQueryOptions{
    Limit:    100,
    Decision: "deny",
})
```

## Configuration

### Functional Options

```go
client := meshguard.NewClient(gatewayURL, apiKey,
    meshguard.WithTimeout(10 * time.Second),
    meshguard.WithAdminToken("admin-token"),
    meshguard.WithTraceID("custom-trace-id"),
    meshguard.WithHTTPClient(customHTTPClient),
    meshguard.WithUserAgent("my-app/1.0"),
)
```

### Environment Variables

| Variable | Description |
|---|---|
| `MESHGUARD_GATEWAY_URL` | Gateway URL (fallback if not passed to constructor) |
| `MESHGUARD_AGENT_TOKEN` | Agent JWT token (fallback if not passed to constructor) |
| `MESHGUARD_ADMIN_TOKEN` | Admin token for management APIs |

## Error Handling

Sentinel errors for use with `errors.Is`:

| Error | Meaning |
|---|---|
| `ErrAuthentication` | Invalid or expired token (401) |
| `ErrPolicyDenied` | Action denied by policy (403) |
| `ErrRateLimit` | Rate limit exceeded (429) |

`*PolicyDeniedError` provides structured denial details (`Action`, `Policy`, `Rule`, `Reason`) and unwraps to `ErrPolicyDenied`.

`*APIError` captures unexpected HTTP errors with `StatusCode` and `Body`.

## License

See [LICENSE](LICENSE) for details.

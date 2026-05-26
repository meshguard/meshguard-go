# Using AGT With meshguard-go

MeshGuard supports direct Go SDK governance and AGT-native governance in the same control plane. AGT is an additional policy enforcement path for teams that use Microsoft Agent Governance Toolkit in part of their fleet.

## Direct Go SDK Pattern

```go
decision, err := client.Check(ctx, agentID, "read:contacts", nil)
```

## AGT-Compatible Path

1. Keep `meshguard-go` in production for Go agents and services.
2. Use AGT-compatible policy YAML when you want policies shared across Go SDK, AGT, sidecar, and egress paths.
3. Point AGT-instrumented agents at the same MeshGuard PDP and audit plane.
4. Compare decisions in MeshGuard audit history when running paths side by side.
5. Choose the enforcement path per agent, framework, and deployment architecture.

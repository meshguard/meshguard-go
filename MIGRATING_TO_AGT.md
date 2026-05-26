# Migrating From meshguard-go To AGT + MeshGuard

The Go SDK remains supported for existing integrations. It is not the primary surface for new agent-governance features.

## Recommended Path

1. Keep `meshguard-go` in production for current Go agents.
2. Move policies to AGT-compatible YAML so they can be shared with the MeshGuard PDP.
3. Use MeshGuard audit export to compare SDK decisions and AGT adapter decisions.
4. For new mixed-language fleets, standardize on AGT-compatible PEPs and MeshGuard as the PDP.


// Package meshguard provides a Go client for the MeshGuard governance gateway.
//
// MeshGuard enables policy-based governance for AI agents and automated
// workflows. This SDK provides methods for checking, enforcing, and wrapping
// actions with policy evaluation, as well as admin operations for managing
// agents, policies, and audit logs.
package meshguard

import "time"

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
	// Allowed indicates whether the action is permitted.
	Allowed bool `json:"allowed"`

	// Action is the action that was checked.
	Action string `json:"action"`

	// Decision is the evaluation result: "allow" or "deny".
	Decision string `json:"decision"`

	// Policy is the name of the policy that produced this decision.
	Policy string `json:"policy,omitempty"`

	// Rule is the specific rule within the policy that matched.
	Rule string `json:"rule,omitempty"`

	// Reason is a human-readable explanation for the decision.
	Reason string `json:"reason,omitempty"`

	// TraceID is the correlation identifier for this request.
	TraceID string `json:"traceId,omitempty"`

	// Timestamp records when the decision was made.
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// Agent represents a MeshGuard agent identity.
type Agent struct {
	// ID is the unique agent identifier.
	ID string `json:"id"`

	// Name is the agent display name.
	Name string `json:"name"`

	// TrustTier indicates the agent's trust level (e.g., "verified", "untrusted").
	TrustTier string `json:"trustTier"`

	// Capabilities lists the actions this agent is authorized to perform.
	Capabilities []string `json:"capabilities,omitempty"`

	// Tags are labels associated with the agent.
	Tags []string `json:"tags,omitempty"`

	// OrgID is the organization this agent belongs to.
	OrgID string `json:"orgId,omitempty"`

	// CreatedAt is when the agent was created.
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

// Policy represents a governance policy definition.
type Policy struct {
	// ID is the unique policy identifier.
	ID string `json:"id"`

	// Name is the human-readable policy name.
	Name string `json:"name"`

	// Description provides details about what the policy governs.
	Description string `json:"description,omitempty"`

	// Rules contains the rules that make up this policy.
	Rules []Rule `json:"rules,omitempty"`

	// CreatedAt is when the policy was created.
	CreatedAt time.Time `json:"createdAt,omitempty"`

	// UpdatedAt is when the policy was last modified.
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// Rule represents a single rule within a policy.
type Rule struct {
	// ID is the unique rule identifier.
	ID string `json:"id"`

	// Name is the human-readable rule name.
	Name string `json:"name,omitempty"`

	// Action is the action pattern this rule applies to.
	Action string `json:"action,omitempty"`

	// Effect is the rule's effect: "allow" or "deny".
	Effect string `json:"effect,omitempty"`
}

// AuditEntry represents an entry in the governance audit log.
type AuditEntry struct {
	// ID is the unique entry identifier.
	ID string `json:"id"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Action is the action that was evaluated.
	Action string `json:"action"`

	// Decision is the evaluation result: "allow" or "deny".
	Decision string `json:"decision"`

	// AgentID identifies the agent that performed the action.
	AgentID string `json:"agentId,omitempty"`

	// Policy is the policy that was evaluated.
	Policy string `json:"policy,omitempty"`

	// Rule is the specific rule that matched.
	Rule string `json:"rule,omitempty"`

	// Reason explains the decision.
	Reason string `json:"reason,omitempty"`

	// Resource is the resource that was accessed.
	Resource string `json:"resource,omitempty"`

	// Meta contains additional metadata.
	Meta map[string]any `json:"meta,omitempty"`
}

// CreateAgentRequest contains parameters for creating a new agent.
type CreateAgentRequest struct {
	// Name is the display name for the new agent. Required.
	Name string `json:"name"`

	// TrustTier sets the trust level. Defaults to "verified" if empty.
	TrustTier string `json:"trustTier,omitempty"`

	// Tags are labels to assign to the agent.
	Tags []string `json:"tags,omitempty"`

	// Capabilities lists actions the agent is authorized to perform.
	Capabilities []string `json:"capabilities,omitempty"`
}

// AuditQueryOptions configures an audit log query.
type AuditQueryOptions struct {
	// Limit is the maximum number of entries to return. Defaults to 50.
	Limit int `json:"limit,omitempty"`

	// Decision filters entries by decision ("allow" or "deny").
	Decision string `json:"decision,omitempty"`

	// AgentID filters entries by agent.
	AgentID string `json:"agentId,omitempty"`

	// Action filters entries by action.
	Action string `json:"action,omitempty"`
}

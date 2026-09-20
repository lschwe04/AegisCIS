package auth

type contextKey string

const (
	ContextKeyMSPID    contextKey = "msp_id"
	ContextKeyTenantID contextKey = "tenant_id"
	ContextKeyActor    contextKey = "actor"
	ContextKeyRole     contextKey = "role" // "msp_admin", "tenant_admin", "node_agent"
)

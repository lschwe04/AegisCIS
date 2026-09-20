package middleware

import (
	"log/slog"
	"net/http"

	"aegis/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogMiddleware erfasst Mutationen und puffert sie in Staging
func AuditLogMiddleware(dbPool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {

				mspID, _ := r.Context().Value(auth.ContextKeyMSPID).(string)
				tenantID, _ := r.Context().Value(auth.ContextKeyTenantID).(string)
				actor, _ := r.Context().Value(auth.ContextKeyActor).(string)

				if mspID == "" || tenantID == "" {
					http.Error(w, "Unvollständiger Sicherheitskontext", http.StatusUnauthorized)
					return
				}

				// Payload-Kopie für DSGVO Art. 32 (PII/Secrets müssen vorher maskiert werden)
				ipAddress := r.RemoteAddr
				payload := `{"ip": "` + ipAddress + `", "path": "` + r.URL.Path + `"}`

				// Write-Ahead in Staging (ohne WORM-Locking)
				_, err := dbPool.Exec(r.Context(), `
					INSERT INTO audit_events_staging (msp_id, tenant_id, action, actor, node_id, payload) 
					VALUES ($1, $2, $3, $4, $5, $6)
				`, mspID, tenantID, r.Method, actor, "system_api", payload)

				if err != nil {
					// Prometheus Metrik Stub
					// metrics.AuditStagingErrors.Inc()
					slog.Error("Audit Staging Insertion failed", "err", err, "tenant_id", tenantID)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

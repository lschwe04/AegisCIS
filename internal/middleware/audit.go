package middleware
package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogMiddleware kapselt schreibende Zugriffe[cite: 18]
func AuditLogMiddleware(dbPool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				
				// Tenant sicher aus Context extrahieren (durch vorherige Auth-Middleware gesetzt)[cite: 18]
				tenantID, ok := r.Context().Value("authenticated_tenant_id").(string)
				if !ok || tenantID == "" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}

				// DSGVO-konforme Erfassung
				actor := "authenticated-agent-or-user" 
				ipAddress := r.RemoteAddr

				_, err := dbPool.Exec(r.Context(), `
					INSERT INTO audit_logs (tenant_id, action, actor, node_id, payload, prev_hash, current_hash) 
					VALUES ($1, $2, $3, $4, $5, 'PENDING', 'PENDING') -- Asynchrone Hash-Generierung für High-Throughput empfohlen
				`, tenantID, r.URL.Path, actor, "system", `{"ip": "`+ipAddress+`"}`)
				
				if err != nil {
					slog.Error("CRITICAL: Audit Log Injection failed", "error", err)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

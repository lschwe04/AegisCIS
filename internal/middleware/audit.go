package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	"aegis/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

// maskIP entfernt das letzte Oktett für IPv4 oder maskiert IPv6 für DSGVO Art. 32
func maskIP(remoteAddr string) string {
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipStr = remoteAddr
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "unknown"
	}
	if ip.To4() != nil {
		parts := strings.Split(ipStr, ".")
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	}
	return "masked-ipv6" // Für vollständige BSI-Konzepte hier /64 Maskierung einbauen
}

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

				maskedIP := maskIP(r.RemoteAddr)
				payload := `{"ip": "` + maskedIP + `", "path": "` + r.URL.Path + `"}`

				_, err := dbPool.Exec(r.Context(), `
					INSERT INTO audit_events_staging (msp_id, tenant_id, action, actor, node_id, payload) 
					VALUES ($1, $2, $3, $4, $5, $6)
				`, mspID, tenantID, r.Method, actor, "system_api", payload)

				if err != nil {
					slog.Error("Audit Staging Insertion failed", "err", err, "tenant_id", tenantID)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

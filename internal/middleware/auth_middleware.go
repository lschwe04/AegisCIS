package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"aegis/internal/api"
	"aegis/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

func AuthMiddleware(dbPool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. API Key aus dem Header "X-API-Key" oder "Authorization: Bearer <key>" extrahieren
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					apiKey = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			// 2. Fallback: API Key aus den URL-Query-Parametern extrahieren (Ideal für Browser & Demos)
			if apiKey == "" {
				apiKey = r.URL.Query().Get("api_key")
			}

			if apiKey == "" {
				api.SendError(w, http.StatusUnauthorized, api.ErrUnauthorized, "Missing API Key", "")
				return
			}

			// Key hashen (da nur Hashes in der DB gespeichert sind)
			hashBytes := sha256.Sum256([]byte(apiKey))
			keyHash := hex.EncodeToString(hashBytes[:])

			var mspID, role string
			var tenantID *string

			// DB-Abfrage
			err := dbPool.QueryRow(r.Context(), `
				SELECT msp_id::text, tenant_id::text, role 
				FROM api_keys WHERE key_hash = $1
			`, keyHash).Scan(&mspID, &tenantID, &role)

			if err != nil {
				api.SendError(w, http.StatusUnauthorized, api.ErrUnauthorized, "Invalid API Key", "")
				return
			}

			// Context befüllen
			ctx := context.WithValue(r.Context(), auth.ContextKeyMSPID, mspID)
			if tenantID != nil {
				ctx = context.WithValue(ctx, auth.ContextKeyTenantID, *tenantID)
			}
			ctx = context.WithValue(ctx, auth.ContextKeyRole, role)
			ctx = context.WithValue(ctx, auth.ContextKeyActor, "api_key_"+keyHash[:8])

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

package handlers
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Struktur basierend auf api/openapi.yaml[cite: 18]
type HardeningReportPayload struct {
	NodeID     string `json:"node_id"`
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	OpenIssues int    `json:"open_issues"`
}

func HandleHardeningReport(dbPool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		tenantID, ok := r.Context().Value("authenticated_tenant_id").(string)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var payload HardeningReportPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}

		// CIS Level Compliance Logik
		cisLevel1 := payload.Success && payload.OpenIssues == 0

		// Upsert Hardening Status[cite: 18]
		_, err := dbPool.Exec(r.Context(), `
			INSERT INTO hardening_status (node_id, tenant_id, cis_level_1_compliant, open_issues, last_report_time)
			VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
			ON CONFLICT (node_id) DO UPDATE SET 
				cis_level_1_compliant = EXCLUDED.cis_level_1_compliant,
				open_issues = EXCLUDED.open_issues,
				last_report_time = EXCLUDED.last_report_time
		`, payload.NodeID, tenantID, cisLevel1, payload.OpenIssues)

		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "Report accepted"})
	}
}

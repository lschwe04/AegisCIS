package handlers

import (
	"encoding/json"
	"net/http"

	"aegis/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

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

		// Strikte MSP & Tenant Validierung
		mspID, _ := r.Context().Value(auth.ContextKeyMSPID).(string)
		tenantID, _ := r.Context().Value(auth.ContextKeyTenantID).(string)

		if mspID == "" || tenantID == "" {
			http.Error(w, "Unauthorized Context", http.StatusUnauthorized)
			return
		}

		var payload HardeningReportPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}

		cisLevel1 := payload.Success && payload.OpenIssues == 0

		// Upsert mit Composite Key (MSP + Tenant + Node) zur Kollisionsvermeidung
		_, err := dbPool.Exec(r.Context(), `
			INSERT INTO hardening_status (msp_id, tenant_id, node_id, cis_level_1_compliant, open_issues, last_report_time)
			VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
			ON CONFLICT (msp_id, tenant_id, node_id) DO UPDATE SET 
				cis_level_1_compliant = EXCLUDED.cis_level_1_compliant,
				open_issues = EXCLUDED.open_issues,
				last_report_time = CURRENT_TIMESTAMP
		`, mspID, tenantID, payload.NodeID, cisLevel1, payload.OpenIssues)

		if err != nil {
			http.Error(w, "Database persistence failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "Report accepted"})
	}
}

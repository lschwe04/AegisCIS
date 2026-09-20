package handlers

import (
	"encoding/json"
	"net/http"

	"aegis/internal/api"
	"aegis/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FailedControl liefert UX-freundliche Remediation-Tipps fürs Dashboard
type FailedControl struct {
	ControlID      string `json:"control_id"`      // z.B. "CIS-3.2.2"
	Description    string `json:"description"`     // z.B. "Ensure IP forwarding is disabled"
	RemediationCmd string `json:"remediation_cmd"` // z.B. "sysctl -w net.ipv4.ip_forward=0"
}

type HardeningReportPayload struct {
	NodeID         string          `json:"node_id"`
	Success        bool            `json:"success"`
	Message        string          `json:"message"`
	OpenIssues     int             `json:"open_issues"`
	FailedControls []FailedControl `json:"failed_controls"` // NEU
}

func HandleHardeningReport(dbPool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.SendError(w, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Only POST allowed", "")
			return
		}

		// MSP-Sicherheitscodes statt flachem Authenticated_tenant_id[cite: 12]
		mspID, _ := r.Context().Value(auth.ContextKeyMSPID).(string)
		tenantID, _ := r.Context().Value(auth.ContextKeyTenantID).(string)

		if mspID == "" || tenantID == "" {
			api.SendError(w, http.StatusUnauthorized, api.ErrUnauthorized, "Missing MSP or Tenant Context", "")
			return
		}

		var payload HardeningReportPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			api.SendError(w, http.StatusBadRequest, api.ErrInvalidPayload, "Malformed JSON", err.Error())
			return
		}

		failedControlsJSON, err := json.Marshal(payload.FailedControls)
		if err != nil {
			api.SendError(w, http.StatusInternalServerError, api.ErrInvalidPayload, "Failed to parse controls", "")
			return
		}

		cisLevel1 := payload.Success && payload.OpenIssues == 0

		// Upsert mit Composite Key für 10.000+ Nodes über alle Kunden hinweg
		_, err = dbPool.Exec(r.Context(), `
			INSERT INTO hardening_status (msp_id, tenant_id, node_id, cis_level_1_compliant, open_issues, failed_controls, last_report_time)
			VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
			ON CONFLICT (msp_id, tenant_id, node_id) DO UPDATE SET 
				cis_level_1_compliant = EXCLUDED.cis_level_1_compliant,
				open_issues = EXCLUDED.open_issues,
				failed_controls = EXCLUDED.failed_controls,
				last_report_time = CURRENT_TIMESTAMP
		`, mspID, tenantID, payload.NodeID, cisLevel1, payload.OpenIssues, failedControlsJSON)

		if err != nil {
			api.SendError(w, http.StatusInternalServerError, api.ErrDBWriteFailed, "Database persistence failed", "")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "Report accepted", "node_id": payload.NodeID})
	}
}

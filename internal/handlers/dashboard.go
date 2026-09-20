package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"aegis/internal/auth"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DashboardData struct {
	MSP_ID string
	Nodes  []NodeStatus
}

type NodeStatus struct {
	NodeID         string
	IsCompliant    bool
	OpenIssues     int
	LastReport     time.Time
	FailedControls []FailedControl // Verwendet die bestehende Struct[cite: 8]
}

const dashboardHTML = `
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>AegisCIS - MSP Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 text-gray-800 font-sans p-8">
    <div class="max-w-7xl mx-auto">
        <div class="flex justify-between items-center mb-8">
            <h1 class="text-3xl font-bold text-gray-900">🛡️ AegisCIS Remediation Center</h1>
            <span class="bg-blue-100 text-blue-800 text-sm font-semibold px-4 py-2 rounded">MSP-View</span>
        </div>

        <div class="bg-white shadow rounded-lg overflow-hidden">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Node ID</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Offene Issues</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Remediation Action (RMM)</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    {{range .Nodes}}
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap font-medium">{{.NodeID}}</td>
                        <td class="px-6 py-4 whitespace-nowrap">
                            {{if .IsCompliant}}
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Compliant (CIS L1)</span>
                            {{else}}
                                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Non-Compliant</span>
                            {{end}}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap">{{.OpenIssues}}</td>
                        <td class="px-6 py-4">
                            {{range .FailedControls}}
                                <div class="mb-2 p-2 bg-gray-50 rounded border border-gray-200">
                                    <p class="text-xs font-bold text-gray-700">{{.ControlID}}: {{.Description}}</p>
                                    <code class="text-xs text-pink-600 bg-pink-50 p-1 rounded block mt-1 select-all cursor-pointer" onclick="navigator.clipboard.writeText('{{.RemediationCmd}}'); alert('Fix kopiert!');">{{.RemediationCmd}}</code>
                                </div>
                            {{end}}
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
`

func HandleDashboard(dbPool *pgxpool.Pool) http.HandlerFunc {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))

	return func(w http.ResponseWriter, r *http.Request) {
		mspID, _ := r.Context().Value(auth.ContextKeyMSPID).(string)

		// Lädt den Härtungs-Status[cite: 8]
		rows, err := dbPool.Query(r.Context(), `
			SELECT node_id, cis_level_1_compliant, open_issues, failed_controls, last_report_time 
			FROM hardening_status 
			WHERE msp_id = $1::UUID
			ORDER BY cis_level_1_compliant ASC, node_id ASC
		`, mspID)

		if err != nil {
			http.Error(w, "Datenbankfehler", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var data DashboardData
		for rows.Next() {
			var node NodeStatus
			var failedControlsJSON []byte
			rows.Scan(&node.NodeID, &node.IsCompliant, &node.OpenIssues, &failedControlsJSON, &node.LastReport)
			json.Unmarshal(failedControlsJSON, &node.FailedControls)
			data.Nodes = append(data.Nodes, node)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl.Execute(w, data)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// Spiegelt die Struktur aus handlers/hardening.go wider
type FailedControl struct {
	ControlID      string `json:"control_id"`
	Description    string `json:"description"`
	RemediationCmd string `json:"remediation_cmd"`
}

type HardeningReportPayload struct {
	NodeID         string          `json:"node_id"`
	Success        bool            `json:"success"`
	Message        string          `json:"message"`
	OpenIssues     int             `json:"open_issues"`
	FailedControls []FailedControl `json:"failed_controls"`
}

func main() {
	apiURL := flag.String("api", "http://localhost:8080/api/v1/hardening/report", "Aegis API URL")
	apiKey := flag.String("key", "DEMO-AGENT-KEY-123", "Agent API Key")
	nodeID := flag.String("node", "srv-pitch-demo-01", "Node Identifier")
	flag.Parse()

	fmt.Printf("🛡️ AegisCIS Agent startet Scan für Node: %s\n", *nodeID)

	var failedControls []FailedControl

	// Echter lokaler Scan (Beispiel: IP Forwarding auf Linux)
	if runtime.GOOS == "linux" {
		out, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err == nil && strings.TrimSpace(string(out)) == "1" {
			failedControls = append(failedControls, FailedControl{
				ControlID:      "CIS-3.2.2",
				Description:    "Ensure IP forwarding is disabled",
				RemediationCmd: "sysctl -w net.ipv4.ip_forward=0",
			})
		}
	} else {
		// Mock-Daten für Windows/Pitch-Demonstration
		failedControls = append(failedControls, FailedControl{
			ControlID:      "CIS-5.2.10",
			Description:    "Ensure SSH Root Login is disabled",
			RemediationCmd: "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
		})
	}

	payload := HardeningReportPayload{
		NodeID:         *nodeID,
		Success:        len(failedControls) == 0,
		Message:        fmt.Sprintf("Scan completed. %d issues found.", len(failedControls)),
		OpenIssues:     len(failedControls),
		FailedControls: failedControls,
	}

	payloadBytes, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, *apiURL, bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", *apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("❌ Verbindung zur Aegis-API fehlgeschlagen: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("❌ API-Fehler (Code %d): %s", resp.StatusCode, string(body))
	}

	fmt.Println("✅ Report erfolgreich gesendet. WORM-Audit getriggert.")
}

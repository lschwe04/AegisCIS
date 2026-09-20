package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	tenantID := flag.String("tenant", "", "Tenant UUID")
	month := flag.String("month", "", "Format YYYY-MM (e.g. 2026-09)")
	flag.Parse()

	if *tenantID == "" || *month == "" {
		log.Fatal("Usage: aegis-cli --tenant=<uuid> --month=<YYYY-MM>")
	}

	connStr := os.Getenv("DATABASE_URL")
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		log.Fatalf("DB Connection failed: %v", err)
	}
	defer conn.Close(ctx)

	// Nutzt die abstrahierte View statt fester Partitionsnamen
	query := `
		SELECT id, action, actor, node_id, payload, prev_hash, current_hash, created_at 
		FROM view_audit_logs_export 
		WHERE tenant_id = $1 AND audit_month = $2 
		ORDER BY id ASC`

	rows, err := conn.Query(ctx, query, *tenantID, *month)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	fmt.Printf("🔒 BSI WORM Audit gestartet für Mandant: %s (Monat: %s)\n", *tenantID, *month)
	var expectedPrevHash string = "0000000000000000000000000000000000000000000000000000000000000000"
	verifiedCount := 0

	for rows.Next() {
		var id int64
		var action, actor, nodeID, payload, prevHash, currentHash string
		var createdAt time.Time

		if err := rows.Scan(&id, &action, &actor, &nodeID, &payload, &prevHash, &currentHash, &createdAt); err != nil {
			log.Fatalf("Row scan failed: %v", err)
		}

		if prevHash != expectedPrevHash {
			log.Fatalf("❌ CHAIN BROKEN at ID %d!\nErwartet: %s\nGefunden: %s", id, expectedPrevHash, prevHash)
		}

		dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			prevHash, *tenantID, action, actor, nodeID, payload, createdAt.Format(time.RFC3339Nano))

		hashBytes := sha256.Sum256([]byte(dataToHash))
		computedHash := hex.EncodeToString(hashBytes[:])

		if computedHash != currentHash {
			log.Fatalf("❌ TAMPERING DETECTED at ID %d! Payload/Zeitstempel manipuliert.", id)
		}

		expectedPrevHash = currentHash
		verifiedCount++
	}

	fmt.Printf("✅ ERFOLG: %d Logs validiert. Kryptografische Integrität zu 100%% bestätigt.\n", verifiedCount)
}

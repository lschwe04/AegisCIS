package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

// usage: aegis-cli verify --tenant=1234-abcd --month=2026-09
func main() {
	if len(os.Args) < 3 {
		log.Fatal("Usage: aegis-cli verify <tenant_id> <partition_table>")
	}
	tenantID := os.Args[1]
	partition := os.Args[2] // z.B. audit_logs_y2026m09

	connStr := os.Getenv("DATABASE_URL")
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		log.Fatalf("DB Connection failed: %v", err)
	}
	defer conn.Close(ctx)

	// Dynamischer Tabellenname (Partition) ist bei read-only Audit-Tools vertretbar
	query := fmt.Sprintf(`
		SELECT id, action, actor, node_id, payload, prev_hash, current_hash, created_at 
		FROM %s 
		WHERE tenant_id = $1 
		ORDER BY id ASC`, partition)

	rows, err := conn.Query(ctx, query, tenantID)
	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}
	defer rows.Close()

	fmt.Printf("Starting cryptographic verification for Tenant: %s\n", tenantID)
	var expectedPrevHash string = "0000000000000000000000000000000000000000000000000000000000000000"
	var verifiedCount int

	for rows.Next() {
		var id int64
		var action, actor, nodeID, payload, prevHash, currentHash string
		var createdAt time.Time

		err := rows.Scan(&id, &action, &actor, &nodeID, &payload, &prevHash, &currentHash, &createdAt)
		if err != nil {
			log.Fatalf("Row scan failed: %v", err)
		}

		// 1. Check Chain Continuity
		if prevHash != expectedPrevHash {
			log.Fatalf("❌ CHAIN BROKEN at ID %d! Expected PrevHash %s, got %s", id, expectedPrevHash, prevHash)
		}

		// 2. Recompute Hash (Exakte Logik wie im Worker)
		dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			prevHash, tenantID, action, actor, nodeID, payload, createdAt.Format(time.RFC3339Nano))

		hashBytes := sha256.Sum256([]byte(dataToHash))
		computedHash := hex.EncodeToString(hashBytes[:])

		// 3. Verify Integrity
		if computedHash != currentHash {
			log.Fatalf("❌ TAMPERING DETECTED at ID %d! Payload or timestamp was modified.", id)
		}

		expectedPrevHash = currentHash
		verifiedCount++
	}

	fmt.Printf("✅ VERIFIED: %d sequential WORM entries cryptographically intact.\n", verifiedCount)
}

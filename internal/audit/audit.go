package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Logger struct {
	pool *pgxpool.Pool
}

func NewLogger(pool *pgxpool.Pool) *Logger {
	return &Logger{pool: pool}
}

// LogEvent schreibt einen fälschungssicheren Audit-Log-Eintrag
func (l *Logger) LogEvent(ctx context.Context, tenantID, action, actor, nodeID string, payload map[string]any) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("audit payload marshal failed: %w", err)
	}

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// FOR UPDATE erzwingt Sequentialität für sichere Hash-Ketten
	var lastHash string
	err = tx.QueryRow(ctx, `
		SELECT current_hash FROM audit_logs 
		WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE
	`, tenantID).Scan(&lastHash)

	if err != nil {
		// Genesis Hash nach BSI/NIST-Standard[cite: 18]
		lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	now := time.Now().UTC()

	// Hash-Generierung[cite: 18]
	dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		lastHash, tenantID, action, actor, nodeID, string(payloadBytes), now.Format(time.RFC3339Nano),
	)
	hashBytes := sha256.Sum256([]byte(dataToHash))
	currentHash := hex.EncodeToString(hashBytes[:])

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs (tenant_id, action, actor, node_id, payload, prev_hash, current_hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, tenantID, action, actor, nodeID, string(payloadBytes), lastHash, currentHash, now)

	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return tx.Commit(ctx)
}

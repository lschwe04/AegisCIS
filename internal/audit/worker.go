package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type WORMBuilder struct {
	pool *pgxpool.Pool
}

func NewWORMBuilder(pool *pgxpool.Pool) *WORMBuilder {
	return &WORMBuilder{pool: pool}
}

// StartWORMWorker läuft als Background-Goroutine
func (w *WORMBuilder) StartWORMWorker(ctx context.Context, pollInterval time.Duration) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.processBatch(ctx); err != nil {
				slog.Error("WORM batch processing failed", "error", err)
			}
		}
	}
}

func (w *WORMBuilder) processBatch(ctx context.Context) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 1. Hole Batch aus Staging (mit Lock auf die Zeilen)
	rows, err := tx.Query(ctx, `
		DELETE FROM audit_events_staging 
		WHERE id IN (SELECT id FROM audit_events_staging ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED)
		RETURNING id, msp_id, tenant_id, action, actor, node_id, payload, created_at
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// 2. Hash-Verkettung (Batch-optimiert)
	for rows.Next() {
		var id int64
		var mspID, tenantID, action, actor, nodeID, payload string
		var createdAt time.Time

		if err := rows.Scan(&id, &mspID, &tenantID, &action, &actor, &nodeID, &payload, &createdAt); err != nil {
			return err
		}

		// FOR UPDATE Lock nur für diesen spezifischen Tenant während der Hash-Berechnung
		var lastHash string
		err = tx.QueryRow(ctx, `
			SELECT current_hash FROM audit_logs 
			WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE
		`, tenantID).Scan(&lastHash)

		if err != nil {
			lastHash = "0000000000000000000000000000000000000000000000000000000000000000" // BSI Genesis Hash
		}

		dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
			lastHash, tenantID, action, actor, nodeID, payload, createdAt.Format(time.RFC3339Nano))

		hashBytes := sha256.Sum256([]byte(dataToHash))
		currentHash := hex.EncodeToString(hashBytes[:])

		_, err = tx.Exec(ctx, `
			INSERT INTO audit_logs (msp_id, tenant_id, action, actor, node_id, payload, prev_hash, current_hash, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, mspID, tenantID, action, actor, nodeID, payload, lastHash, currentHash, createdAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

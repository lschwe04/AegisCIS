package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
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

type stagingEvent struct {
	id                                              int64
	mspID, tenantID, action, actor, nodeID, payload string
	createdAt                                       time.Time
}

func (w *WORMBuilder) processBatch(ctx context.Context) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// 1. Hole Batch & locke
	rows, err := tx.Query(ctx, `
		DELETE FROM audit_events_staging 
		WHERE id IN (SELECT id FROM audit_events_staging ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED)
		RETURNING id, msp_id, tenant_id, action, actor, node_id, payload, created_at
	`)
	if err != nil {
		return err
	}

	// Gruppiere nach Tenant für in-memory Hash-Ketten
	eventsByTenant := make(map[string][]stagingEvent)
	for rows.Next() {
		var e stagingEvent
		if err := rows.Scan(&e.id, &e.mspID, &e.tenantID, &e.action, &e.actor, &e.nodeID, &e.payload, &e.createdAt); err != nil {
			rows.Close()
			return err
		}
		eventsByTenant[e.tenantID] = append(eventsByTenant[e.tenantID], e)
	}
	rows.Close()

	if len(eventsByTenant) == 0 {
		return tx.Commit(ctx) // Nichts zu tun
	}

	batch := &pgx.Batch{}

	// 2. Hash-Verkettung (In-Memory per Tenant)
	for tenantID, events := range eventsByTenant {
		var lastHash string
		err = tx.QueryRow(ctx, `
			SELECT current_hash FROM audit_logs 
			WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1 FOR UPDATE
		`, tenantID).Scan(&lastHash)

		if err != nil {
			lastHash = "0000000000000000000000000000000000000000000000000000000000000000" // BSI Genesis Hash
		}

		for _, e := range events {
			dataToHash := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
				lastHash, e.tenantID, e.action, e.actor, e.nodeID, e.payload, e.createdAt.Format(time.RFC3339Nano))

			hashBytes := sha256.Sum256([]byte(dataToHash))
			currentHash := hex.EncodeToString(hashBytes[:])

			batch.Queue(`
				INSERT INTO audit_logs (msp_id, tenant_id, action, actor, node_id, payload, prev_hash, current_hash, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			`, e.mspID, e.tenantID, e.action, e.actor, e.nodeID, e.payload, lastHash, currentHash, e.createdAt)

			lastHash = currentHash // Verkettung im RAM vorantreiben
		}
	}

	// 3. Batch-Execution (1 DB-Roundtrip für alle 500 Inserts)
	br := tx.SendBatch(ctx, batch)
	if err := br.Close(); err != nil {
		return fmt.Errorf("batch insert failed: %w", err)
	}

	return tx.Commit(ctx)
}

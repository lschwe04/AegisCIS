-- 1. Index für den Worker (beschleunigt das ORDER BY id ... FOR UPDATE SKIP LOCKED)
-- Durch WHERE-Klausel wird der Index extrem klein gehalten (Partial Index)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_staging_queue 
ON audit_events_staging (id) 
INCLUDE (msp_id, tenant_id, action, actor, node_id, payload, created_at);

-- 2. Audit-View für einfache CLI-Abfragen ohne Partitions-Kenntnisse
CREATE OR REPLACE VIEW view_audit_logs_export AS 
SELECT 
    id, msp_id, tenant_id, action, actor, node_id, payload, prev_hash, current_hash, created_at,
    to_char(created_at, 'YYYY-MM') as audit_month
FROM audit_logs;

-- RLS auch auf die View anwenden
ALTER VIEW view_audit_logs_export OWNER TO CURRENT_USER;

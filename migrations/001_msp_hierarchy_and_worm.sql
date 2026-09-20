-- Bestehende flache Tabellen aufräumen (falls Test-Daten existieren)
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS hardening_status CASCADE;
DROP TABLE IF EXISTS audit_events_staging CASCADE;

-- 0. Hardening Status (Multi-Tenant & Multi-Node)
CREATE TABLE hardening_status (
    msp_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    node_id VARCHAR(128) NOT NULL,
    cis_level_1_compliant BOOLEAN DEFAULT FALSE,
    open_issues INTEGER DEFAULT 0,
    last_report_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (msp_id, tenant_id, node_id)
);

-- 1. High-Throughput Staging (Wird von Middleware befüllt)
CREATE TABLE audit_events_staging (
    id BIGSERIAL PRIMARY KEY,
    msp_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    action VARCHAR(128) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    node_id VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. WORM Audit Log (Partitioniert für Skalierung, befüllt durch Async Worker)
CREATE TABLE audit_logs (
    id BIGSERIAL,
    msp_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    action VARCHAR(128) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    node_id VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Partitionen anlegen (Beispiel aktueller Monat)
CREATE TABLE audit_logs_y2026m09 PARTITION OF audit_logs 
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');

-- Indizes für effiziente WORM-Ketten-Suche durch den Worker
CREATE INDEX idx_audit_logs_tenant_hash ON audit_logs (tenant_id, id DESC);

-- RLS (Row Level Security) aktivieren
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardening_status ENABLE ROW LEVEL SECURITY;

-- Policy für audit_logs
CREATE POLICY msp_audit_isolation ON audit_logs
    USING (
        (current_setting('app.role', true) = 'msp_admin' AND msp_id = nullif(current_setting('app.msp_id', true), '')::UUID)
        OR 
        (current_setting('app.role', true) = 'tenant_admin' AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::UUID)
    );

-- Policy für hardening_status
CREATE POLICY msp_hardening_isolation ON hardening_status
    USING (
        (current_setting('app.role', true) = 'msp_admin' AND msp_id = nullif(current_setting('app.msp_id', true), '')::UUID)
        OR 
        (current_setting('app.role', true) = 'tenant_admin' AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::UUID)
    );

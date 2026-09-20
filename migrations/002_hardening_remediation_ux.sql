-- Datei: migrations/002_hardening_remediation_ux.sql

-- Löschen der alten, flachen Tabelle
DROP TABLE IF EXISTS hardening_status CASCADE;

CREATE TABLE hardening_status (
    msp_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    node_id VARCHAR(128) NOT NULL,
    cis_level_1_compliant BOOLEAN DEFAULT FALSE,
    open_issues INTEGER DEFAULT 0,
    -- NEU: Speichert die konkreten Fehlkonfigurationen & Fixes für das Dashboard
    failed_controls JSONB DEFAULT '[]'::jsonb, 
    last_report_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (msp_id, tenant_id, node_id)
);

-- Index für Dashboard-Suchen (Welche Nodes haben spezifische CIS-Fails?)
CREATE INDEX idx_hardening_failed_controls ON hardening_status USING GIN (failed_controls);

-- RLS für saubere Mandantentrennung im Dashboard
ALTER TABLE hardening_status ENABLE ROW LEVEL SECURITY;

CREATE POLICY msp_hardening_isolation ON hardening_status
    USING (
        (current_setting('app.role', true) = 'msp_admin' AND msp_id = nullif(current_setting('app.msp_id', true), '')::UUID)
        OR 
        (current_setting('app.role', true) = 'tenant_admin' AND tenant_id = nullif(current_setting('app.tenant_id', true), '')::UUID)
    );

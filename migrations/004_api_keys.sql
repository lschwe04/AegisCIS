CREATE TABLE api_keys (
    key_hash VARCHAR(64) PRIMARY KEY, -- SHA256 des Keys (Best Practice, niemals plain speichern)
    msp_id UUID NOT NULL,
    tenant_id UUID,                   -- NULL wenn es ein MSP-weiter Key ist
    role VARCHAR(32) NOT NULL,        -- 'msp_admin', 'tenant_admin', 'node_agent'
    description VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Lege einen Demo-Agenten-Key und einen Admin-Key für deinen Pitch an:
-- Plain Key 1: "DEMO-AGENT-KEY-123" -> Hash: 3e0281b378051786...
-- Plain Key 2: "DEMO-ADMIN-KEY-456" -> Hash: 12b...
INSERT INTO api_keys (key_hash, msp_id, tenant_id, role, description) VALUES 
-- SHA256 von 'DEMO-AGENT-KEY-123'
('3e0281b3780517865f37ef6ed7cb3f2df7d4f901a1c97a55ed9960db87fb64db', '11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'node_agent', 'Pitch Demo Agent'),
-- SHA256 von 'DEMO-ADMIN-KEY-456'
('12b3391d4e0a7eb5cb0bb96c1df3bd90f230cd71edccbb15c5e00311f67fce51', '11111111-1111-1111-1111-111111111111', NULL, 'msp_admin', 'Pitch Demo Admin');

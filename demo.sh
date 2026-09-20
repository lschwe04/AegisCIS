#!/usr/bin/env bash
set -euo pipefail

# Verzeichnis für Binaries erstellen
mkdir -p bin

CLEANUP_DOCKER=false
if ! docker ps --format '{{.Names}}' | grep -q '^aegis-postgres$'; then
    echo "=== 1. Starte PostgreSQL via Docker ==="
    docker run --name aegis-postgres \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=secret \
        -e POSTGRES_DB=aegis \
        -p 5432:5432 \
        -d postgres:15-alpine >/dev/null
    CLEANUP_DOCKER=true
    echo "Warte auf PostgreSQL (3 Sek.)..."
    sleep 3
else
    echo "=== 1. PostgreSQL läuft bereits ==="
fi

export DATABASE_URL="postgres://postgres:secret@localhost:5432/aegis"

echo "=== 2. Wende DB-Migrationen an ==="
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_msp_hierarchy_and_worm.log >/dev/null 2>&1 || true
# Direktes Ausführen der SQLs über psql:
psql "$DATABASE_URL" -f migrations/001_msp_hierarchy_and_worm.sql >/dev/null
psql "$DATABASE_URL" -f migrations/002_hardening_remediation_ux.sql >/dev/null
psql "$DATABASE_URL" -f migrations/003_performance_and_audit_ux.sql >/dev/null
psql "$DATABASE_URL" -f migrations/004_api_keys.sql >/dev/null

# Read-only Auditor User für CLI-Test anlegen & Rechte geben
psql "$DATABASE_URL" -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'readonly_auditor') THEN CREATE ROLE readonly_auditor LOGIN PASSWORD 'secret'; END IF; END \$\$;" >/dev/null
psql "$DATABASE_URL" -c "GRANT CONNECT ON DATABASE aegis TO readonly_auditor;" >/dev/null
psql "$DATABASE_URL" -c "GRANT USAGE ON SCHEMA public TO readonly_auditor;" >/dev/null
psql "$DATABASE_URL" -c "GRANT SELECT ON audit_logs TO readonly_auditor;" >/dev/null
psql "$DATABASE_URL" -c "GRANT SELECT ON view_audit_logs_export TO readonly_auditor;" >/dev/null

echo "=== 3. Baue Go-Binaries ==="
go build -o bin/aegis-server ./cmd/aegis-server
go build -o bin/aegis-agent ./cmd/aegis-agent
go build -o bin/aegis-cli ./cmd/aegis-cli

echo "=== 4. Starte Aegis Server im Hintergrund ==="
./bin/aegis-server &
SERVER_PID=$!

# Trap für sauberes Aufräumen bei Exit/Ctrl+C
cleanup() {
    echo "=== 🧹 Cleanup ==="
    kill $SERVER_PID 2>/dev/null || true
    if [ "$CLEANUP_DOCKER" = true ]; then
        docker rm -f aegis-postgres 2>/dev/null || true
    fi
}
trap cleanup EXIT

sleep 2

echo "=== 5. Starte Aegis Agent (Simuliert Node-Scan & Report) ==="
./bin/aegis-agent \
    -api http://localhost:8080/api/v1/hardening/report \
    -key DEMO-AGENT-KEY-123 \
    -node srv-pitch-demo-01

echo "=== 6. Warte auf WORM Worker (Batch-Flush, 3 Sek.) ==="
sleep 3

echo "=== 7. Führe BSI CLI Verifizierung aus ==="
export DATABASE_URL="postgres://readonly_auditor:secret@localhost:5432/aegis"
./bin/aegis-cli \
    --tenant="22222222-2222-2222-2222-222222222222" \
    --month="2026-09"

echo "=== 🎉 DEMO ERFOLGREICH DURCHGELAUFEN ==="

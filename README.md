# AegisCIS – Enterprise DACH MSP Hardening & Audit Platform

**AegisCIS** ist eine unbestechliche, multi-tenant-fähige Härtungs- und Audit-Plattform für IT-Systemhäuser (MSPs) im DACH-Raum. Sie kombiniert BSI/CIS-konformes Security-Reporting mit einer kryptografisch verketteten WORM-Audit-Pipeline (Write Once, Read Many) und integrierten Remediation-Playbooks für Administratoren.

---

## 🏗️ Systemarchitektur & Datenfluss

```mermaid
graph TD
    subgraph EdgeNodes ["Edge / Nodes"]
        Node[Managed Node] -->|local scan| Agent[Aegis Agent]
    end

    subgraph CoreAPI ["Core API (aegis-server)"]
        Agent -->|HTTPS POST + X-API-Key| Server[Aegis Server]
        Server --> Auth[Auth Middleware / SHA256 Hash]
        Auth --> AuditMw[Audit Log Middleware / DSGVO /24 IP Masking]
    end

    subgraph StorageWORM ["Storage & WORM Pipeline (PostgreSQL)"]
        AuditMw --> Staging[(audit_events_staging)]
        Worker[WORM Background Worker] -->|FOR UPDATE SKIP LOCKED batch| Staging
        Worker -->|SHA256 Hash Chain RAM| WORM[(partitioned audit_logs WORM)]
        Auth --> HardeningDB[(hardening_status Composite PK)]
    end

    subgraph UXCompliance ["UX & Compliance"]
        HardeningDB --> Dashboard[Dashboard / RMM Remediation Copy]
        WORM --> CLI[aegis-cli BSI Verifier]
    end
    

🎯 Policy Tiers (Mandanten-Skalierung ohne Code-Forks)
AegisCIS steuert Funktionstiefen über mandantenspezifische Tier-Konfigurationen:

Tier A (Audit/Basic): Nur Read-Only-Scanning, WORM-Audit-Export für BSI/Compliance-Nachweise, Dashboard-Reporting (ohne Remediation-Spalte).

Tier B (Standard Hardening): CIS Level 1 Checks + kopierbare RMM-Remediation-Befehle (Default-Stand).

Tier C (Enforced/Advanced): CIS Level 2 / Gated Pre-flight Execution mit Dry-Run-Mode und Rollback-Timer (in Vorbereitung).

1. Architektur- & Mandantenmodell
AegisCIS erzwingt eine strikte 3-stufige Hierarchie auf Datenbank- und API-Ebene:

Systemhaus (MSP-ID) -> Endkunde (Tenant-ID) -> Node / Server (Node-ID)

Isolation: PostgreSQL Row Level Security (msp_audit_isolation, msp_hardening_isolation) trennt Daten auf Datenbankebene nach msp_id und tenant_id via Sessions-Kontext (app.role, app.msp_id, app.tenant_id).

Kollisionsfreiheit: Alle Hardening-Status-Einträge nutzen einen Composite Primary Key (msp_id, tenant_id, node_id).

Asynchroner WORM-Engine: API-Mutationen werden latenzfrei (<20ms) in Staging-Tabellen gepuffert (audit_events_staging) und von einem Background-Worker in-memory verkettet und chargenweise in die WORM-Partitionen geschrieben (audit_logs).

2. API, Auth & Security
Auth: Gehashte API-Keys (SHA256 in api_keys-Tabelle, rollenbasiert: msp_admin, tenant_admin, node_agent).

DSGVO by Design: IP-Adressen im Audit-Log werden automatisiert maskiert (192.168.1.0/24).

RFC 7807: API-Fehler folgen dem standardisierten Problem-Details-Format (application/problem+json).

3. Quickstart & BSI-Verifikation
BSI-Prüfer / Audit-Export (aegis-cli)

DATABASE_URL="postgres://readonly_auditor:secret@db:5432/aegis" \
aegis-cli --tenant="12345678-1111-2222-3333-444455556666" --month="2026-09"

Installation, Migration & Build
Siehe Developer-Operations-Guide für DB-Migrationspfade (001-004) und Cross-Kompilierung.

4. Playbooks & Dokumentation
System-Administratoren

BSI-Prüfer

Endkunden-Admins
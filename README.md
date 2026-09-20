# AegisCIS – Enterprise DACH MSP Hardening & Audit Platform

**AegisCIS** ist eine unbestechliche, multi-tenant-fähige Härtungs- und Audit-Plattform für IT-Systemhäuser (MSPs) im DACH-Raum. Sie kombiniert BSI/CIS-konformes Security-Reporting mit einer kryptografisch verketteten WORM-Audit-Pipeline (Write Once, Read Many) und integrierten Remediation-Playbooks für Administratoren.

---

## 🏗️ Systemarchitektur & Datenfluss

```mermaid
graph TD
    subgraph Edge / Nodes
        Node[Managed Node] -->|local scan| Agent[Aegis Agent]
    end

    subgraph Core API (aegis-server)
        Agent -->|HTTPS POST + X-API-Key| Server[Aegis Server]
        Server --> Auth[Auth Middleware / SHA256 Hash]
        Auth --> AuditMw[Audit Log Middleware / DSGVO /24 IP Masking]
    end

    subgraph Storage & WORM Pipeline (PostgreSQL)
        AuditMw --> Staging[(audit_events_staging)]
        Worker[WORM Background Worker] -->|FOR UPDATE SKIP LOCKED batch| Staging
        Worker -->|SHA256 Hash Chain RAM| WORM[(partitioned audit_logs WORM)]
        Auth --> HardeningDB[(hardening_status Composite PK)]
    end

    subgraph UX & Compliance
        HardeningDB --> Dashboard[Dashboard / RMM Remediation Copy]
        WORM --> CLI[aegis-cli BSI Verifier]
    end

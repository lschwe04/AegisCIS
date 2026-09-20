# AegisCIS – Enterprise DACH MSP Hardening & Audit Platform

**AegisCIS** ist eine unbestechliche, multi-tenant-fähige Härtungs- und Audit-Plattform für IT-Systemhäuser (MSPs) im DACH-Raum. Sie kombiniert BSI/CIS-konformes Security-Reporting mit einer kryptografisch verketteten WORM-Audit-Pipeline (Write Once, Read Many) und integrierten Remediation-Playbooks für Administratoren.

---

## 1. Architektur- & Mandantenmodell

AegisCIS erzwingt eine strikte 3-stufige Hierarchie auf Datenbank- und API-Ebene:

<p align="center">
  <img src="docs/diagram.jpg" alt="AegisCIS Architecture Flow" width="650">
</p>

* **Isolation**: PostgreSQL Row Level Security (RLS) trennt Daten auf Datenbankebene nach `msp_id` und `tenant_id`.
* **Kollisionsfreiheit**: Alle Hardening-Status-Einträge nutzen einen Composite Primary Key `(msp_id, tenant_id, node_id)`.
* **Asynchroner WORM-Engine**: API-Mutationen werden latenzfrei (<20ms) in Staging-Tabellen gepuffert und von einem Background-Worker in-memory verkettet und chargenweise in die WORM-Partitionen geschrieben.


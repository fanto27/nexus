from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from nexus.core.models import Finding, ScanResult, Service


def _default_db_path() -> Path:
    data_home = Path(
        os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")
    )
    return data_home / "nexus" / "nexus.sqlite3"


class Store:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser() if path else _default_db_path()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        try:
            self.path.parent.chmod(0o700)
        except OSError:
            pass

        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    status TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    ports_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_targets (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    address TEXT NOT NULL,
                    PRIMARY KEY (scan_id, address)
                );

                CREATE TABLE IF NOT EXISTS services (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT,
                    tls INTEGER,
                    certificate_json TEXT,
                    PRIMARY KEY (scan_id, address, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    target_address TEXT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    what TEXT NOT NULL,
                    why TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    cve_id TEXT,
                    source TEXT
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    at TEXT NOT NULL,
                    plugin_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    action TEXT NOT NULL,
                    expected_impact TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_services_scan
                    ON services(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_scan
                    ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_actions_scan
                    ON actions(scan_id);
                """
            )

        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save_scan(self, result: ScanResult, mode: str) -> str:
        scan_id = result.scan_id or uuid.uuid4().hex
        result.scan_id = scan_id

        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO scans
                    (id, started_at, duration_seconds, status, mode, ports_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    result.started_at,
                    result.duration_seconds,
                    result.status,
                    mode,
                    json.dumps(result.ports),
                ),
            )

            connection.executemany(
                "INSERT INTO scan_targets(scan_id, address) VALUES (?, ?)",
                [(scan_id, address) for address in result.targets],
            )

            for service in result.services:
                connection.execute(
                    """
                    INSERT INTO services
                        (scan_id, address, port, protocol, state, name,
                         version, tls, certificate_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        service.address,
                        service.port,
                        service.protocol,
                        service.state,
                        service.name,
                        service.version,
                        None if service.tls is None else int(service.tls),
                        json.dumps(service.certificate)
                        if service.certificate is not None
                        else None,
                    ),
                )

            for finding in result.findings:
                connection.execute(
                    """
                    INSERT INTO findings
                        (scan_id, target_address, severity, title, what, why,
                         evidence, impact, recommendation, confidence,
                         cve_id, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding.target_address,
                        finding.severity,
                        finding.title,
                        finding.what,
                        finding.why,
                        finding.evidence,
                        finding.impact,
                        finding.recommendation,
                        finding.confidence,
                        finding.cve_id,
                        finding.source,
                    ),
                )

        return scan_id

    def latest_scan_id(self) -> str | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT id FROM scans ORDER BY started_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
        return None if row is None else str(row["id"])

    def load_scan(self, scan_id: str) -> ScanResult | None:
        with self._connection() as connection:
            scan = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            if scan is None:
                return None

            targets = connection.execute(
                "SELECT address FROM scan_targets WHERE scan_id = ? ORDER BY address",
                (scan_id,),
            ).fetchall()
            services = connection.execute(
                """
                SELECT * FROM services
                WHERE scan_id = ?
                ORDER BY address, port, protocol
                """,
                (scan_id,),
            ).fetchall()
            findings = connection.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()

        return ScanResult(
            scan_id=scan_id,
            targets=[str(row["address"]) for row in targets],
            ports=json.loads(scan["ports_json"]),
            started_at=str(scan["started_at"]),
            duration_seconds=float(scan["duration_seconds"]),
            status=str(scan["status"]),
            services=[
                Service(
                    address=str(row["address"]),
                    port=int(row["port"]),
                    protocol=str(row["protocol"]),
                    state=str(row["state"]),
                    name=str(row["name"]),
                    version=row["version"],
                    tls=None if row["tls"] is None else bool(row["tls"]),
                    certificate=(
                        json.loads(row["certificate_json"])
                        if row["certificate_json"]
                        else None
                    ),
                )
                for row in services
            ],
            findings=[
                Finding(
                    target_address=row["target_address"],
                    severity=str(row["severity"]),  # type: ignore[arg-type]
                    title=str(row["title"]),
                    what=str(row["what"]),
                    why=str(row["why"]),
                    evidence=str(row["evidence"]),
                    impact=str(row["impact"]),
                    recommendation=str(row["recommendation"]),
                    confidence=float(row["confidence"]),
                    cve_id=row["cve_id"],
                    source=row["source"],
                )
                for row in findings
            ],
        )

    def record_action(
        self,
        *,
        plugin_name: str,
        target: str,
        action: str,
        expected_impact: str,
        status: str,
        details: dict[str, object] | None = None,
        scan_id: str | None = None,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO actions
                    (id, scan_id, at, plugin_name, target, action,
                     expected_impact, status, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex,
                    scan_id,
                    datetime.now(timezone.utc).isoformat(),
                    plugin_name,
                    target,
                    action,
                    expected_impact,
                    status,
                    json.dumps(details or {}, ensure_ascii=False),
                ),
            )

    def list_actions(self, scan_id: str | None = None) -> list[dict[str, object]]:
        with self._connection() as connection:
            if scan_id is None:
                rows = connection.execute(
                    "SELECT * FROM actions ORDER BY at"
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM actions WHERE scan_id = ? ORDER BY at",
                    (scan_id,),
                ).fetchall()

        output: list[dict[str, object]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            output.append(item)
        return output

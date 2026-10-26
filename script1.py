#!/usr/bin/env python3
"""Backend SOC multi-client avec collecte Wazuh et analyse Ollama locale."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import ssl
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Generator
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen


LOG = logging.getLogger("soc-backend")
MAX_REQUEST_BYTES = 1_000_000
DEFAULT_DB_PATH = "soc.db"
LOW_ALERT_GROUP_WINDOW = timedelta(hours=6)
HIGH_ALERT_GROUP_WINDOW = timedelta(minutes=30)
LOW_ALERT_PUBLISH_THRESHOLD = 40
HIGH_ALERT_LEVEL = 10
AI_QUEUE_POLL_SECONDS = 1
AI_RETRY_DELAY = timedelta(minutes=1)
MAX_AI_ATTEMPTS = 3
WAZUH_DEDUP_RETENTION = timedelta(days=7)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_json_env(name: str, default: Any) -> Any:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} doit contenir du JSON valide: {exc}") from exc


def json_response(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Convertit les champs Wazuh les plus courants en événement SOC stable."""
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    source_ip = data.get("srcip") or data.get("src_ip") or alert.get("srcip")
    dest_ip = data.get("dstip") or data.get("dst_ip") or alert.get("dstip")
    timestamp = alert.get("timestamp") or alert.get("@timestamp") or iso_now()

    return {
        "wazuh_id": str(alert.get("id") or alert.get("_id") or ""),
        "timestamp": str(timestamp),
        "rule_id": str(rule.get("id") or alert.get("rule_id") or "unknown"),
        "rule_level": max(0, min(15, safe_int(rule.get("level", alert.get("level")), 0))),
        "description": str(rule.get("description") or alert.get("description") or "Aucune description"),
        "agent_id": str(agent.get("id") or alert.get("agent_id") or ""),
        "agent_name": str(agent.get("name") or alert.get("agent_name") or "inconnu"),
        "source_ip": str(source_ip or ""),
        "dest_ip": str(dest_ip or ""),
        "location": str(alert.get("location") or ""),
        "raw": alert,
    }


def risk_score(rule_level: int, occurrences: int, rule_id: str) -> int:
    """Score déterministe sur 100, combinant sévérité et répétition."""
    repeat_bonus = min(25, max(0, occurrences - 1) * 5)
    critical_rule_bonus = 10 if rule_id in {"5710", "5720", "1002"} else 0
    return min(100, max(0, rule_level * 6 + repeat_bonus + critical_rule_bonus))


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


class SocBackend:
    def __init__(
        self,
        database_path: str,
        tenants: dict[str, str],
        notification_webhooks: dict[str, str],
        ollama_url: str,
        ollama_model: str,
        iris_base_url: str = "",
        iris_api_key: str = "",
        iris_case_id: int | None = None,
    ) -> None:
        if not tenants or any(not token or not tenant for token, tenant in tenants.items()):
            raise RuntimeError("Configurez SOC_TENANTS_JSON avec des jetons et identifiants clients.")
        self.database_path = database_path
        self.tenants = tenants
        self.notification_webhooks = notification_webhooks
        self.ollama_url = ollama_url.rstrip("/")
        self.ollama_model = ollama_model
        iris_configured = (iris_base_url, iris_api_key, iris_case_id)
        if any(iris_configured) and not all(iris_configured):
            raise RuntimeError(
                "Configurez ensemble IRIS_BASE_URL, IRIS_API_KEY et IRIS_CASE_ID."
            )
        self.iris_base_url = iris_base_url.rstrip("/")
        self.iris_api_key = iris_api_key
        self.iris_case_id = iris_case_id
        if self.iris_api_key:
            iris_url = urlsplit(self.iris_base_url)
            if (
                iris_url.scheme != "https"
                or not iris_url.hostname
                or iris_url.username
                or iris_url.password
                or iris_url.query
                or iris_url.fragment
                or iris_url.path not in {"", "/"}
            ):
                raise RuntimeError(
                    "IRIS_BASE_URL doit être une origine HTTPS sans identifiants ni chemin."
                )
        self._initialize_database()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self.database_path, timeout=10)
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

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    dedup_key TEXT NOT NULL,
                    wazuh_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_level INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    location TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    source_ip_counts_json TEXT NOT NULL DEFAULT '{}',
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    occurrences_6h INTEGER NOT NULL DEFAULT 1,
                    UNIQUE (tenant_id, dedup_key)
                );
                CREATE INDEX IF NOT EXISTS alerts_tenant_last_seen
                    ON alerts (tenant_id, last_seen DESC);
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    feedback TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS incidents_tenant_updated
                    ON incidents (tenant_id, updated_at DESC);
                CREATE TABLE IF NOT EXISTS incident_alerts (
                    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    PRIMARY KEY (incident_id, alert_id)
                );
                CREATE TABLE IF NOT EXISTS incident_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    memory_type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS memory_tenant_created
                    ON incident_memory (tenant_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS incident_ai_jobs (
                    job_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL UNIQUE,
                    due_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    iris_attempts INTEGER NOT NULL DEFAULT 0,
                    analysis TEXT NOT NULL DEFAULT '',
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ai_jobs_due
                    ON incident_ai_jobs (status, due_at);
                CREATE TABLE IF NOT EXISTS wazuh_event_dedup (
                    tenant_id TEXT NOT NULL,
                    wazuh_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, wazuh_id)
                );
                CREATE INDEX IF NOT EXISTS wazuh_event_dedup_created
                    ON wazuh_event_dedup (created_at);
                CREATE TABLE IF NOT EXISTS alert_occurrence_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    source_ip TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS alert_occurrences_window
                    ON alert_occurrence_events (alert_id, created_at);
                CREATE INDEX IF NOT EXISTS alert_occurrences_created
                    ON alert_occurrence_events (created_at);
                """
            )
            alert_columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
            }
            if "source_ip_counts_json" not in alert_columns:
                connection.execute(
                    """ALTER TABLE alerts ADD COLUMN source_ip_counts_json
                       TEXT NOT NULL DEFAULT '{}'"""
                )
            if "occurrences_6h" not in alert_columns:
                connection.execute(
                    """ALTER TABLE alerts ADD COLUMN occurrences_6h
                       INTEGER NOT NULL DEFAULT 1"""
                )
            connection.execute(
                """UPDATE incident_ai_jobs SET status = CASE status
                       WHEN 'processing' THEN 'pending'
                       WHEN 'iris_processing' THEN 'iris_pending'
                       ELSE status END
                   WHERE status IN ('processing', 'iris_processing')"""
            )

    def tenant_for_token(self, token: str) -> str | None:
        token_bytes = token.encode("utf-8")
        for configured_token, tenant_id in self.tenants.items():
            if hmac.compare_digest(token_bytes, configured_token.encode("utf-8")):
                return tenant_id
        return None

    def _dedup_key(self, tenant_id: str, event: dict[str, Any]) -> str:
        try:
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            event_time = utc_now()
        bucket = int(event_time.timestamp() // 600)
        parts = (
            tenant_id,
            event["rule_id"],
            event["agent_id"],
            event["source_ip"],
            event["dest_ip"],
            event["description"],
            str(bucket),
        )
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _source_ip_counts(
        counts_json: str, fallback_ip: str, occurrences: int
    ) -> dict[str, int]:
        try:
            counts = json.loads(counts_json)
        except json.JSONDecodeError:
            counts = {}
        if not isinstance(counts, dict):
            counts = {}
        normalized = {
            str(ip): safe_int(count, 0)
            for ip, count in counts.items()
            if isinstance(ip, str) and safe_int(count, 0) > 0
        }
        if not normalized and fallback_ip:
            normalized[fallback_ip] = occurrences
        return normalized

    @staticmethod
    def _agent_group_clause(event: dict[str, Any]) -> tuple[str, str]:
        if event["agent_id"]:
            return "agent_id = ?", event["agent_id"]
        if event["agent_name"] != "inconnu":
            return "agent_name = ?", event["agent_name"]
        return "", ""

    def _queue_qualified_analysis(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        incident_id: str,
        alert_id: str,
        rule_level: int,
        occurrences: int,
    ) -> None:
        if rule_level < HIGH_ALERT_LEVEL and occurrences < LOW_ALERT_PUBLISH_THRESHOLD:
            return
        now = iso_now()
        connection.execute(
            """INSERT OR IGNORE INTO incident_ai_jobs
               (job_id, tenant_id, incident_id, alert_id, due_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), tenant_id, incident_id, alert_id, now, now),
        )

    def ingest_alert(self, tenant_id: str, raw_alert: dict[str, Any]) -> dict[str, Any]:
        event = normalize_alert(raw_alert)
        now = iso_now()
        dedup_key = self._dedup_key(tenant_id, event)
        with self._connect() as connection:
            if event["wazuh_id"]:
                duplicate = connection.execute(
                    """SELECT a.* FROM wazuh_event_dedup w
                       JOIN alerts a ON a.id = w.alert_id
                       WHERE w.tenant_id = ? AND w.wazuh_id = ?""",
                    (tenant_id, event["wazuh_id"]),
                ).fetchone()
                if duplicate:
                    incident = connection.execute(
                        """SELECT i.* FROM incidents i JOIN incident_alerts ia
                           ON ia.incident_id = i.id WHERE ia.alert_id = ?
                           AND i.tenant_id = ?""",
                        (duplicate["id"], tenant_id),
                    ).fetchone()
                    return {
                        "alert": self._alert_json(duplicate),
                        "incident": self._incident_json(incident) if incident else None,
                        "created": False,
                    }
            occurrence_cutoff = (utc_now() - timedelta(hours=6)).isoformat(timespec="seconds")
            dedup_cutoff = (
                utc_now() - WAZUH_DEDUP_RETENTION
            ).isoformat(timespec="seconds")
            connection.execute(
                "DELETE FROM alert_occurrence_events WHERE created_at < ?",
                (occurrence_cutoff,),
            )
            connection.execute(
                "DELETE FROM wazuh_event_dedup WHERE created_at < ?",
                (dedup_cutoff,),
            )
            agent_clause, agent_value = self._agent_group_clause(event)
            group_window = (
                HIGH_ALERT_GROUP_WINDOW
                if event["rule_level"] >= HIGH_ALERT_LEVEL
                else LOW_ALERT_GROUP_WINDOW
            )
            cutoff = (utc_now() - group_window).isoformat(timespec="seconds")
            existing = None
            if agent_clause:
                existing = connection.execute(
                    f"""SELECT * FROM alerts WHERE tenant_id = ? AND rule_id = ?
                        AND {agent_clause} AND last_seen >= ?
                        ORDER BY last_seen DESC LIMIT 1""",
                    (tenant_id, event["rule_id"], agent_value, cutoff),
                ).fetchone()
            if not existing:
                existing = connection.execute(
                    """SELECT * FROM alerts WHERE tenant_id = ? AND dedup_key = ?
                       AND last_seen >= ?
                       UNION ALL
                       SELECT * FROM alerts WHERE tenant_id = ? AND dedup_key LIKE ?
                       AND last_seen >= ? LIMIT 1""",
                    (
                        tenant_id, dedup_key, cutoff,
                        tenant_id, f"{dedup_key}:%", cutoff,
                    ),
                ).fetchone()
            if existing:
                alert_id = existing["id"]
                connection.execute(
                    """UPDATE alerts SET occurrences = occurrences + 1, last_seen = ?,
                       raw_json = ?,
                       source_ip = CASE WHEN source_ip = '' THEN ? ELSE source_ip END
                       WHERE id = ? AND tenant_id = ?""",
                    (
                        now, json.dumps(raw_alert, ensure_ascii=False),
                        event["source_ip"], alert_id, tenant_id,
                    ),
                )
                linked_incident = connection.execute(
                    """SELECT i.id FROM incidents i
                       JOIN incident_alerts ia ON ia.incident_id = i.id
                       WHERE ia.alert_id = ? AND i.tenant_id = ?""",
                    (alert_id, tenant_id),
                ).fetchone()
                if linked_incident:
                    counts = connection.execute(
                        """SELECT COALESCE(SUM(a.occurrences), 0) AS total,
                                  MAX(a.rule_level) AS level
                           FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id
                           WHERE ia.incident_id = ?""",
                        (linked_incident["id"],),
                    ).fetchone()
                    score = risk_score(counts["level"] or 0, counts["total"], event["rule_id"])
                    connection.execute(
                        """UPDATE incidents SET score = ?, severity = ?, updated_at = ?
                           WHERE id = ? AND tenant_id = ?""",
                        (
                            score, severity_for(score), now,
                            linked_incident["id"], tenant_id,
                        ),
                    )
            else:
                alert_id = str(uuid.uuid4())
                stored_dedup_key = dedup_key
                if connection.execute(
                    "SELECT 1 FROM alerts WHERE tenant_id = ? AND dedup_key = ?",
                    (tenant_id, dedup_key),
                ).fetchone():
                    stored_dedup_key = f"{dedup_key}:{alert_id}"
                connection.execute(
                    """INSERT INTO alerts
                       (id, tenant_id, dedup_key, wazuh_id, timestamp, rule_id, rule_level,
                        description, agent_id, agent_name, source_ip, dest_ip, location,
                        raw_json, source_ip_counts_json, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert_id, tenant_id, stored_dedup_key,
                        event["wazuh_id"], event["timestamp"],
                        event["rule_id"], event["rule_level"], event["description"],
                        event["agent_id"], event["agent_name"], event["source_ip"],
                        event["dest_ip"], event["location"],
                        json.dumps(raw_alert, ensure_ascii=False),
                        json.dumps({event["source_ip"]: 1} if event["source_ip"] else {}),
                        now, now,
                    ),
                )
                self._correlate_alert(connection, tenant_id, alert_id, event, 1)

            connection.execute(
                """INSERT INTO alert_occurrence_events (alert_id, source_ip, created_at)
                   VALUES (?, ?, ?)""",
                (alert_id, event["source_ip"], now),
            )
            connection.execute(
                """DELETE FROM alert_occurrence_events
                   WHERE alert_id = ? AND created_at < ?""",
                (alert_id, occurrence_cutoff),
            )
            window_ip_rows = connection.execute(
                """SELECT source_ip, COUNT(*) AS count FROM alert_occurrence_events
                   WHERE alert_id = ? AND created_at >= ? AND source_ip != ''
                   GROUP BY source_ip""",
                (alert_id, occurrence_cutoff),
            ).fetchall()
            occurrences_6h = connection.execute(
                """SELECT COUNT(*) AS count FROM alert_occurrence_events
                   WHERE alert_id = ? AND created_at >= ?""",
                (alert_id, occurrence_cutoff),
            ).fetchone()["count"]
            source_ip_counts = {row["source_ip"]: row["count"] for row in window_ip_rows}
            connection.execute(
                """UPDATE alerts SET occurrences_6h = ?, source_ip_counts_json = ?
                   WHERE id = ? AND tenant_id = ?""",
                (
                    occurrences_6h, json.dumps(source_ip_counts, ensure_ascii=False),
                    alert_id, tenant_id,
                ),
            )
            alert_row = connection.execute(
                "SELECT * FROM alerts WHERE id = ? AND tenant_id = ?", (alert_id, tenant_id)
            ).fetchone()
            incident_row = connection.execute(
                """SELECT i.* FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id
                   WHERE ia.alert_id = ? AND i.tenant_id = ?""",
                (alert_id, tenant_id),
            ).fetchone()
            if incident_row:
                self._queue_qualified_analysis(
                    connection, tenant_id, incident_row["id"], alert_id,
                    event["rule_level"], alert_row["occurrences_6h"],
                )
            if event["wazuh_id"]:
                connection.execute(
                    """INSERT OR IGNORE INTO wazuh_event_dedup
                       (tenant_id, wazuh_id, alert_id, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (tenant_id, event["wazuh_id"], alert_id, now),
                )
            return {
                "alert": self._alert_json(alert_row),
                "incident": self._incident_json(incident_row) if incident_row else None,
                "created": existing is None,
            }

    def _correlate_alert(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        alert_id: str,
        event: dict[str, Any],
        occurrences: int,
    ) -> None:
        cutoff = (utc_now() - timedelta(minutes=30)).isoformat(timespec="seconds")
        related = connection.execute(
            """SELECT DISTINCT i.* FROM incidents i
               JOIN incident_alerts ia ON ia.incident_id = i.id
               JOIN alerts a ON a.id = ia.alert_id
               WHERE i.tenant_id = ? AND i.status != 'resolved' AND i.updated_at >= ?
               AND ((? != '' AND a.agent_id = ?) OR (? != '' AND a.source_ip = ?))
               ORDER BY i.updated_at DESC LIMIT 1""",
            (
                tenant_id, cutoff, event["agent_id"], event["agent_id"],
                event["source_ip"], event["source_ip"],
            ),
        ).fetchone()
        score = risk_score(event["rule_level"], occurrences, event["rule_id"])
        now = iso_now()

        if related:
            incident_id = related["id"]
            connection.execute(
                "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                (incident_id, alert_id),
            )
            counts = connection.execute(
                """SELECT COALESCE(SUM(a.occurrences), 0) AS total, MAX(a.rule_level) AS level
                   FROM incident_alerts ia JOIN alerts a ON a.id = ia.alert_id
                   WHERE ia.incident_id = ?""",
                (incident_id,),
            ).fetchone()
            score = risk_score(counts["level"] or 0, counts["total"], event["rule_id"])
            connection.execute(
                """UPDATE incidents SET score = ?, severity = ?, updated_at = ?
                   WHERE id = ? AND tenant_id = ?""",
                (score, severity_for(score), now, incident_id, tenant_id),
            )
            connection.execute(
                """INSERT INTO incident_memory
                   (tenant_id, incident_id, memory_type, content, created_at)
                   VALUES (?, ?, 'correlation', ?, ?)""",
                (tenant_id, incident_id, f"Alerte liée par agent/IP: {event['agent_name']}", now),
            )
            return

        incident_id = str(uuid.uuid4())
        title = f"{event['description'][:140]} ({event['agent_name']})"
        connection.execute(
            """INSERT INTO incidents
               (id, tenant_id, title, description, status, score, severity, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)""",
            (
                incident_id, tenant_id, title, event["description"], score,
                severity_for(score), now, now,
            ),
        )
        connection.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
            (incident_id, alert_id),
        )
        connection.execute(
            """INSERT INTO incident_memory
               (tenant_id, incident_id, memory_type, content, created_at)
               VALUES (?, ?, 'created', ?, ?)""",
            (tenant_id, incident_id, "Incident créé depuis une alerte Wazuh", now),
        )
        connection.execute(
            """INSERT INTO incident_memory
               (tenant_id, incident_id, memory_type, content, created_at)
               VALUES (?, ?, 'score', ?, ?)""",
            (tenant_id, incident_id, f"Score initial: {score}/100", now),
        )
        connection.execute(
            """INSERT INTO incident_memory
               (tenant_id, incident_id, memory_type, content, created_at)
               VALUES (?, ?, 'notification', ?, ?)""",
            (tenant_id, incident_id, "Notification d'incident à envoyer", now),
        )
        threading.Thread(
            target=self._notify_incident,
            args=(tenant_id, incident_id, title, score),
            daemon=True,
        ).start()

    @staticmethod
    def _alert_json(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        counts = SocBackend._source_ip_counts(
            value.pop("source_ip_counts_json", "{}"),
            value["source_ip"],
            value["occurrences"],
        )
        value["source_ip_counts"] = counts
        value["source_ips"] = sorted(counts)
        value["raw"] = json.loads(value.pop("raw_json"))
        return value

    @staticmethod
    def _incident_json(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def list_alerts(self, tenant_id: str, limit: int, since: str | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        query = "SELECT * FROM alerts WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            return [self._alert_json(row) for row in connection.execute(query, params)]

    def list_incidents(
        self, tenant_id: str, status: str | None, limit: int
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 200))
        query = "SELECT * FROM incidents WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            return [self._incident_json(row) for row in connection.execute(query, params)]

    def incident_detail(self, tenant_id: str, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE id = ? AND tenant_id = ?",
                (incident_id, tenant_id),
            ).fetchone()
            if not incident:
                return None
            alerts = connection.execute(
                """SELECT a.id, a.wazuh_id, a.timestamp, a.rule_id, a.rule_level, a.description,
                          a.agent_id, a.agent_name, a.source_ip, a.source_ip_counts_json,
                          a.dest_ip, a.occurrences, a.occurrences_6h
                   FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id
                   WHERE ia.incident_id = ? AND a.tenant_id = ?
                   ORDER BY a.last_seen DESC""",
                (incident_id, tenant_id),
            ).fetchall()
            alert_items = []
            for row in alerts:
                item = dict(row)
                counts = self._source_ip_counts(
                    item.pop("source_ip_counts_json"), item["source_ip"], item["occurrences"]
                )
                item["source_ip_counts"] = counts
                item["source_ips"] = sorted(counts)
                alert_items.append(item)
            history = connection.execute(
                """SELECT memory_type, content, created_at FROM incident_memory
                   WHERE incident_id = ? AND tenant_id = ? ORDER BY created_at DESC""",
                (incident_id, tenant_id),
            ).fetchall()
            return {
                "incident": self._incident_json(incident),
                "alerts": alert_items,
                "history": [dict(row) for row in history],
            }

    def dashboard(self, tenant_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            summary = connection.execute(
                """SELECT COUNT(*) AS total,
                   COALESCE(SUM(CASE WHEN status != 'resolved' THEN 1 ELSE 0 END), 0) AS open,
                   COALESCE(SUM(CASE WHEN severity IN ('critical', 'high') AND status != 'resolved'
                       THEN 1 ELSE 0 END), 0) AS priority
                   FROM incidents WHERE tenant_id = ?""",
                (tenant_id,),
            ).fetchone()
            severities = connection.execute(
                """SELECT severity, COUNT(*) AS count FROM incidents
                   WHERE tenant_id = ? AND status != 'resolved' GROUP BY severity""",
                (tenant_id,),
            ).fetchall()
            return {
                "tenant_id": tenant_id,
                "incidents": dict(summary),
                "by_severity": {row["severity"]: row["count"] for row in severities},
            }

    def update_incident(
        self, tenant_id: str, incident_id: str, status: str | None, feedback: str | None
    ) -> dict[str, Any] | None:
        if status is not None and status not in {"open", "investigating", "resolved", "false_positive"}:
            raise ValueError("Statut invalide.")
        with self._connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE id = ? AND tenant_id = ?",
                (incident_id, tenant_id),
            ).fetchone()
            if not incident:
                return None
            next_status = status or incident["status"]
            next_feedback = feedback if feedback is not None else incident["feedback"]
            connection.execute(
                """UPDATE incidents SET status = ?, feedback = ?, updated_at = ?
                   WHERE id = ? AND tenant_id = ?""",
                (next_status, next_feedback, iso_now(), incident_id, tenant_id),
            )
            if feedback is not None:
                connection.execute(
                    """INSERT INTO incident_memory
                       (tenant_id, incident_id, memory_type, content, created_at)
                       VALUES (?, ?, 'feedback', ?, ?)""",
                    (tenant_id, incident_id, feedback, iso_now()),
                )
            updated = connection.execute(
                "SELECT * FROM incidents WHERE id = ? AND tenant_id = ?",
                (incident_id, tenant_id),
            ).fetchone()
            return self._incident_json(updated)

    def analyze_incident(self, tenant_id: str, incident_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE id = ? AND tenant_id = ?",
                (incident_id, tenant_id),
            ).fetchone()
            if not incident:
                return None
            alerts = connection.execute(
                """SELECT a.rule_id, a.rule_level, a.description, a.agent_name,
                          a.source_ip, a.source_ip_counts_json, a.dest_ip,
                          a.occurrences, a.occurrences_6h, a.timestamp
                   FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id
                   WHERE ia.incident_id = ? AND a.tenant_id = ?""",
                (incident_id, tenant_id),
            ).fetchall()
            alert_items = []
            for row in alerts:
                item = dict(row)
                counts = self._source_ip_counts(
                    item.pop("source_ip_counts_json"), item["source_ip"], item["occurrences"]
                )
                item["source_ip_counts"] = counts
                item["source_ips"] = sorted(counts)
                alert_items.append(item)
            memories = connection.execute(
                """SELECT memory_type, content, created_at FROM incident_memory
                   WHERE incident_id = ? AND tenant_id = ? ORDER BY created_at DESC LIMIT 20""",
                (incident_id, tenant_id),
            ).fetchall()

        prompt = {
            "instruction": (
                "Analyse ces données SOC défensives. Réponds en français avec: résumé, "
                "hypothèses à vérifier, actions de triage et recommandations. Distingue "
                "les faits des hypothèses; n'exécute aucune action. Pour les alertes "
                "agrégées, tiens compte des occurrences et des IP sources distinctes."
            ),
            "incident": dict(incident),
            "alerts": alert_items,
            "history_and_feedback": [dict(row) for row in memories],
        }
        body = json_response(
            {
                "model": self.ollama_model,
                "prompt": json.dumps(prompt, ensure_ascii=False),
                "stream": False,
            }
        )
        request = Request(
            f"{self.ollama_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=120) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Échec de l'analyse Ollama: {exc}") from exc
        answer = result.get("response")
        if not isinstance(answer, str) or not answer.strip():
            raise RuntimeError("Ollama a renvoyé une réponse vide ou invalide.")
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO incident_memory
                   (tenant_id, incident_id, memory_type, content, created_at)
                   VALUES (?, ?, 'ai_analysis', ?, ?)""",
                (tenant_id, incident_id, answer.strip(), iso_now()),
            )
        return {"incident_id": incident_id, "model": self.ollama_model, "analysis": answer}

    def process_ai_queue(self) -> None:
        now = iso_now()
        ai_jobs: list[tuple[str, str, str]] = []
        iris_jobs: list[tuple[str, str, str, str]] = []
        with self._connect() as connection:
            pending = connection.execute(
                """SELECT * FROM incident_ai_jobs
                   WHERE status IN ('pending', 'iris_pending') AND due_at <= ?
                   ORDER BY due_at LIMIT 20""",
                (now,),
            ).fetchall()
            for item in pending:
                if item["status"] == "pending":
                    claimed = connection.execute(
                        """UPDATE incident_ai_jobs SET status = 'processing'
                           WHERE job_id = ? AND status = 'pending'""",
                        (item["job_id"],),
                    )
                    if claimed.rowcount != 1:
                        continue
                    connection.execute(
                        """INSERT INTO incident_memory
                           (tenant_id, incident_id, memory_type, content, created_at)
                           VALUES (?, ?, 'ai_analysis_requested', ?, ?)""",
                        (
                            item["tenant_id"], item["incident_id"],
                            "Analyse automatique après seuil de pertinence atteint",
                            now,
                        ),
                    )
                    ai_jobs.append(
                        (item["job_id"], item["tenant_id"], item["incident_id"])
                    )
                else:
                    claimed = connection.execute(
                        """UPDATE incident_ai_jobs SET status = 'iris_processing'
                           WHERE job_id = ? AND status = 'iris_pending'""",
                        (item["job_id"],),
                    )
                    if claimed.rowcount != 1:
                        continue
                    iris_jobs.append(
                        (
                            item["job_id"], item["tenant_id"], item["incident_id"],
                            item["analysis"],
                        )
                    )
        for job_id, tenant_id, incident_id in ai_jobs:
            threading.Thread(
                target=self._run_queued_analysis,
                args=(job_id, tenant_id, incident_id),
                daemon=True,
            ).start()
        for job_id, tenant_id, incident_id, analysis in iris_jobs:
            threading.Thread(
                target=self._run_queued_iris_publish,
                args=(job_id, tenant_id, incident_id, analysis),
                daemon=True,
            ).start()

    def _run_queued_analysis(
        self, job_id: str, tenant_id: str, incident_id: str
    ) -> None:
        try:
            result = self.analyze_incident(tenant_id, incident_id)
            if result is None:
                raise RuntimeError("Incident introuvable au moment de l'analyse automatique.")
        except (RuntimeError, sqlite3.Error) as exc:
            LOG.error("Analyse automatique en échec pour l'incident %s: %s", incident_id, exc)
            with self._connect() as connection:
                item = connection.execute(
                    "SELECT attempts FROM incident_ai_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                if item:
                    attempts = item["attempts"] + 1
                    status = "failed" if attempts >= MAX_AI_ATTEMPTS else "pending"
                    retry_at = (utc_now() + AI_RETRY_DELAY).isoformat(timespec="seconds")
                    connection.execute(
                        """UPDATE incident_ai_jobs SET attempts = ?, status = ?,
                           due_at = ?, last_error = ? WHERE job_id = ?""",
                        (
                            attempts, status, retry_at, str(exc), job_id,
                        ),
                    )
            return
        analysis = result["analysis"]
        with self._connect() as connection:
            connection.execute(
                """UPDATE incident_ai_jobs SET status = ?, analysis = ?, due_at = ?,
                   last_error = '' WHERE job_id = ?""",
                (
                    "iris_processing" if self.iris_api_key else "completed",
                    analysis, iso_now(), job_id,
                ),
            )
        if self.iris_api_key:
            self._run_queued_iris_publish(job_id, tenant_id, incident_id, analysis)

    def _publish_iris_event(
        self, job_id: str, tenant_id: str, incident_id: str, analysis: str
    ) -> None:
        if not self.iris_base_url or not self.iris_api_key or self.iris_case_id is None:
            raise RuntimeError("La publication IRIS est activée sans configuration complète.")
        detail = self.incident_detail(tenant_id, incident_id)
        if detail is None:
            raise RuntimeError("Incident introuvable lors de la publication vers IRIS.")
        payload = {
            "event_title": f"Analyse SOC: {detail['incident']['title'][:200]}",
            "event_in_graph": True,
            "event_in_summary": True,
            "event_content": analysis,
            "event_raw": json.dumps(
                {
                    "soc_job_id": job_id,
                    "incident": detail["incident"],
                    "alerts": detail["alerts"],
                    "analysis": analysis,
                },
                ensure_ascii=False,
                indent=2,
            ),
            "event_source": "SOC Backend / Ollama",
            "event_assets": [],
            "event_iocs": [],
            "event_category_id": "1",
            "event_color": "",
            "event_date": utc_now().strftime("%Y-%m-%dT%H:%M:%S.%f"),
            "event_tags": "SOC,Wazuh,Ollama",
            "event_tz": "+00:00",
            "custom_attributes": {},
            "event_sync_iocs_assets": False,
            "cid": self.iris_case_id,
        }
        request = Request(
            f"{self.iris_base_url}/case/timeline/events/add",
            data=json_response(payload),
            headers={
                "Authorization": f"Bearer {self.iris_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (
            HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError
        ) as exc:
            raise RuntimeError(f"Échec de publication dans IRIS DFIR: {exc}") from exc
        if (
            not isinstance(result, dict)
            or result.get("success") is False
            or str(result.get("status", "")).lower() in {"error", "failed", "failure"}
        ):
            raise RuntimeError("IRIS DFIR a renvoyé une réponse invalide.")

    def _run_queued_iris_publish(
        self, job_id: str, tenant_id: str, incident_id: str, analysis: str
    ) -> None:
        try:
            self._publish_iris_event(job_id, tenant_id, incident_id, analysis)
        except (RuntimeError, sqlite3.Error) as exc:
            LOG.error("Publication IRIS échouée pour l'incident %s: %s", incident_id, exc)
            with self._connect() as connection:
                item = connection.execute(
                    "SELECT iris_attempts FROM incident_ai_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                if item:
                    attempts = item["iris_attempts"] + 1
                    status = "failed" if attempts >= MAX_AI_ATTEMPTS else "iris_pending"
                    retry_at = (utc_now() + AI_RETRY_DELAY).isoformat(timespec="seconds")
                    connection.execute(
                        """UPDATE incident_ai_jobs SET iris_attempts = ?, status = ?,
                           due_at = ?, last_error = ? WHERE job_id = ?""",
                        (attempts, status, retry_at, str(exc), job_id),
                    )
            return
        with self._connect() as connection:
            connection.execute(
                """UPDATE incident_ai_jobs SET status = 'completed', last_error = ''
                   WHERE job_id = ?""",
                (job_id,),
            )
            connection.execute(
                """INSERT INTO incident_memory
                   (tenant_id, incident_id, memory_type, content, created_at)
                   VALUES (?, ?, 'iris_published', ?, ?)""",
                (
                    tenant_id, incident_id,
                    f"Analyse Ollama publiée dans le cas IRIS {self.iris_case_id}",
                    iso_now(),
                ),
            )

    def run_ai_queue_forever(self) -> None:
        while True:
            try:
                self.process_ai_queue()
            except sqlite3.Error:
                LOG.exception("Erreur lors du traitement de la file d'analyses IA")
            time.sleep(AI_QUEUE_POLL_SECONDS)

    def _notify_incident(self, tenant_id: str, incident_id: str, title: str, score: int) -> None:
        webhook = self.notification_webhooks.get(tenant_id)
        if not webhook:
            return
        request = Request(
            webhook,
            data=json_response(
                {
                    "tenant_id": tenant_id,
                    "incident_id": incident_id,
                    "title": title,
                    "score": score,
                    "severity": severity_for(score),
                }
            ),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                if response.status >= 300:
                    raise RuntimeError(f"Webhook HTTP {response.status}")
        except (HTTPError, URLError, TimeoutError, RuntimeError) as exc:
            LOG.error("Notification en échec pour le client %s: %s", tenant_id, exc)
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO incident_memory
                       (tenant_id, incident_id, memory_type, content, created_at)
                       VALUES (?, ?, 'notification_error', ?, ?)""",
                    (tenant_id, incident_id, str(exc), iso_now()),
                )


class WazuhCollector:
    def __init__(self, backend: SocBackend, sources: list[dict[str, Any]], interval: int) -> None:
        self.backend = backend
        self.sources = sources
        self.interval = max(15, interval)

    def run_forever(self) -> None:
        while True:
            for source in self.sources:
                try:
                    self.collect(source)
                except (HTTPError, URLError, TimeoutError, ValueError, KeyError, RuntimeError) as exc:
                    LOG.error("Collecte Wazuh en échec (client %s): %s", source.get("tenant_id"), exc)
            time.sleep(self.interval)

    @staticmethod
    def _ssl_context(verify_tls: bool) -> ssl.SSLContext | None:
        return None if verify_tls else ssl._create_unverified_context()

    def collect(self, source: dict[str, Any]) -> int:
        tenant_id = str(source["tenant_id"])
        if tenant_id not in self.backend.tenants.values():
            raise ValueError(f"Client Wazuh non déclaré dans SOC_TENANTS_JSON: {tenant_id}")
        base_url = str(source["url"]).rstrip("/")
        verify_tls = bool(source.get("verify_tls", True))
        context = self._ssl_context(verify_tls)
        index_pattern = str(source.get("alerts_index", "wazuh-alerts-*"))
        if not re.fullmatch(r"[A-Za-z0-9*._-]+", index_pattern):
            raise ValueError("alerts_index contient des caractères non autorisés.")
        credentials = base64.b64encode(
            f"{source['username']}:{source['password']}".encode("utf-8")
        ).decode("ascii")
        query = {
            "size": max(1, min(safe_int(source.get("batch_size"), 100), 1000)),
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "range": {
                    "timestamp": {"gte": f"now-{max(self.interval + 60, 120)}s"}
                }
            },
        }
        alerts_request = Request(
            f"{base_url}/{index_pattern}/_search",
            data=json_response(query),
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(alerts_request, timeout=30, context=context) as response:
            result = json.loads(response.read().decode("utf-8"))
        hits = result.get("hits") if isinstance(result, dict) else None
        records = hits.get("hits") if isinstance(hits, dict) else None
        if not isinstance(records, list):
            raise ValueError("Réponse Wazuh Indexer inattendue: les résultats hits sont absents.")
        alerts = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Réponse Wazuh Indexer invalide: un résultat n'est pas un objet.")
            alert = record.get("_source", {})
            if not isinstance(alert, dict):
                raise ValueError("Réponse Wazuh Indexer invalide: un document n'a pas _source.")
            alert.setdefault("id", record.get("_id", ""))
            alerts.append(alert)
        for alert in alerts:
            if isinstance(alert, dict):
                self.backend.ingest_alert(tenant_id, alert)
        LOG.info("%s alerte(s) Wazuh indexer importée(s) pour %s", len(alerts), tenant_id)
        return len(alerts)


def create_handler(backend: SocBackend) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SocBackend/1.0"

        def log_message(self, format_string: str, *args: Any) -> None:
            LOG.info("%s - %s", self.address_string(), format_string % args)

        def _send(self, status: int, payload: Any) -> None:
            body = json_response(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("Content-Length invalide.") from exc
            if length < 0 or length > MAX_REQUEST_BYTES:
                raise ValueError("Corps de requête trop volumineux.")
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("Le corps doit être un JSON UTF-8 valide.") from exc
            if not isinstance(payload, dict):
                raise ValueError("Le corps JSON doit être un objet.")
            return payload

        def _authenticated_tenant(self) -> str | None:
            authorization = self.headers.get("Authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token:
                return None
            return backend.tenant_for_token(token.strip())

        def do_GET(self) -> None:
            path = urlsplit(self.path)
            if path.path == "/health":
                self._send(200, {"status": "ok"})
                return
            tenant_id = self._authenticated_tenant()
            if tenant_id is None:
                self._send(401, {"error": "Authentification Bearer requise."})
                return
            params = parse_qs(path.query)
            try:
                if path.path == "/api/dashboard":
                    self._send(200, backend.dashboard(tenant_id))
                elif path.path == "/api/alerts":
                    self._send(
                        200,
                        {
                            "items": backend.list_alerts(
                                tenant_id,
                                safe_int(params.get("limit", ["100"])[0], 100),
                                params.get("since", [None])[0],
                            )
                        },
                    )
                elif path.path == "/api/incidents":
                    status = params.get("status", [None])[0]
                    if status and status not in {
                        "open", "investigating", "resolved", "false_positive"
                    }:
                        self._send(400, {"error": "Filtre de statut invalide."})
                        return
                    self._send(
                        200,
                        {
                            "items": backend.list_incidents(
                                tenant_id, status, safe_int(params.get("limit", ["100"])[0], 100)
                            )
                        },
                    )
                elif re.fullmatch(r"/api/incidents/[0-9a-fA-F-]+", path.path):
                    incident_id = path.path.rsplit("/", 1)[-1]
                    result = backend.incident_detail(tenant_id, incident_id)
                    self._send(200, result) if result else self._send(404, {"error": "Incident introuvable."})
                else:
                    self._send(404, {"error": "Route introuvable."})
            except (sqlite3.Error, ValueError) as exc:
                LOG.exception("Erreur de lecture API")
                self._send(500, {"error": str(exc)})

        def do_POST(self) -> None:
            tenant_id = self._authenticated_tenant()
            if tenant_id is None:
                self._send(401, {"error": "Authentification Bearer requise."})
                return
            try:
                payload = self._read_json()
                if self.path == "/api/alerts":
                    alert = payload.get("alert", payload)
                    if not isinstance(alert, dict):
                        self._send(400, {"error": "'alert' doit être un objet."})
                        return
                    result = backend.ingest_alert(tenant_id, alert)
                    self._send(201 if result["created"] else 200, result)
                    return
                match = re.fullmatch(r"/api/incidents/([0-9a-fA-F-]+)/analyze", self.path)
                if match:
                    result = backend.analyze_incident(tenant_id, match.group(1))
                    self._send(200, result) if result else self._send(404, {"error": "Incident introuvable."})
                    return
                self._send(404, {"error": "Route introuvable."})
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
            except (sqlite3.Error, RuntimeError) as exc:
                LOG.exception("Erreur lors du traitement POST")
                self._send(502 if isinstance(exc, RuntimeError) else 500, {"error": str(exc)})

        def do_PATCH(self) -> None:
            tenant_id = self._authenticated_tenant()
            if tenant_id is None:
                self._send(401, {"error": "Authentification Bearer requise."})
                return
            match = re.fullmatch(r"/api/incidents/([0-9a-fA-F-]+)", self.path)
            if not match:
                self._send(404, {"error": "Route introuvable."})
                return
            try:
                payload = self._read_json()
                status = payload.get("status")
                feedback = payload.get("feedback")
                if status is not None and not isinstance(status, str):
                    raise ValueError("'status' doit être une chaîne.")
                if feedback is not None and not isinstance(feedback, str):
                    raise ValueError("'feedback' doit être une chaîne.")
                result = backend.update_incident(tenant_id, match.group(1), status, feedback)
                self._send(200, result) if result else self._send(404, {"error": "Incident introuvable."})
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
            except sqlite3.Error as exc:
                LOG.exception("Erreur lors de la mise à jour d'incident")
                self._send(500, {"error": str(exc)})

    return Handler


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    tenants = parse_json_env("SOC_TENANTS_JSON", {})
    webhooks = parse_json_env("SOC_WEBHOOKS_JSON", {})
    sources = parse_json_env("WAZUH_SOURCES_JSON", [])
    if not isinstance(tenants, dict) or not isinstance(webhooks, dict) or not isinstance(sources, list):
        raise RuntimeError("SOC_TENANTS_JSON/SOC_WEBHOOKS_JSON doivent être des objets et WAZUH_SOURCES_JSON une liste.")
    for source in sources:
        if not isinstance(source, dict) or not {"tenant_id", "url", "username", "password"} <= source.keys():
            raise RuntimeError(
                "Chaque source Wazuh doit déclarer tenant_id, url, username et password."
            )
    iris_case_id_raw = os.environ.get("IRIS_CASE_ID", "").strip()
    iris_case_id = safe_int(iris_case_id_raw, -1) if iris_case_id_raw else None
    if iris_case_id is not None and iris_case_id <= 0:
        raise RuntimeError("IRIS_CASE_ID doit être un entier positif.")
    backend = SocBackend(
        database_path=os.environ.get("SOC_DB_PATH", DEFAULT_DB_PATH),
        tenants={str(token): str(tenant) for token, tenant in tenants.items()},
        notification_webhooks={str(tenant): str(url) for tenant, url in webhooks.items()},
        ollama_url=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
        ollama_model=os.environ.get("OLLAMA_MODEL", "llama3.1"),
        iris_base_url=os.environ.get("IRIS_BASE_URL", "").strip(),
        iris_api_key=os.environ.get("IRIS_API_KEY", "").strip(),
        iris_case_id=iris_case_id,
    )
    threading.Thread(target=backend.run_ai_queue_forever, daemon=True).start()

    if sources:
        collector = WazuhCollector(
            backend,
            sources,
            safe_int(os.environ.get("WAZUH_POLL_SECONDS"), 60),
        )
        threading.Thread(target=collector.run_forever, daemon=True).start()

    host = os.environ.get("SOC_HOST", "127.0.0.1")
    port = safe_int(os.environ.get("SOC_PORT"), 8080)
    server = ThreadingHTTPServer((host, port), create_handler(backend))
    LOG.info("Backend SOC démarré sur http://%s:%s", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Arrêt demandé.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
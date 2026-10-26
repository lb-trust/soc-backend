import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from script1 import SocBackend


class AlertGroupingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temp_dir.name) / "soc.db")
        self.backend = SocBackend(
            self.database_path,
            {"test-token": "client-test"},
            {},
            "http://127.0.0.1:11434",
            "llama3.1",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def alert(
        source_ip: str, agent_id: str = "001", rule_id: str = "1011", level: int = 5
    ) -> dict[str, object]:
        return {
            "timestamp": datetime.now().astimezone().isoformat(),
            "rule": {"id": rule_id, "level": level, "description": "Test alert"},
            "agent": {"id": agent_id, "name": "test-host"},
            "data": {"srcip": source_ip},
        }

    def queued_item(self, incident_id: str) -> dict[str, object]:
        with self.backend._connect() as connection:
            row = connection.execute(
                "SELECT * FROM incident_ai_queue WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            return dict(row)

    def test_same_rule_agent_aggregates_source_ips(self) -> None:
        first = self.backend.ingest_alert("client-test", self.alert("192.0.2.1"))
        second = self.backend.ingest_alert("client-test", self.alert("192.0.2.2"))

        self.assertEqual(first["alert"]["id"], second["alert"]["id"])
        self.assertEqual(second["alert"]["occurrences"], 2)
        self.assertEqual(
            second["alert"]["source_ip_counts"],
            {"192.0.2.1": 1, "192.0.2.2": 1},
        )
        detail = self.backend.incident_detail(
            "client-test", first["incident"]["id"]
        )
        self.assertEqual(
            detail["alerts"][0]["source_ips"], ["192.0.2.1", "192.0.2.2"]
        )

    def test_different_agents_are_not_grouped(self) -> None:
        first = self.backend.ingest_alert("client-test", self.alert("192.0.2.1", "001"))
        second = self.backend.ingest_alert("client-test", self.alert("192.0.2.2", "002"))

        self.assertNotEqual(first["alert"]["id"], second["alert"]["id"])
        self.assertNotEqual(first["incident"]["id"], second["incident"]["id"])

    def test_group_expires_after_thirty_minutes(self) -> None:
        alert = self.alert("192.0.2.1")
        first = self.backend.ingest_alert("client-test", alert)
        expired_at = (datetime.now(timezone.utc) - timedelta(minutes=31)).isoformat(
            timespec="seconds"
        )
        with self.backend._connect() as connection:
            connection.execute(
                "UPDATE alerts SET last_seen = ? WHERE id = ?",
                (expired_at, first["alert"]["id"]),
            )
            connection.execute(
                "UPDATE incidents SET updated_at = ? WHERE id = ?",
                (expired_at, first["incident"]["id"]),
            )

        second = self.backend.ingest_alert("client-test", alert)

        self.assertNotEqual(first["alert"]["id"], second["alert"]["id"])
        self.assertNotEqual(first["incident"]["id"], second["incident"]["id"])

    def test_burst_is_scheduled_five_minutes_from_first_alert(self) -> None:
        first = self.backend.ingest_alert("client-test", self.alert("192.0.2.1"))
        self.backend.ingest_alert("client-test", self.alert("192.0.2.2"))

        queued = self.queued_item(first["incident"]["id"])
        expected_due = (
            datetime.fromisoformat(queued["burst_started_at"]) + timedelta(minutes=5)
        ).isoformat(timespec="seconds")
        self.assertEqual(queued["burst_confirmed"], 1)
        self.assertEqual(queued["due_at"], expected_due)
        self.assertEqual(queued["status"], "pending")

    def test_isolated_low_alert_does_not_call_ai(self) -> None:
        result = self.backend.ingest_alert("client-test", self.alert("192.0.2.1"))
        with self.backend._connect() as connection:
            connection.execute(
                "UPDATE incident_ai_queue SET due_at = '2000-01-01T00:00:00+00:00' "
                "WHERE incident_id = ?",
                (result["incident"]["id"],),
            )

        with patch("script1.threading.Thread") as thread:
            self.backend.process_ai_queue()

        thread.assert_not_called()
        self.assertEqual(self.queued_item(result["incident"]["id"])["status"], "completed")

    def test_high_alert_is_queued_immediately(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=13)
        )
        queued = self.queued_item(result["incident"]["id"])

        self.assertEqual(queued["high_priority"], 1)
        self.assertLessEqual(
            datetime.fromisoformat(queued["due_at"]),
            datetime.now().astimezone() + timedelta(seconds=1),
        )

    def test_analysis_sends_occurrences_and_all_source_ips_to_ollama(self) -> None:
        first = self.backend.ingest_alert("client-test", self.alert("192.0.2.1"))
        self.backend.ingest_alert("client-test", self.alert("192.0.2.2"))
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(
            {"response": "Analyse de test"}
        ).encode()

        with patch("script1.urlopen", return_value=response) as urlopen:
            self.backend.analyze_incident("client-test", first["incident"]["id"])

        request_body = json.loads(urlopen.call_args.args[0].data)
        prompt = json.loads(request_body["prompt"])
        self.assertEqual(prompt["alerts"][0]["occurrences"], 2)
        self.assertEqual(
            prompt["alerts"][0]["source_ip_counts"],
            {"192.0.2.1": 1, "192.0.2.2": 1},
        )
        detail = self.backend.incident_detail(
            "client-test", first["incident"]["id"]
        )
        self.assertIn(
            "ai_analysis", [entry["memory_type"] for entry in detail["history"]]
        )

    def test_due_high_alert_is_claimed_for_background_analysis(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=13)
        )
        with patch("script1.threading.Thread") as thread:
            self.backend.process_ai_queue()

        thread.assert_called_once()
        self.assertEqual(
            self.queued_item(result["incident"]["id"])["status"], "processing"
        )


if __name__ == "__main__":
    unittest.main()

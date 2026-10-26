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
                "SELECT * FROM incident_ai_jobs WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            return dict(row) if row else {}

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

    def test_low_level_group_expires_after_six_hours(self) -> None:
        alert = self.alert("192.0.2.1")
        first = self.backend.ingest_alert("client-test", alert)
        expired_at = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat(
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

    def test_low_level_alerts_wait_for_forty_occurrences(self) -> None:
        result = self.backend.ingest_alert("client-test", self.alert("192.0.2.1"))
        self.assertEqual(self.queued_item(result["incident"]["id"]), {})

        for _ in range(38):
            result = self.backend.ingest_alert("client-test", self.alert("192.0.2.2"))

        queued = self.queued_item(result["incident"]["id"])
        self.assertEqual(result["alert"]["occurrences"], 39)
        self.assertEqual(queued, {})

        result = self.backend.ingest_alert("client-test", self.alert("192.0.2.3"))
        queued = self.queued_item(result["incident"]["id"])
        self.assertEqual(result["alert"]["occurrences"], 40)
        self.assertEqual(queued["status"], "pending")

    def test_wazuh_repoll_does_not_inflate_occurrences(self) -> None:
        first_alert = self.alert("192.0.2.1")
        first_alert["id"] = "wazuh-event-1"
        second_alert = self.alert("192.0.2.2")
        second_alert["id"] = "wazuh-event-1"

        first = self.backend.ingest_alert("client-test", first_alert)
        repeated = self.backend.ingest_alert("client-test", second_alert)

        self.assertEqual(first["alert"]["id"], repeated["alert"]["id"])
        self.assertEqual(repeated["alert"]["occurrences"], 1)
        self.assertEqual(repeated["alert"]["source_ips"], ["192.0.2.1"])

    def test_low_alert_threshold_only_counts_events_from_last_six_hours(self) -> None:
        result = self.backend.ingest_alert("client-test", self.alert("192.0.2.1"))
        for _ in range(38):
            result = self.backend.ingest_alert(
                "client-test", self.alert("192.0.2.1")
            )
        expired_at = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat(
            timespec="seconds"
        )
        with self.backend._connect() as connection:
            connection.execute(
                "UPDATE alert_occurrence_events SET created_at = ? WHERE alert_id = ?",
                (expired_at, result["alert"]["id"]),
            )

        result = self.backend.ingest_alert("client-test", self.alert("192.0.2.2"))

        self.assertEqual(result["alert"]["occurrences"], 40)
        self.assertEqual(result["alert"]["occurrences_6h"], 1)
        self.assertEqual(self.queued_item(result["incident"]["id"]), {})

    def test_high_alert_is_queued_immediately(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=10)
        )
        queued = self.queued_item(result["incident"]["id"])

        self.assertEqual(queued["status"], "pending")
        self.assertLessEqual(
            datetime.fromisoformat(queued["due_at"]),
            datetime.now().astimezone() + timedelta(seconds=1),
        )

    def test_partial_iris_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Configurez ensemble"):
            SocBackend(
                self.database_path,
                {"test-token": "client-test"},
                {},
                "http://127.0.0.1:11434",
                "llama3.1",
                iris_base_url="https://iris.example.test",
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

    def test_iris_event_contains_ollama_analysis_and_incident_details(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=13)
        )
        self.backend.iris_base_url = "https://iris.example.test"
        self.backend.iris_api_key = "test-api-key"
        self.backend.iris_case_id = 123
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data": {}}'

        with patch("script1.urlopen", return_value=response) as urlopen:
            self.backend._publish_iris_event(
                "job-123",
                "client-test",
                result["incident"]["id"],
                "Analyse Ollama de test",
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url, "https://iris.example.test/case/timeline/events/add"
        )
        self.assertEqual(request.get_header("Authorization"), "Bearer test-api-key")
        payload = json.loads(request.data)
        self.assertEqual(payload["cid"], 123)
        self.assertEqual(payload["event_content"], "Analyse Ollama de test")
        raw = json.loads(payload["event_raw"])
        self.assertEqual(raw["soc_job_id"], "job-123")
        self.assertEqual(raw["alerts"][0]["source_ips"], ["192.0.2.1"])

    def test_automatic_analysis_is_published_to_iris_only_after_ollama(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=13)
        )
        self.backend.iris_base_url = "https://iris.example.test"
        self.backend.iris_api_key = "test-api-key"
        self.backend.iris_case_id = 123
        job = self.queued_item(result["incident"]["id"])

        with (
            patch.object(
                self.backend,
                "analyze_incident",
                return_value={"analysis": "Ollama analysis"},
            ) as analyze,
            patch.object(self.backend, "_publish_iris_event") as publish,
        ):
            self.backend._run_queued_analysis(
                job["job_id"], "client-test", result["incident"]["id"]
            )

        analyze.assert_called_once()
        publish.assert_called_once_with(
            job["job_id"],
            "client-test",
            result["incident"]["id"],
            "Ollama analysis",
        )
        self.assertEqual(self.queued_item(result["incident"]["id"])["status"], "completed")

    def test_automatic_analysis_without_iris_configuration_stays_local(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=13)
        )
        job = self.queued_item(result["incident"]["id"])

        with (
            patch.object(
                self.backend,
                "analyze_incident",
                return_value={"analysis": "Ollama analysis"},
            ) as analyze,
            patch.object(self.backend, "_publish_iris_event") as publish,
        ):
            self.backend._run_queued_analysis(
                job["job_id"], "client-test", result["incident"]["id"]
            )

        analyze.assert_called_once()
        publish.assert_not_called()
        self.assertEqual(self.queued_item(result["incident"]["id"])["status"], "completed")

    def test_iris_retry_reuses_analysis_without_calling_ollama_again(self) -> None:
        result = self.backend.ingest_alert(
            "client-test", self.alert("192.0.2.1", level=13)
        )
        self.backend.iris_base_url = "https://iris.example.test"
        self.backend.iris_api_key = "test-api-key"
        self.backend.iris_case_id = 123
        job = self.queued_item(result["incident"]["id"])

        with (
            patch.object(
                self.backend,
                "analyze_incident",
                return_value={"analysis": "Ollama analysis"},
            ) as analyze,
            patch.object(
                self.backend,
                "_publish_iris_event",
                side_effect=RuntimeError("IRIS unavailable"),
            ),
        ):
            self.backend._run_queued_analysis(
                job["job_id"], "client-test", result["incident"]["id"]
            )
            queued = self.queued_item(result["incident"]["id"])
            self.assertEqual(queued["status"], "iris_pending")
            self.assertEqual(queued["analysis"], "Ollama analysis")
            self.assertEqual(queued["attempts"], 0)
            self.assertEqual(queued["iris_attempts"], 1)

            with patch.object(self.backend, "_publish_iris_event") as publish:
                self.backend._run_queued_iris_publish(
                    job["job_id"],
                    "client-test",
                    result["incident"]["id"],
                    queued["analysis"],
                )

        analyze.assert_called_once()
        publish.assert_called_once()
        self.assertEqual(self.queued_item(result["incident"]["id"])["status"], "completed")


if __name__ == "__main__":
    unittest.main()

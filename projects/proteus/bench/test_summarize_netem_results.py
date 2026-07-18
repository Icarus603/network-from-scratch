#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize-netem-results.py")
SPEC = importlib.util.spec_from_file_location("summarize_netem_results", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReorderValidationTest(unittest.TestCase):
    def make_fixture(self, root: Path) -> Path:
        cell = root / "reorder-p5-c25-delay50"
        cell.mkdir()
        (cell / "cell-config.json").write_text(
            json.dumps(
                {
                    "cell": cell.name,
                    "model": "reorder",
                    "arguments": ["reorder", "5", "25", "50"],
                }
            )
        )
        rows = (
            '{"kind":"run_start","run":1}\n'
            '{"profile":"socks5-tcp","mib_per_sec":10.0}\n'
        )
        (cell / "proteus.jsonl").write_text(rows)
        (cell / "hy2.jsonl").write_text(rows)
        empty_qdisc = {"client_qdisc": [], "server_qdisc": []}
        (cell / "qdisc-before.json").write_text(json.dumps(empty_qdisc))
        after_qdisc = {
            "client_qdisc": [{"packets": 100, "drops": 0}],
            "server_qdisc": [{"packets": 100, "drops": 0}],
        }
        (cell / "qdisc-after.json").write_text(json.dumps(after_qdisc))
        applied_entry = {
            "kind": "netem",
            "options": {
                "delay": {"delay": 0.05},
                "reorder": {"reorder": 0.05, "correlation": 0.25},
            },
        }
        applied_qdisc = {
            "client_qdisc": [applied_entry],
            "server_qdisc": [applied_entry],
        }
        (cell / "qdisc-applied.json").write_text(json.dumps(applied_qdisc))
        stats_line = (
            "β session QUIC delta (client path) sent_packets={sent} "
            "lost_packets={lost} lost_bytes={lost_bytes} "
            "congestion_events={events} rtt_ms={rtt}\n"
        )
        (cell / "proteus-client-daemon.log").write_text(
            stats_line.format(
                sent=10, lost=1, lost_bytes=1200, events=1, rtt=50.0
            )
            + stats_line.format(
                sent=100, lost=60, lost_bytes=72000, events=4, rtt=100.0
            )
        )
        return cell

    def test_reorder_accepts_packets_without_drops(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.make_fixture(Path(directory))
            rows = MODULE.summarize(Path(directory))
            summary = next(row for row in rows if row["kind"] == "cell_summary")
            self.assertEqual(summary["loss_model"], "reorder")
            self.assertEqual(summary["reorder_pct"], 5.0)
            self.assertEqual(summary["client_qdisc_drop_delta"], 0)
            self.assertEqual(summary["proteus_quic_sent_packets_total"], 100)
            self.assertEqual(
                summary["proteus_quic_declared_lost_packets_total"], 60
            )
            self.assertAlmostEqual(
                summary["proteus_quic_declared_loss_ratio_total"], 0.6
            )

    def test_recovery_rows_require_exactly_one_warmup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cell = self.make_fixture(Path(directory))
            log = cell / "proteus-client-daemon.log"
            log.write_text(log.read_text().splitlines()[0] + "\n")
            with self.assertRaisesRegex(ValueError, "one warmup plus 1"):
                MODULE.summarize(Path(directory))

    def test_reorder_rejects_unapplied_kernel_qdisc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cell = self.make_fixture(Path(directory))
            (cell / "qdisc-applied.json").write_text(
                json.dumps({"client_qdisc": [], "server_qdisc": []})
            )
            with self.assertRaisesRegex(ValueError, "did not apply"):
                MODULE.summarize(Path(directory))


if __name__ == "__main__":
    unittest.main()

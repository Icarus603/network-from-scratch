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
            "packet_threshold_lost_packets={packet_lost} "
            "time_threshold_lost_packets={time_lost} "
            "spurious_lost_packets={spurious} "
            "spurious_packet_threshold_lost_packets={spurious_packet} "
            "spurious_time_threshold_lost_packets={spurious_time} "
            "congestion_events={events} rtt_ms={rtt}\n"
        )
        (cell / "proteus-client-daemon.log").write_text(
            stats_line.format(
                sent=10,
                lost=1,
                lost_bytes=1200,
                packet_lost=1,
                time_lost=0,
                spurious=1,
                spurious_packet=1,
                spurious_time=0,
                events=1,
                rtt=50.0,
            )
            + stats_line.format(
                sent=100,
                lost=60,
                lost_bytes=72000,
                packet_lost=50,
                time_lost=10,
                spurious=45,
                spurious_packet=40,
                spurious_time=5,
                events=4,
                rtt=100.0,
            )
        )
        (cell / "proteus-server-daemon.log").write_text(
            stats_line.replace("client path", "server path").format(
                sent=20,
                lost=2,
                lost_bytes=2400,
                packet_lost=2,
                time_lost=0,
                spurious=1,
                spurious_packet=1,
                spurious_time=0,
                events=2,
                rtt=55.0,
            )
            + stats_line.replace("client path", "server path").format(
                sent=200,
                lost=100,
                lost_bytes=120000,
                packet_lost=80,
                time_lost=20,
                spurious=70,
                spurious_packet=60,
                spurious_time=10,
                events=5,
                rtt=101.0,
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
            self.assertEqual(
                summary["proteus_quic_packet_threshold_lost_packets_total"],
                50,
            )
            self.assertEqual(
                summary["proteus_quic_time_threshold_lost_packets_total"], 10
            )
            self.assertEqual(
                summary["proteus_quic_spurious_lost_packets_total"], 45
            )
            self.assertAlmostEqual(
                summary["proteus_quic_spurious_loss_ratio_total"], 0.75
            )
            self.assertEqual(
                summary["proteus_server_quic_sent_packets_total"], 200
            )
            self.assertAlmostEqual(
                summary["proteus_server_quic_declared_loss_ratio_total"], 0.5
            )
            self.assertEqual(
                summary[
                    "proteus_server_quic_spurious_packet_threshold_lost_packets_total"
                ],
                60,
            )
            self.assertEqual(
                summary[
                    "proteus_server_quic_spurious_time_threshold_lost_packets_total"
                ],
                10,
            )
            self.assertAlmostEqual(
                summary["proteus_server_quic_spurious_loss_ratio_total"], 0.7
            )

    def test_legacy_recovery_rows_remain_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cell = self.make_fixture(Path(directory))
            legacy_line = (
                "β session QUIC delta ({path}) sent_packets={sent} "
                "lost_packets={lost} lost_bytes={lost_bytes} "
                "congestion_events={events} rtt_ms={rtt}\n"
            )
            (cell / "proteus-client-daemon.log").write_text(
                legacy_line.format(
                    path="client path",
                    sent=10,
                    lost=1,
                    lost_bytes=1200,
                    events=1,
                    rtt=50.0,
                )
                + legacy_line.format(
                    path="client path",
                    sent=100,
                    lost=60,
                    lost_bytes=72000,
                    events=4,
                    rtt=100.0,
                )
            )
            (cell / "proteus-server-daemon.log").write_text(
                legacy_line.format(
                    path="server path",
                    sent=20,
                    lost=2,
                    lost_bytes=2400,
                    events=2,
                    rtt=55.0,
                )
                + legacy_line.format(
                    path="server path",
                    sent=200,
                    lost=100,
                    lost_bytes=120000,
                    events=5,
                    rtt=101.0,
                )
            )

            rows = MODULE.summarize(Path(directory))
            summary = next(row for row in rows if row["kind"] == "cell_summary")
            self.assertEqual(
                summary["proteus_quic_declared_lost_packets_total"], 60
            )
            self.assertNotIn(
                "proteus_quic_spurious_lost_packets_total", summary
            )
            self.assertNotIn(
                "proteus_server_quic_spurious_lost_packets_total", summary
            )

    def test_partial_spurious_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cell = self.make_fixture(Path(directory))
            log = cell / "proteus-client-daemon.log"
            log.write_text(
                log.read_text().replace(
                    "spurious_time_threshold_lost_packets=0 ", "", 1
                )
            )
            with self.assertRaisesRegex(
                ValueError, "spurious_time_threshold_lost_packets"
            ):
                MODULE.summarize(Path(directory))

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

    def test_monte_carlo_permutation_never_reports_zero(self) -> None:
        proteus = [float(value + 100) for value in range(30)]
        hy2 = [float(value) for value in range(30)]
        p_value, method = MODULE.permutation_p_value(
            proteus, hy2, "separated-cell"
        )
        self.assertEqual(method, "monte_carlo_100000")
        self.assertEqual(p_value, 1 / 100_001)


if __name__ == "__main__":
    unittest.main()

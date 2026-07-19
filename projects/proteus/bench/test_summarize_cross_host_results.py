#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("summarize-cross-host-results.py")
SPEC = importlib.util.spec_from_file_location("cross_host_summary", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def recovery_line(marker: str) -> str:
    return (
        f"{marker} sent_packets=10 lost_packets=0 lost_bytes=0 "
        "packet_threshold_lost_packets=0 time_threshold_lost_packets=0 "
        "spurious_lost_packets=0 spurious_packet_threshold_lost_packets=0 "
        "spurious_time_threshold_lost_packets=0 current_packet_threshold=3 "
        "adaptive_packet_threshold_updates=0 max_spurious_packet_reordering=0 "
        "current_time_threshold=1.125 adaptive_time_threshold_updates=0 "
        "max_spurious_time_ratio=0.0 congestion_events=0 rtt_ms=1.0\n"
    )


class CrossHostSummaryTests(unittest.TestCase):
    def make_fixture(self, root: Path, server_git: str = "abc") -> None:
        write_jsonl(
            root / "metadata.jsonl",
            [
                {
                    "runs_per_implementation": 2,
                    "client_git_commit": "abc",
                    "server": {"git_commit": server_git},
                    "formal_eligible": True,
                }
            ],
        )
        for filename, speeds in (
            ("proteus.jsonl", [20.0, 22.0]),
            ("hy2.jsonl", [10.0, 11.0]),
        ):
            rows = []
            for run, speed in enumerate(speeds, start=1):
                rows.extend(
                    [
                        {"kind": "run_start", "run": run},
                        {
                            "profile": "socks5-tcp",
                            "mib_per_sec": speed,
                        },
                    ]
                )
            write_jsonl(root / filename, rows)
        for filename, implementation in (
            ("proteus-resources.jsonl", "proteus-beta-brutal"),
            ("hy2-resources.jsonl", "hysteria2"),
        ):
            write_jsonl(
                root / filename,
                [
                    {
                        "kind": "resource",
                        "implementation": implementation,
                        "run": run,
                        "cpu_usage_usec": 100_000 * run,
                        "rss_after_kib": 1024 * run,
                        "exit_status": 0,
                    }
                    for run in (1, 2)
                ],
            )
        (root / "proteus-client-daemon.log").write_text("")

    def test_formal_gate_requires_direction_complete_server_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root)
            rows = SUMMARY.summarize(root)
            first_summary = rows[-1]
            self.assertFalse(first_summary["server_recovery_counters_available"])
            self.assertFalse(first_summary["formal_eligible"])

            marker = "β session QUIC delta (server path)"
            (root / "proteus-server-daemon.log").write_text(
                recovery_line(marker) * 3
            )
            rows = SUMMARY.summarize(root)
            complete_summary = rows[-1]
            self.assertTrue(complete_summary["server_recovery_counters_available"])
            self.assertTrue(complete_summary["formal_eligible"])
            self.assertEqual(rows[0]["server_quic_sent_packets"], 10)

    def test_source_commit_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root, server_git="different")
            with self.assertRaisesRegex(ValueError, "source commits differ"):
                SUMMARY.summarize(root)


if __name__ == "__main__":
    unittest.main()

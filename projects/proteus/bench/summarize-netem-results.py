#!/usr/bin/env python3
"""Normalize and validate Proteus/Hy2 container benchmark output."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import re
import statistics
import sys
from pathlib import Path
from typing import Any


SPEED_RE = re.compile(r"^(?P<value>[0-9.]+) (?P<unit>[KMGT]?B/s)$")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
BETA_CLIENT_STATS_MARKER = "β session QUIC delta (client path)"
BETA_SERVER_STATS_MARKER = "β session QUIC delta (server path)"
BETA_STATS_FIELD_RE = re.compile(
    r"\b(sent_packets|lost_packets|lost_bytes|packet_threshold_lost_packets|"
    r"time_threshold_lost_packets|spurious_lost_packets|"
    r"spurious_packet_threshold_lost_packets|"
    r"spurious_time_threshold_lost_packets|congestion_events|rtt_ms)"
    r"=([0-9.]+)"
)
DECIMAL_MULTIPLIER = {
    "B/s": 1,
    "KB/s": 1_000,
    "MB/s": 1_000_000,
    "GB/s": 1_000_000_000,
    "TB/s": 1_000_000_000_000,
}


def json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    if not rows:
        raise ValueError(f"{path}: no JSON objects found")
    return rows


def parse_speed(value: str) -> float:
    match = SPEED_RE.fullmatch(value)
    if not match:
        raise ValueError(f"unsupported Hysteria speed value: {value!r}")
    return float(match["value"]) * DECIMAL_MULTIPLIER[match["unit"]]


def qdisc_totals(value: Any) -> tuple[int, int]:
    packets = 0
    drops = 0
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "packets" and isinstance(child, int):
                packets += child
            elif key == "drops" and isinstance(child, int):
                drops += child
            elif isinstance(child, (dict, list)):
                child_packets, child_drops = qdisc_totals(child)
                packets += child_packets
                drops += child_drops
    elif isinstance(value, list):
        for child in value:
            child_packets, child_drops = qdisc_totals(child)
            packets += child_packets
            drops += child_drops
    return packets, drops


def parse_hy2_runs(rows: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    proxy_runs = parse_socks_runs(rows)
    if proxy_runs:
        return proxy_runs

    current_run: int | None = None
    partial: dict[int, dict[str, float]] = {}
    failed: set[int] = set()
    for row in rows:
        if row.get("kind") == "run_start":
            current_run = int(row["run"])
            partial.setdefault(current_run, {})
            continue
        if row.get("kind") == "run_failure":
            failed.add(int(row["run"]))
            continue
        if current_run is None:
            continue
        message = row.get("msg")
        if message not in {"download complete", "upload complete"}:
            continue
        direction = "download" if message.startswith("download") else "upload"
        partial[current_run][direction] = parse_speed(str(row["speed"]))

    normalized: list[dict[str, float | int]] = []
    for run, speeds in sorted(partial.items()):
        if run in failed:
            continue
        if set(speeds) != {"download", "upload"}:
            raise ValueError(f"Hy2 run {run} is incomplete: {speeds}")
        download = speeds["download"]
        upload = speeds["upload"]
        equivalent = (download * upload) / (download + upload) / (1024 * 1024)
        normalized.append(
            {
                "run": run,
                "download_decimal_mb_per_sec": download / 1_000_000,
                "upload_decimal_mb_per_sec": upload / 1_000_000,
                "roundtrip_equivalent_mib_per_sec": equivalent,
            }
        )
    return normalized


def parse_proteus_runs(rows: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    proxy_runs = parse_socks_runs(rows)
    if proxy_runs:
        return proxy_runs

    current_run: int | None = None
    normalized: list[dict[str, float | int]] = []
    for row in rows:
        if row.get("kind") == "run_start":
            current_run = int(row["run"])
        elif (
            current_run is not None
            and row.get("profile") == "beta"
            and "mib_per_sec" in row
        ):
            normalized.append(
                {
                    "run": current_run,
                    "roundtrip_equivalent_mib_per_sec": float(row["mib_per_sec"]),
                }
            )
    return normalized


def parse_socks_runs(rows: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    current_run: int | None = None
    normalized: list[dict[str, float | int]] = []
    failed: set[int] = {
        int(row["run"]) for row in rows if row.get("kind") == "run_failure"
    }
    for row in rows:
        if row.get("kind") == "run_start":
            current_run = int(row["run"])
        elif (
            current_run is not None
            and current_run not in failed
            and row.get("profile") == "socks5-tcp"
            and "mib_per_sec" in row
        ):
            normalized.append(
                {
                    "run": current_run,
                    "roundtrip_equivalent_mib_per_sec": float(row["mib_per_sec"]),
                }
            )
    return normalized


def parse_tuic_runs(rows: list[dict[str, Any]]) -> list[dict[str, float | int]]:
    return parse_socks_runs(rows)


def attempt_ids(rows: list[dict[str, Any]]) -> set[int]:
    return {
        int(row["run"])
        for row in rows
        if row.get("kind") == "run_start" and "run" in row
    }


def resource_rows(path: Path, implementation: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return [
        row
        for row in rows
        if row.get("kind") == "resource"
        and row.get("implementation") == implementation
        and int(row.get("exit_status", 1)) == 0
    ]


def beta_recovery_rows(
    path: Path, expected_runs: int, marker: str
) -> list[dict[str, Any]]:
    """Parse one warmup plus per-observation Quinn recovery counters."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw_line in path.read_text().splitlines():
        line = ANSI_ESCAPE_RE.sub("", raw_line)
        if marker not in line:
            continue
        fields = dict(BETA_STATS_FIELD_RE.findall(line))
        required = {
            "sent_packets",
            "lost_packets",
            "lost_bytes",
            "congestion_events",
            "rtt_ms",
        }
        optional_spurious = {
            "packet_threshold_lost_packets",
            "time_threshold_lost_packets",
            "spurious_lost_packets",
            "spurious_packet_threshold_lost_packets",
            "spurious_time_threshold_lost_packets",
        }
        present_spurious = set(fields) & optional_spurious
        if not required.issubset(fields) or (
            present_spurious and present_spurious != optional_spurious
        ):
            missing = required - set(fields)
            if present_spurious:
                missing |= optional_spurious - present_spurious
            raise ValueError(
                f"{path}: incomplete beta recovery row: "
                f"missing {sorted(missing)}"
            )
        sent_packets = int(fields["sent_packets"])
        lost_packets = int(fields["lost_packets"])
        row = {
            "quic_sent_packets": sent_packets,
            "quic_declared_lost_packets": lost_packets,
            "quic_declared_lost_bytes": int(fields["lost_bytes"]),
            "quic_congestion_events": int(fields["congestion_events"]),
            "quic_rtt_ms": float(fields["rtt_ms"]),
            "quic_declared_loss_ratio": (
                lost_packets / sent_packets if sent_packets else 0.0
            ),
        }
        if present_spurious:
            spurious_lost_packets = int(fields["spurious_lost_packets"])
            row.update(
                {
                    "quic_packet_threshold_lost_packets": int(
                        fields["packet_threshold_lost_packets"]
                    ),
                    "quic_time_threshold_lost_packets": int(
                        fields["time_threshold_lost_packets"]
                    ),
                    "quic_spurious_lost_packets": spurious_lost_packets,
                    "quic_spurious_packet_threshold_lost_packets": int(
                        fields["spurious_packet_threshold_lost_packets"]
                    ),
                    "quic_spurious_time_threshold_lost_packets": int(
                        fields["spurious_time_threshold_lost_packets"]
                    ),
                    "quic_spurious_loss_ratio": (
                        spurious_lost_packets / lost_packets
                        if lost_packets
                        else 0.0
                    ),
                }
            )
        rows.append(row)
    if not rows:
        return []
    expected_with_warmup = expected_runs + 1
    if len(rows) != expected_with_warmup:
        raise ValueError(
            f"{path}: expected one warmup plus {expected_runs} recovery rows, "
            f"found {len(rows)}"
        )
    return rows[1:]


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_uplift_interval(
    proteus: list[float], hy2: list[float], cell: str
) -> tuple[float, float]:
    seed = int.from_bytes(hashlib.sha256(cell.encode()).digest()[:8], "big")
    generator = random.Random(seed)
    uplifts: list[float] = []
    for _ in range(20_000):
        proteus_sample = [generator.choice(proteus) for _ in proteus]
        hy2_sample = [generator.choice(hy2) for _ in hy2]
        hy2_median = statistics.median(hy2_sample)
        uplifts.append(
            (statistics.median(proteus_sample) / hy2_median - 1) * 100
        )
    return percentile(uplifts, 0.025), percentile(uplifts, 0.975)


def permutation_p_value(
    proteus: list[float], hy2: list[float], cell: str
) -> tuple[float, str]:
    combined = proteus + hy2
    group_size = len(proteus)
    observed = abs(statistics.mean(proteus) - statistics.mean(hy2))
    extreme = 0
    total = 0
    if len(combined) <= 20:
        partitions = itertools.combinations(range(len(combined)), group_size)
        method = "exact"
    else:
        seed = int.from_bytes(
            hashlib.sha256((cell + ":permutation").encode()).digest()[:8], "big"
        )
        generator = random.Random(seed)
        partitions = (
            generator.sample(range(len(combined)), group_size)
            for _ in range(100_000)
        )
        method = "monte_carlo_100000"

    for selected in partitions:
        selected_set = set(selected)
        left = [combined[index] for index in selected_set]
        right = [
            value for index, value in enumerate(combined) if index not in selected_set
        ]
        difference = abs(statistics.mean(left) - statistics.mean(right))
        if difference >= observed - 1e-12:
            extreme += 1
        total += 1
    return extreme / total, method


def probability_of_superiority(proteus: list[float], hy2: list[float]) -> float:
    wins = 0.0
    comparisons = 0
    for proteus_value in proteus:
        for hy2_value in hy2:
            wins += float(proteus_value > hy2_value)
            wins += 0.5 * float(proteus_value == hy2_value)
            comparisons += 1
    return wins / comparisons


def summarize(results_dir: Path) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    failures: list[str] = []
    cell_dirs = sorted(path for path in results_dir.iterdir() if path.is_dir())
    if not cell_dirs:
        raise ValueError(f"{results_dir}: no benchmark cells found")

    for cell_dir in cell_dirs:
        config_path = cell_dir / "cell-config.json"
        if not config_path.exists():
            continue
        config = json.loads(config_path.read_text())
        arguments = list(config["arguments"])
        model = str(config["model"])
        if model == "iid" and len(arguments) == 3:
            loss_pct = float(arguments[1])
            one_way_delay_ms = float(arguments[2])
            model_parameters: dict[str, Any] = {"loss_pct": loss_pct}
        elif model == "gemodel" and len(arguments) == 6:
            loss_pct = None
            one_way_delay_ms = float(arguments[5])
            model_parameters = {
                "p_pct": float(str(arguments[1]).rstrip("%")),
                "r_pct": float(str(arguments[2]).rstrip("%")),
                "one_minus_h_pct": float(str(arguments[3]).rstrip("%")),
                "one_minus_k_pct": float(str(arguments[4]).rstrip("%")),
            }
        elif model == "reorder" and len(arguments) == 4:
            loss_pct = None
            one_way_delay_ms = float(arguments[3])
            model_parameters = {
                "reorder_pct": float(str(arguments[1]).rstrip("%")),
                "correlation_pct": float(str(arguments[2]).rstrip("%")),
            }
        else:
            failures.append(f"{cell_dir.name}: invalid cell config {config}")
            continue
        common = {
            "cell": cell_dir.name,
            "loss_model": model,
            "one_way_delay_ms": one_way_delay_ms,
            **model_parameters,
        }
        proteus_raw = json_lines(cell_dir / "proteus.jsonl")
        hy2_raw = json_lines(cell_dir / "hy2.jsonl")
        tuic_path = cell_dir / "tuic.jsonl"
        tuic_raw = json_lines(tuic_path) if tuic_path.exists() else []
        proteus_rows = parse_proteus_runs(proteus_raw)
        hy2_rows = parse_hy2_runs(hy2_raw)
        tuic_rows = parse_tuic_runs(tuic_raw) if tuic_raw else []
        proteus_attempts = attempt_ids(proteus_raw)
        hy2_attempts = attempt_ids(hy2_raw)
        tuic_attempts = attempt_ids(tuic_raw) if tuic_raw else set()
        proteus_recovery = beta_recovery_rows(
            cell_dir / "proteus-client-daemon.log",
            len(proteus_attempts),
            BETA_CLIENT_STATS_MARKER,
        )
        server_recovery = beta_recovery_rows(
            cell_dir / "proteus-server-daemon.log",
            len(proteus_attempts),
            BETA_SERVER_STATS_MARKER,
        )
        if proteus_recovery:
            if len(proteus_recovery) != len(proteus_rows):
                failures.append(
                    f"{cell_dir.name}: recovery-count mismatch "
                    f"Proteus={len(proteus_rows)} recovery={len(proteus_recovery)}"
                )
                continue
            for row, recovery in zip(proteus_rows, proteus_recovery, strict=True):
                row.update(recovery)
        if server_recovery:
            if len(server_recovery) != len(proteus_rows):
                failures.append(
                    f"{cell_dir.name}: server recovery-count mismatch "
                    f"Proteus={len(proteus_rows)} recovery={len(server_recovery)}"
                )
                continue
            for row, recovery in zip(proteus_rows, server_recovery, strict=True):
                row.update(
                    {f"server_{key}": value for key, value in recovery.items()}
                )
        proteus_resource_path = cell_dir / "proteus-resources.jsonl"
        if not proteus_resource_path.exists():
            proteus_resource_path = cell_dir / "proteus.stderr"
        hy2_resource_path = cell_dir / "hy2-resources.jsonl"
        if not hy2_resource_path.exists():
            hy2_resource_path = cell_dir / "hy2.jsonl"
        proteus_resources = resource_rows(
            proteus_resource_path, "proteus-beta-brutal"
        )
        hy2_resources = resource_rows(hy2_resource_path, "hysteria2")
        tuic_resources = resource_rows(
            cell_dir / "tuic-resources.jsonl", "official-tuic-v5-1.0.0"
        )
        if proteus_attempts != hy2_attempts:
            failures.append(
                f"{cell_dir.name}: attempt-id mismatch "
                f"Proteus={sorted(proteus_attempts)} Hy2={sorted(hy2_attempts)}"
            )
            continue
        if tuic_raw and proteus_attempts != tuic_attempts:
            failures.append(
                f"{cell_dir.name}: TUIC attempt-id mismatch "
                f"Proteus={sorted(proteus_attempts)} TUIC={sorted(tuic_attempts)}"
            )
            continue

        for row in proteus_rows:
            output.append(
                {
                    "kind": "run",
                    "implementation": "proteus-beta-brutal",
                    **common,
                    **row,
                }
            )
        for row in hy2_rows:
            output.append(
                {
                    "kind": "run",
                    "implementation": "hysteria2",
                    **common,
                    **row,
                }
            )
        for row in tuic_rows:
            output.append(
                {
                    "kind": "run",
                    "implementation": "official-tuic-v5-1.0.0",
                    **common,
                    **row,
                }
            )

        proteus_values = [
            float(row["roundtrip_equivalent_mib_per_sec"]) for row in proteus_rows
        ]
        hy2_values = [
            float(row["roundtrip_equivalent_mib_per_sec"]) for row in hy2_rows
        ]
        tuic_values = [
            float(row["roundtrip_equivalent_mib_per_sec"]) for row in tuic_rows
        ]
        if not proteus_values or not hy2_values:
            failures.append(
                f"{cell_dir.name}: no successful observations "
                f"Proteus={len(proteus_values)} Hy2={len(hy2_values)}"
            )
            continue
        proteus_median = statistics.median(proteus_values)
        hy2_median = statistics.median(hy2_values)
        uplift_ci_low, uplift_ci_high = bootstrap_uplift_interval(
            proteus_values, hy2_values, cell_dir.name
        )
        permutation_p, permutation_method = permutation_p_value(
            proteus_values, hy2_values, cell_dir.name
        )

        before = json.loads((cell_dir / "qdisc-before.json").read_text())
        after = json.loads((cell_dir / "qdisc-after.json").read_text())
        applied = json.loads((cell_dir / "qdisc-applied.json").read_text())
        qdisc_deltas: dict[str, dict[str, int]] = {}
        for side in ("client_qdisc", "server_qdisc"):
            before_packets, before_drops = qdisc_totals(before.get(side, []))
            after_packets, after_drops = qdisc_totals(after.get(side, []))
            packet_delta = after_packets - before_packets
            drop_delta = after_drops - before_drops
            qdisc_deltas[side] = {
                "packets": packet_delta,
                "drops": drop_delta,
            }
            if packet_delta <= 0:
                failures.append(
                    f"{cell_dir.name}: {side} saw no packets; path is invalid"
                )
            expects_drops = (
                (model == "iid" and loss_pct is not None and loss_pct > 0)
                or (
                    model == "gemodel"
                    and any(float(value) > 0 for value in model_parameters.values())
                )
            )
            if expects_drops and drop_delta <= 0:
                failures.append(
                    f"{cell_dir.name}: {side} produced no drops under configured loss"
                )
            if model == "iid" and loss_pct == 0 and drop_delta != 0:
                failures.append(
                    f"{cell_dir.name}: {side} unexpectedly dropped {drop_delta} "
                    "packets under 0% configured loss; netem queue overflow is likely"
                )
            if model == "reorder":
                expected_reorder = model_parameters["reorder_pct"] / 100
                expected_correlation = model_parameters["correlation_pct"] / 100
                expected_delay = one_way_delay_ms / 1000
                qdiscs = applied.get(side, [])
                matches = any(
                    qdisc.get("kind") == "netem"
                    and abs(
                        float(
                            qdisc.get("options", {})
                            .get("reorder", {})
                            .get("reorder", -1)
                        )
                        - expected_reorder
                    )
                    < 1e-9
                    and abs(
                        float(
                            qdisc.get("options", {})
                            .get("reorder", {})
                            .get("correlation", -1)
                        )
                        - expected_correlation
                    )
                    < 1e-9
                    and abs(
                        float(
                            qdisc.get("options", {})
                            .get("delay", {})
                            .get("delay", -1)
                        )
                        - expected_delay
                    )
                    < 1e-9
                    for qdisc in qdiscs
                )
                if not matches:
                    failures.append(
                        f"{cell_dir.name}: {side} did not apply the requested "
                        "reorder/correlation/delay qdisc"
                    )

        summary: dict[str, Any] = {
                "kind": "cell_summary",
                **common,
                "attempts_per_implementation": len(proteus_attempts),
                "proteus_successes": len(proteus_values),
                "hy2_successes": len(hy2_values),
                "proteus_success_rate": len(proteus_values) / len(proteus_attempts),
                "hy2_success_rate": len(hy2_values) / len(hy2_attempts),
                "proteus_median_mib_per_sec": proteus_median,
                "hy2_median_mib_per_sec": hy2_median,
                "proteus_uplift_pct": (proteus_median / hy2_median - 1) * 100,
                "proteus_uplift_bootstrap_95pct_low": uplift_ci_low,
                "proteus_uplift_bootstrap_95pct_high": uplift_ci_high,
                "permutation_p_value_two_sided": permutation_p,
                "permutation_method": permutation_method,
                "probability_proteus_exceeds_hy2": probability_of_superiority(
                    proteus_values, hy2_values
                ),
                "client_qdisc_packet_delta": qdisc_deltas["client_qdisc"]["packets"],
                "client_qdisc_drop_delta": qdisc_deltas["client_qdisc"]["drops"],
                "server_qdisc_packet_delta": qdisc_deltas["server_qdisc"]["packets"],
                "server_qdisc_drop_delta": qdisc_deltas["server_qdisc"]["drops"],
        }
        if proteus_recovery:
            client_sent_packets = sum(
                int(row["quic_sent_packets"]) for row in proteus_recovery
            )
            client_lost_packets = sum(
                int(row["quic_declared_lost_packets"]) for row in proteus_recovery
            )
            summary.update(
                {
                    "proteus_quic_declared_loss_ratio_median": statistics.median(
                        float(row["quic_declared_loss_ratio"])
                        for row in proteus_recovery
                    ),
                    "proteus_quic_declared_loss_ratio_total": (
                        client_lost_packets / client_sent_packets
                        if client_sent_packets
                        else 0.0
                    ),
                    "proteus_quic_sent_packets_total": client_sent_packets,
                    "proteus_quic_declared_lost_packets_total": (
                        client_lost_packets
                    ),
                    "proteus_quic_congestion_events_median": statistics.median(
                        int(row["quic_congestion_events"])
                        for row in proteus_recovery
                    ),
                }
            )
            if "quic_spurious_lost_packets" in proteus_recovery[0]:
                client_spurious_packets = sum(
                    int(row["quic_spurious_lost_packets"])
                    for row in proteus_recovery
                )
                summary.update(
                    {
                        "proteus_quic_packet_threshold_lost_packets_total": sum(
                            int(row["quic_packet_threshold_lost_packets"])
                            for row in proteus_recovery
                        ),
                        "proteus_quic_time_threshold_lost_packets_total": sum(
                            int(row["quic_time_threshold_lost_packets"])
                            for row in proteus_recovery
                        ),
                        "proteus_quic_spurious_lost_packets_total": (
                            client_spurious_packets
                        ),
                        "proteus_quic_spurious_packet_threshold_lost_packets_total": sum(
                            int(
                                row[
                                    "quic_spurious_packet_threshold_lost_packets"
                                ]
                            )
                            for row in proteus_recovery
                        ),
                        "proteus_quic_spurious_time_threshold_lost_packets_total": sum(
                            int(
                                row["quic_spurious_time_threshold_lost_packets"]
                            )
                            for row in proteus_recovery
                        ),
                        "proteus_quic_spurious_loss_ratio_total": (
                            client_spurious_packets / client_lost_packets
                            if client_lost_packets
                            else 0.0
                        ),
                    }
                )
        if server_recovery:
            server_sent_packets = sum(
                int(row["quic_sent_packets"]) for row in server_recovery
            )
            server_lost_packets = sum(
                int(row["quic_declared_lost_packets"]) for row in server_recovery
            )
            summary.update(
                {
                    "proteus_server_quic_declared_loss_ratio_median": (
                        statistics.median(
                            float(row["quic_declared_loss_ratio"])
                            for row in server_recovery
                        )
                    ),
                    "proteus_server_quic_declared_loss_ratio_total": (
                        server_lost_packets / server_sent_packets
                        if server_sent_packets
                        else 0.0
                    ),
                    "proteus_server_quic_sent_packets_total": server_sent_packets,
                    "proteus_server_quic_declared_lost_packets_total": (
                        server_lost_packets
                    ),
                    "proteus_server_quic_congestion_events_median": (
                        statistics.median(
                            int(row["quic_congestion_events"])
                            for row in server_recovery
                        )
                    ),
                }
            )
            if "quic_spurious_lost_packets" in server_recovery[0]:
                server_spurious_packets = sum(
                    int(row["quic_spurious_lost_packets"])
                    for row in server_recovery
                )
                summary.update(
                    {
                        "proteus_server_quic_packet_threshold_lost_packets_total": sum(
                            int(row["quic_packet_threshold_lost_packets"])
                            for row in server_recovery
                        ),
                        "proteus_server_quic_time_threshold_lost_packets_total": sum(
                            int(row["quic_time_threshold_lost_packets"])
                            for row in server_recovery
                        ),
                        "proteus_server_quic_spurious_lost_packets_total": (
                            server_spurious_packets
                        ),
                        "proteus_server_quic_spurious_packet_threshold_lost_packets_total": sum(
                            int(
                                row[
                                    "quic_spurious_packet_threshold_lost_packets"
                                ]
                            )
                            for row in server_recovery
                        ),
                        "proteus_server_quic_spurious_time_threshold_lost_packets_total": sum(
                            int(
                                row["quic_spurious_time_threshold_lost_packets"]
                            )
                            for row in server_recovery
                        ),
                        "proteus_server_quic_spurious_loss_ratio_total": (
                            server_spurious_packets / server_lost_packets
                            if server_lost_packets
                            else 0.0
                        ),
                    }
                )
        if tuic_raw:
            summary.update(
                {
                    "tuic_successes": len(tuic_values),
                    "tuic_success_rate": len(tuic_values) / len(tuic_attempts),
                }
            )
            if tuic_values:
                tuic_median = statistics.median(tuic_values)
                tuic_ci_low, tuic_ci_high = bootstrap_uplift_interval(
                    proteus_values, tuic_values, cell_dir.name + ":tuic"
                )
                tuic_permutation_p, tuic_permutation_method = permutation_p_value(
                    proteus_values, tuic_values, cell_dir.name + ":tuic"
                )
                summary.update(
                    {
                        "tuic_median_mib_per_sec": tuic_median,
                        "proteus_vs_tuic_uplift_pct": (
                            proteus_median / tuic_median - 1
                        )
                        * 100,
                        "proteus_vs_tuic_bootstrap_95pct_low": tuic_ci_low,
                        "proteus_vs_tuic_bootstrap_95pct_high": tuic_ci_high,
                        "proteus_vs_tuic_permutation_p_value_two_sided": (
                            tuic_permutation_p
                        ),
                        "proteus_vs_tuic_permutation_method": tuic_permutation_method,
                        "probability_proteus_exceeds_tuic": probability_of_superiority(
                            proteus_values, tuic_values
                        ),
                    }
                )
        if (
            len(proteus_resources) == len(proteus_rows)
            and len(hy2_resources) == len(hy2_rows)
            and (not tuic_raw or len(tuic_resources) == len(tuic_rows))
        ):
            summary.update(
                {
                    "proteus_client_cpu_sec_per_run": statistics.median(
                        float(row["cpu_usage_usec"]) / 1_000_000
                        for row in proteus_resources
                    ),
                    "hy2_client_cpu_sec_per_run": statistics.median(
                        float(row["cpu_usage_usec"]) / 1_000_000
                        for row in hy2_resources
                    ),
                }
            )
            if "rss_after_kib" in proteus_resources[0]:
                summary.update(
                    {
                        "proteus_client_rss_after_run_mib": statistics.median(
                            float(row["rss_after_kib"]) / 1024
                            for row in proteus_resources
                        ),
                        "hy2_client_rss_after_run_mib": statistics.median(
                            float(row["rss_after_kib"]) / 1024
                            for row in hy2_resources
                        ),
                    }
                )
                if tuic_resources:
                    summary.update(
                        {
                            "tuic_client_cpu_sec_per_run": statistics.median(
                                float(row["cpu_usage_usec"]) / 1_000_000
                                for row in tuic_resources
                            ),
                            "tuic_client_rss_after_run_mib": statistics.median(
                                float(row["rss_after_kib"]) / 1024
                                for row in tuic_resources
                            ),
                        }
                    )
            else:
                summary.update(
                    {
                        "proteus_client_peak_rss_mib": statistics.median(
                            float(row["peak_rss_kib"]) / 1024
                            for row in proteus_resources
                        ),
                        "hy2_client_peak_rss_mib": statistics.median(
                            float(row["peak_rss_kib"]) / 1024
                            for row in hy2_resources
                        ),
                    }
                )
        elif proteus_resources or hy2_resources or tuic_resources:
            failures.append(
                f"{cell_dir.name}: resource-count mismatch "
                f"Proteus={len(proteus_resources)} Hy2={len(hy2_resources)} "
                f"TUIC={len(tuic_resources)}"
            )
        output.append(summary)

    if failures:
        raise ValueError("; ".join(failures))
    if not output:
        raise ValueError(f"{results_dir}: no recognized benchmark results")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="write normalized JSONL here (default: RESULTS_DIR/summary.jsonl)",
    )
    args = parser.parse_args()
    destination = args.output or args.results_dir / "summary.jsonl"
    try:
        rows = summarize(args.results_dir)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"benchmark result validation failed: {error}", file=sys.stderr)
        return 1
    destination.write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    )
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
        proteus_resources = resource_rows(
            cell_dir / "proteus.stderr", "proteus-beta-brutal"
        )
        hy2_resources = resource_rows(cell_dir / "hy2.jsonl", "hysteria2")
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
                    "implementation": "sing-box-tuic-v5",
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
                loss_pct > 0
                if loss_pct is not None
                else any(float(value) > 0 for value in model_parameters.values())
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
                    "proteus_client_peak_rss_mib": statistics.median(
                        float(row["peak_rss_kib"]) / 1024
                        for row in proteus_resources
                    ),
                    "hy2_client_peak_rss_mib": statistics.median(
                        float(row["peak_rss_kib"]) / 1024 for row in hy2_resources
                    ),
                }
            )
        elif proteus_resources or hy2_resources:
            failures.append(
                f"{cell_dir.name}: resource-count mismatch "
                f"Proteus={len(proteus_resources)} Hy2={len(hy2_resources)}"
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

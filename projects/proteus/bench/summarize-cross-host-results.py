#!/usr/bin/env python3
"""Validate and summarize the production-shaped physical two-host benchmark."""

from __future__ import annotations

import argparse
import importlib.util
import json
import statistics
import sys
from pathlib import Path
from typing import Any


def load_netem_helpers(script_dir: Path) -> Any:
    path = script_dir / "summarize-netem-results.py"
    spec = importlib.util.spec_from_file_location("proteus_netem_summary", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import statistical helpers from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def median_resource(
    rows: list[dict[str, Any]], field: str, scale: float
) -> float | None:
    values = [float(row[field]) / scale for row in rows if field in row]
    return statistics.median(values) if values else None


def summarize(results_dir: Path) -> list[dict[str, Any]]:
    helpers = load_netem_helpers(Path(__file__).resolve().parent)
    metadata_rows = helpers.json_lines(results_dir / "metadata.jsonl")
    metadata = metadata_rows[-1]
    expected_runs = int(metadata["runs_per_implementation"])
    expected_ids = set(range(1, expected_runs + 1))

    proteus_raw = helpers.json_lines(results_dir / "proteus.jsonl")
    hy2_raw = helpers.json_lines(results_dir / "hy2.jsonl")
    proteus_attempts = helpers.attempt_ids(proteus_raw)
    hy2_attempts = helpers.attempt_ids(hy2_raw)
    if proteus_attempts != expected_ids or hy2_attempts != expected_ids:
        raise ValueError(
            "cross-host attempt IDs are incomplete or unequal: "
            f"expected={sorted(expected_ids)} "
            f"Proteus={sorted(proteus_attempts)} Hy2={sorted(hy2_attempts)}"
        )

    proteus_runs = helpers.parse_proteus_runs(proteus_raw)
    hy2_runs = helpers.parse_hy2_runs(hy2_raw)
    if len(proteus_runs) != expected_runs or len(hy2_runs) != expected_runs:
        raise ValueError(
            "cross-host success count mismatch: "
            f"expected={expected_runs} "
            f"Proteus={len(proteus_runs)} Hy2={len(hy2_runs)}"
        )

    recovery = helpers.beta_recovery_rows(
        results_dir / "proteus-client-daemon.log",
        expected_runs,
        helpers.BETA_CLIENT_STATS_MARKER,
    )
    if recovery:
        for run, counters in zip(proteus_runs, recovery, strict=True):
            run.update(counters)
    server_recovery_path = results_dir / "proteus-server-daemon.log"
    server_recovery = helpers.beta_recovery_rows(
        server_recovery_path,
        expected_runs,
        helpers.BETA_SERVER_STATS_MARKER,
    )
    if server_recovery:
        for run, counters in zip(proteus_runs, server_recovery, strict=True):
            run.update({f"server_{key}": value for key, value in counters.items()})

    proteus_resources = helpers.resource_rows(
        results_dir / "proteus-resources.jsonl", "proteus-beta-brutal"
    )
    hy2_resources = helpers.resource_rows(
        results_dir / "hy2-resources.jsonl", "hysteria2"
    )
    if len(proteus_resources) != expected_runs or len(hy2_resources) != expected_runs:
        raise ValueError(
            "cross-host resource count mismatch: "
            f"expected={expected_runs} "
            f"Proteus={len(proteus_resources)} Hy2={len(hy2_resources)}"
        )

    proteus_values = [
        float(row["roundtrip_equivalent_mib_per_sec"]) for row in proteus_runs
    ]
    hy2_values = [
        float(row["roundtrip_equivalent_mib_per_sec"]) for row in hy2_runs
    ]
    proteus_median = statistics.median(proteus_values)
    hy2_median = statistics.median(hy2_values)
    if hy2_median <= 0:
        raise ValueError("Hysteria2 median throughput must be positive")
    uplift = (proteus_median / hy2_median - 1) * 100
    cell = "physical-cross-host"
    ci_low, ci_high = helpers.bootstrap_uplift_interval(
        proteus_values, hy2_values, cell
    )
    p_value, permutation_method = helpers.permutation_p_value(
        proteus_values, hy2_values, cell
    )

    server_git = str(metadata.get("server", {}).get("git_commit", ""))
    client_git = str(metadata.get("client_git_commit", ""))
    if not server_git or server_git != client_git:
        raise ValueError(
            "server/client source commits differ: "
            f"server={server_git!r} client={client_git!r}"
        )

    output: list[dict[str, Any]] = []
    for row in proteus_runs:
        output.append(
            {
                "kind": "run",
                "implementation": "proteus-beta-brutal",
                "cell": cell,
                **row,
            }
        )
    for row in hy2_runs:
        output.append(
            {
                "kind": "run",
                "implementation": "hysteria2",
                "cell": cell,
                **row,
            }
        )

    output.append(
        {
            "kind": "cell_summary",
            "cell": cell,
            "attempts_per_implementation": expected_runs,
            "proteus_successes": len(proteus_runs),
            "hy2_successes": len(hy2_runs),
            "proteus_median_mib_per_sec": proteus_median,
            "hy2_median_mib_per_sec": hy2_median,
            "proteus_uplift_pct": uplift,
            "proteus_uplift_bootstrap_95pct_low": ci_low,
            "proteus_uplift_bootstrap_95pct_high": ci_high,
            "permutation_p_value_two_sided": p_value,
            "permutation_method": permutation_method,
            "probability_proteus_exceeds_hy2": helpers.probability_of_superiority(
                proteus_values, hy2_values
            ),
            "proteus_client_cpu_sec_per_run": median_resource(
                proteus_resources, "cpu_usage_usec", 1_000_000
            ),
            "hy2_client_cpu_sec_per_run": median_resource(
                hy2_resources, "cpu_usage_usec", 1_000_000
            ),
            "proteus_client_rss_after_run_mib": median_resource(
                proteus_resources, "rss_after_kib", 1024
            ),
            "hy2_client_rss_after_run_mib": median_resource(
                hy2_resources, "rss_after_kib", 1024
            ),
            "server_recovery_counters_available": bool(server_recovery),
            "formal_eligible": bool(metadata.get("formal_eligible", False))
            and bool(server_recovery),
        }
    )
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dir", type=Path)
    args = parser.parse_args()
    try:
        rows = summarize(args.results_dir)
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"cross-host summary rejected: {error}", file=sys.stderr)
        return 1
    output = args.results_dir / "summary.jsonl"
    with output.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, separators=(",", ":")) + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

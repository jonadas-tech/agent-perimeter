"""Re-identification safeguards for published study datasets.

The input brand list is public, so anonymized records must not be linkable back to it by
record order or by sector cells that contain only a handful of brands.
"""

from __future__ import annotations

import random
from collections import Counter

from agentic_perimeter.study import (
    MIN_CELL_SIZE,
    anonymize_batch_results,
    assign_random_anon_ids,
    build_study_from_records,
    coarsen_small_sectors,
)


def _report(i: int, cohort: str, sector: str) -> dict:
    return {
        "target": {"domain": f"brand{i}.example", "brand": f"brand{i}", "sector": sector, "cohort": cohort},
        "score": {
            "control_posture_applicable": i % 2 == 0,
            "control_posture_score": (i * 7) % 100 if i % 2 == 0 else None,
            "control_posture_grade": "C" if i % 2 == 0 else "N/A",
            "threat_pressure_score": i % 60,
            "threat_pressure_level": "Moderate",
            "action_posture": "Action Required",
        },
        "findings": [],
        "vector1": {"flags": {"has_any_mcp_footprint": i % 3 == 0}},
        "vector2": {"flags": {"live_mcp_endpoint_count": i % 4 == 0}},
        "vector3": {"flags": {}},
    }


def _batch() -> dict:
    sectors = (
        [("fortune_traditional", "Banking")] * 8
        + [("fortune_traditional", "Insurance")] * 3
        + [("fortune_traditional", "Aerospace")] * 3
        + [("saas_ai_fintech", "Cloud & DevTools")] * 6
        + [("saas_ai_fintech", "Cybersecurity")] * 3
        + [("saas_ai_fintech", "Enterprise SaaS")] * 7
    )
    return {
        "tool_version": "test",
        "reports": [_report(i, c, s) for i, (c, s) in enumerate(sectors)],
    }


def test_anon_ids_are_not_assigned_in_input_order() -> None:
    batch = _batch()
    input_order = [r["target"]["sector"] for r in batch["reports"] if r["target"]["cohort"] == "fortune_traditional"]
    study = anonymize_batch_results(batch, rng=random.Random(7))
    ent = [r for r in study["anonymized_records"] if r["anon_id"].startswith("ENT-")]
    assert [r["anon_id"] for r in ent] == [f"ENT-{i:03d}" for i in range(1, len(ent) + 1)]
    published_order = [r["threat_pressure_score"] for r in ent]
    original_order = [rep["score"]["threat_pressure_score"] for rep in batch["reports"][: len(input_order)]]
    assert published_order != original_order
    assert sorted(published_order) == sorted(original_order)


def test_every_published_sector_cell_meets_minimum_size() -> None:
    study = anonymize_batch_results(_batch(), rng=random.Random(1))
    cells = Counter((r["cohort"], r["sector"]) for r in study["anonymized_records"])
    assert all(n >= MIN_CELL_SIZE for n in cells.values()), cells
    sectors = {s for (_c, s) in cells}
    assert "Cybersecurity" not in sectors and "Insurance" not in sectors
    assert "Cloud, DevTools & Security" in sectors
    assert "Other traditional sectors" in sectors
    assert all(sdata["count"] >= MIN_CELL_SIZE for sdata in study["by_sector"].values())


def test_rekeying_preserves_every_overall_and_cohort_aggregate() -> None:
    original = anonymize_batch_results(_batch(), rng=random.Random(3))
    records = [dict(r) for r in original["anonymized_records"]]
    rekeyed = build_study_from_records(
        assign_random_anon_ids(coarsen_small_sectors(records), rng=random.Random(99)),
        {"tool_version": "test"},
    )
    assert rekeyed["overall"] == original["overall"]
    assert rekeyed["by_cohort"] == original["by_cohort"]


def test_sector_posture_mean_is_suppressed_when_fewer_than_min_cell_brands_are_graded() -> None:
    study = anonymize_batch_results(_batch(), rng=random.Random(5))
    for sdata in study["by_sector"].values():
        if sdata["graded_posture_count"] < MIN_CELL_SIZE and sdata["graded_posture_count"] > 0:
            assert sdata["mean_control_posture"] is None
            assert sdata["control_posture_suppressed"] is True


def test_small_private_batches_suppress_sector_table_instead_of_failing() -> None:
    batch = {"reports": [_report(i, "custom", "Retail") for i in range(2)]}
    study = anonymize_batch_results(batch, rng=random.Random(0))
    assert study["overall"]["count"] == 2
    assert study["by_sector"] == {}
    assert study["anonymization"]["suppressed_sector_records"] == 2

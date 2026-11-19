"""Construct packet groups and score frozen learned or conventional candidates."""

import math

import numpy as np
from scipy.optimize import linear_sum_assignment


def fixed_windows(source, seconds):
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("Expected a positive finite window length")
    begin, stop = source["observed_scope"]
    times = np.asarray([p[0] for p in source["packets"]])
    if np.any(np.diff(times) < 0):
        raise ValueError("Packets must be time ordered")
    groups = []
    for tick in range(math.floor(begin) + 1, math.ceil(stop) + 1):
        right = min(float(tick), stop)
        left = max(begin, right - seconds)
        lo = int(times.searchsorted(left))
        hi = int(times.searchsorted(right, side="right" if right == stop else "left"))
        if hi > lo:
            groups.append(
                dict(
                    packet_indices=list(range(lo, hi)),
                    start=left,
                    end=right,
                    time=float((times[lo] + times[hi - 1]) / 2),
                )
            )
    return groups


def silence_groups(source, gap, max_span=5.0):
    """First packet opens; silence closes; hard cap never extends on arrivals."""
    if not np.isfinite(gap) or not np.isfinite(max_span) or gap <= 0 or max_span <= 0:
        raise ValueError("Positive finite gap and maximum span required")
    packets = source["packets"]
    groups, ids = [], []
    end_scope = source["observed_scope"][1]

    def close(reason):
        start, end = packets[ids[0]][0], packets[ids[-1]][0]
        groups.append(
            dict(
                packet_indices=list(ids),
                start=float(start),
                end=float(end),
                time=float((start + end) / 2),
                closed_at=float(min(end_scope, end + gap, start + max_span)),
                close_reason=reason,
            )
        )

    for i, packet in enumerate(packets):
        t = packet[0]
        if ids:
            if t < packets[ids[-1]][0]:
                raise ValueError("Packets must be time ordered")
            if t - packets[ids[0]][0] >= max_span or t - packets[ids[-1]][0] > gap:
                reason = (
                    "cap"
                    if packets[ids[0]][0] + max_span <= packets[ids[-1]][0] + gap
                    else "silence"
                )
                close(reason)
                ids = []
        ids.append(i)
    if ids:
        start, end = packets[ids[0]][0], packets[ids[-1]][0]
        reason = (
            "scope_end"
            if end_scope < min(end + gap, start + max_span)
            else ("cap" if start + max_span <= end + gap else "silence")
        )
        close(reason)
    return groups


def first_hit_indices(rows, labels, distance=2.0):
    """Keep first accepted result; suppressed results never extend cooldown."""
    last = {}
    kept = []
    for i in sorted(range(len(rows)), key=lambda i: (rows[i]["time"], i)):
        label = labels[i]
        if label in {"__background__", "__uncertain__", "__unavailable__"}:
            continue
        key = rows[i]["source_id"], label
        t = rows[i]["time"]
        if key not in last or t - last[key] >= distance:
            kept.append(i)
            last[key] = t
    return sorted(kept)


def _ids(values, name):
    if (
        not values
        or list(values) != sorted(set(values))
        or any(type(i) is not int or i < 0 for i in values)
    ):
        raise ValueError("Invalid " + name)
    return set(values)


def reference_cores(reference):
    """Return alternatives for ONE event; validate the full member partition."""
    allowed = _ids(reference["packet_indices"], "positive members")
    required_values = reference.get("required_packet_indices", reference["packet_indices"])
    required = _ids(required_values, "required members")
    optional_values = reference.get("optional_packet_indices", [])
    optional = set(optional_values)
    if (
        list(optional_values) != sorted(optional)
        or required & optional
        or required | optional != allowed
    ):
        raise ValueError("Required/optional members must partition the annotated event")
    cores = [list(required_values)]
    for alternative in reference.get("equivalent_first_stage_cores", []):
        if not _ids(alternative, "alternative core") <= allowed:
            raise ValueError("Alternative core includes unannotated members")
        if alternative not in cores:
            cores.append(list(alternative))
    return cores


def evaluate_source(references, candidates, negative_indices, *, time_tolerance_seconds=None):
    """Optionally gate association by explicit event times before matching.

    Timed evaluation requires a finite ``time`` on every reference and candidate.
    Time means the estimated event occurrence, not when an output was available.
    Omitting the tolerance preserves the historical member-overlap contract.
    """
    expected = [set(r["packet_indices"]) for r in references]
    actual = [set(c["packet_indices"]) for c in candidates]
    negative = set(negative_indices)
    if any(ids & negative for ids in expected):
        raise ValueError("Conflicting evaluation labels")
    overlap = np.asarray([[len(e & a) for a in actual] for e in expected], dtype=float).reshape(
        len(expected), len(actual)
    )
    reviewed = any("required_packet_indices" in r for r in references)
    core_valid = (
        np.asarray(
            [
                [
                    bool(a <= e and any(set(core) <= a for core in reference_cores(r)))
                    for a in actual
                ]
                for r, e in zip(references, expected)
            ],
            dtype=bool,
        ).reshape(len(expected), len(actual))
        if reviewed
        else None
    )
    time_error = None
    if time_tolerance_seconds is not None:
        tolerance = float(time_tolerance_seconds)
        if not np.isfinite(tolerance) or tolerance < 0:
            raise ValueError("A finite nonnegative time tolerance is required")
        try:
            ref_times = np.asarray([r["time"] for r in references], dtype=float)
            candidate_times = np.asarray([c["time"] for c in candidates], dtype=float)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Timed evaluation requires explicit numeric event times") from exc
        if not np.isfinite(ref_times).all() or not np.isfinite(candidate_times).all():
            raise ValueError("Event times must be finite")
        time_error = candidate_times[None, :] - ref_times[:, None]
        eligible = np.abs(time_error) <= tolerance
        overlap = np.where(eligible, overlap, 0.0)
        if reviewed:
            core_valid = core_valid & eligible
    pairs = []
    if expected and actual:
        weights = overlap + (overlap.sum() + 1) * core_valid if reviewed else overlap
        aa, bb = linear_sum_assignment(-weights)
        pairs = [(int(i), int(j)) for i, j in zip(aa, bb) if overlap[i, j] > 0]
    used = {j for i, j in pairs}
    matches = []
    for i, j in pairs:
        e, a = expected[i], actual[j]
        matches.append(
            dict(
                sample_id=references[i]["sample_id"],
                candidate=j,
                expected_members=len(e),
                recovered_members=len(e & a),
                extra_members=len(a - e),
                full_members=e <= a,
                exact_members=e == a,
                truth=references[i]["action"],
                prediction=candidates[j]["prediction"],
                correct=candidates[j]["prediction"] == references[i]["action"],
            )
        )
        if reviewed:
            matches[-1]["complete_core"] = bool(core_valid[i, j])
        if time_error is not None:
            matches[-1]["time_error_seconds"] = float(time_error[i, j])
    categories = []
    for j, a in enumerate(actual):
        if j in used:
            category = "matched"
        elif any(a & e for e in expected):
            category = "duplicate"
        elif a and a <= negative:
            category = "known_background"
        else:
            category = "unadjudicated"
        categories.append(category)
    accepted = [
        c.get("prediction") not in ("__background__", "__uncertain__", "__unavailable__")
        for c in candidates
    ]
    result = dict(
        stage1=dict(
            references=len(references),
            candidates=len(candidates),
            hits=len(matches),
            misses=len(references) - len(matches),
            full_member_hits=sum(m["full_members"] for m in matches),
            exact_member_hits=sum(m["exact_members"] for m in matches),
            known_background_outputs=categories.count("known_background"),
            duplicate_outputs=categories.count("duplicate"),
            unadjudicated_outputs=categories.count("unadjudicated"),
        ),
        stage2_conditional=dict(
            candidates_matched_to_reference=len(matches), correct=sum(m["correct"] for m in matches)
        ),
        end_to_end=dict(
            reference_denominator=len(references),
            correct=sum(m["correct"] for m in matches),
            accepted_outputs=sum(accepted),
            known_background_false_positives=sum(
                a and c == "known_background" for a, c in zip(accepted, categories)
            ),
            duplicate_outputs=sum(a and c == "duplicate" for a, c in zip(accepted, categories)),
            unadjudicated_outputs=sum(
                a and c == "unadjudicated" for a, c in zip(accepted, categories)
            ),
        ),
        matches=matches,
        output_categories=categories,
        matching_contract="One-to-one maximum member overlap; any overlap is a hit, full/exact recovery reported separately. Unresolved actions excluded from identifiable-reference recall, not treated as background.",
    )
    if reviewed:
        cores = sum(m["complete_core"] for m in matches)
        result["stage1"].update(core_member_hits=cores, core_member_misses=len(references) - cores)
        result["matching_contract"] = (
            "One event per matched candidate; prioritize complete required alternatives without background contamination, then member overlap. Core success, full optional-member recovery and exact full membership are separate."
        )
    if time_error is not None:
        result["time_tolerance_seconds"] = tolerance
        result["matching_contract"] += (
            " Require abs(candidate time - reference time) <= tolerance before label-independent association; class correctness is assessed after matching."
        )
    return result

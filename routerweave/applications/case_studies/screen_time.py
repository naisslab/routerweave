"""Publish Screen Time records and score one device timeline at a time."""

from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from .activity_timeline import DWELL_SECONDS, LABELS, STEP, Segment


@dataclass(frozen=True)
class Publication:
    start: float
    end: float
    label: str
    published_at: float


def publish(ends, experts, available, immediate_probabilities, delayed_probabilities):
    """Decode frozen temporal-head outputs on a five-second observation grid.

    The three expert rows correspond to 5, 10 and 30 seconds. Delayed rows
    contain the transport-corrected probabilities for each target interval.
    """
    ends = np.asarray(ends, dtype=float)
    available = np.asarray(available)
    if (ends.ndim != 1 or not len(ends) or not np.isfinite(ends).all()
            or np.any(np.diff(ends) != STEP)):
        raise ValueError("Expected consecutive five-second observation ends")
    if available.shape != (len(ends), 3) or not np.isin(available, [False, True]).all():
        raise ValueError("Expected three scale availability flags per slot")

    def winners(probabilities, shape):
        values = np.asarray(probabilities)
        if (values.shape != shape or not np.isfinite(values).all() or (values < 0).any()
                or not np.allclose(values.sum(axis=-1), 1, atol=1e-5)):
            raise ValueError("Expected normalized class probabilities")
        return values.argmax(axis=-1)

    shape = (len(ends), len(LABELS))
    instant = winners(immediate_probabilities, shape)
    delayed = winners(delayed_probabilities, shape)
    scales = winners(experts, (len(ends), 3, len(LABELS)))
    stable = np.r_[False, instant[1:] == instant[:-1]]
    eligible = stable & available.all(axis=1) & (scales == instant[:, None]).all(axis=1)
    immediate_records = []
    final_records = []
    last_publication = -float("inf")
    for i, end in enumerate(ends):
        guess = instant[i]
        immediate_records.append(Publication(end - STEP, end, LABELS[guess], end))
        # Check only the three observations before this target's deadline.
        # At end-of-stream, unresolved targets still wait the full 15 seconds.
        label, ready = delayed[i], end + 3 * STEP
        for j in range(i, min(i + 3, len(ends))):
            if eligible[j] and instant[j] == guess:
                label, ready = guess, ends[j]
                break
        last_publication = max(ready, last_publication)
        final_records.append(Publication(end - STEP, end, LABELS[label], last_publication))
    return immediate_records, final_records


def merge_intervals(records, *, start=None, end=None, as_of=None):
    """Return published activity intervals clipped to the requested history period."""
    if start is not None and end is not None and start > end:
        raise ValueError("History start exceeds its end")
    intervals = []
    for r in records:
        if as_of is not None and r.published_at > as_of:
            continue
        left = r.start if start is None else max(start, r.start)
        right = r.end if end is None else min(end, r.end)
        if left >= right:
            continue
        if intervals and left < intervals[-1].end:
            raise ValueError("Overlapping activity records")
        if intervals and left == intervals[-1].end and intervals[-1].label == r.label:
            intervals[-1] = Segment(intervals[-1].start, right, r.label)
        else:
            intervals.append(Segment(left, right, r.label))
    return intervals


def score_timeline(layout, records, initial_prediction):
    """Score labeled seconds and match old/new label pairs on publication time.

    The replay initializes switch counting with the first 30-second expert's
    winner. Unknown spans break reference adjacency and contribute no seconds.
    """
    if initial_prediction not in LABELS or not records:
        raise ValueError("Missing initial prediction or publication history")
    if any(a.end > b.start for a, b in zip(layout, layout[1:])):
        raise ValueError("Reference intervals overlap or are out of order")
    if any(r.published_at < r.end or not np.isfinite(r.published_at) for r in records):
        raise ValueError("Invalid publication time")
    if any(a.published_at > b.published_at for a, b in zip(records, records[1:])):
        raise ValueError("Publication time moved backwards")
    if any(a.end > b.start for a, b in zip(records, records[1:])):
        raise ValueError("Overlapping or unordered published slots")
    confusion = np.zeros((len(LABELS), len(LABELS)))
    cursor = 0
    known = [s for s in layout if s.label is not None and not s.warmup]
    for span in known:
        while cursor < len(records) and records[cursor].end <= span.start:
            cursor += 1
        j = cursor
        while j < len(records) and records[j].start < span.end:
            pred = records[j]
            seconds = min(span.end, pred.end) - max(span.start, pred.start)
            confusion[LABELS.index(span.label), LABELS.index(pred.label)] += seconds
            j += 1
    if not len(known) or not np.isclose(confusion.sum(), sum(s.end - s.start for s in known),
                                       rtol=0, atol=1e-7):
        raise ValueError("Published slots must cover all scored reference time")
    true_changes = [(b.start, a.label, b.label) for a, b in zip(known, known[1:])
                    if a.end == b.start and a.label != b.label]
    changes = defaultdict(list)
    previous = initial_prediction
    for record in records:
        if record.label != previous:
            changes[previous, record.label].append(record.published_at)
        previous = record.label
    predicted_count = sum(map(len, changes.values()))
    delays = []
    for index, (start, old, new) in enumerate(true_changes):
        next_start = true_changes[index + 1][0] if index + 1 < len(true_changes) else records[-1].end
        deadline = min(start + 30, next_start)
        candidates = changes[old, new]
        for j, clock in enumerate(candidates):
            if clock > deadline:
                break
            if clock >= start:
                delays.append(clock - start)
                del candidates[j]
                break
    return dict(confusion_seconds=confusion, reference_changes=len(true_changes),
                published_changes=predicted_count, matched_delays=delays)


def _history_summary(rows, *, include_duration=False):
    """Pool seconds for accuracy and weight timelines equally for IoU and MAE."""
    matrices = np.stack([row["confusion_seconds"] for row in rows])
    reference = matrices.sum(axis=2)
    predicted = matrices.sum(axis=1)
    correct = matrices.diagonal(axis1=1, axis2=2)
    union = reference + predicted - correct
    iou = np.divide(correct, union, out=np.zeros_like(correct), where=union > 0)
    table = dict(timelines=len(rows), scored_seconds=float(matrices.sum()),
                 accuracy=float(correct.sum() / matrices.sum()),
                 temporal_iou=float((iou.sum(axis=1) / (union > 0).sum(axis=1)).mean()))
    if include_duration:
        errors = predicted[:, 1:].sum(axis=1) - reference[:, 1:].sum(axis=1)
        table["active_duration_mae_seconds"] = float(np.abs(errors).mean())
    return table


def evaluate_screen_time(layout, ends, experts, available, immediate_probabilities, delayed_probabilities):
    """Compute application durations from records and evaluation scores from labeled time."""
    immediate, final = publish(ends, experts, available, immediate_probabilities, delayed_probabilities)
    initial = LABELS[np.argmax(experts[0][2])]
    result = {}
    for name, publications in (("immediate", immediate), ("delayed", final)):
        scored = score_timeline(layout, publications, initial)
        history = merge_intervals(publications, start=layout[0].start, end=layout[-1].end)
        durations = dict.fromkeys(LABELS, 0.0)
        for interval in history:
            durations[interval.label] += interval.end - interval.start
        result[name] = dict(publications=publications, intervals=history,
                            duration_seconds=durations, scores=scored)
    return result


def summarize_study(cases):
    """Summarize (platform, saved layout profile, evaluate_screen_time result) triples."""
    retrospective = []
    by_platform = defaultdict(list)
    by_dwell = defaultdict(list)
    immediate = []
    for platform, profile, result in cases:
        final = result["delayed"]["scores"]
        retrospective.append(final)
        by_platform[platform].append(final)
        if profile == "real_guided":
            continue
        dwell = profile.removeprefix("variable_")
        if dwell not in DWELL_SECONDS:
            raise ValueError(f"Unknown duration profile {profile!r}")
        by_dwell[dwell].append(final)
        immediate.append(result["immediate"]["scores"])

    if not retrospective:
        raise ValueError("At least one timeline is required")
    live = None
    if immediate:
        confusion = np.sum([row["confusion_seconds"] for row in immediate], axis=0)
        changes = sum(row["reference_changes"] for row in immediate)
        published = sum(row["published_changes"] for row in immediate)
        delays = [delay for row in immediate for delay in row["matched_delays"]]
        live = dict(timelines=len(immediate), scored_seconds=float(confusion.sum()),
                    accuracy=float(confusion.trace() / confusion.sum()),
                    reference_changes=changes, published_changes=published, matched_changes=len(delays),
                    switch_recall=len(delays) / changes if changes else None,
                    switch_precision=len(delays) / published if published else None,
                    mean_matched_delay_seconds=float(np.mean(delays)) if delays else None)
    return dict(retrospective=_history_summary(retrospective, include_duration=True),
                by_platform={p: _history_summary(rows) for p, rows in by_platform.items()},
                by_activity_duration={d: _history_summary(rows) for d, rows in by_dwell.items()},
                live_monitoring=live)

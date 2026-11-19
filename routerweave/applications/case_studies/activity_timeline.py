"""Construct single-device Screen Time workloads from recorded excerpts."""

from bisect import bisect_left
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from math import ceil, isfinite

import numpy as np


LABELS = ("background", "browsing", "live_stream", "long_video", "music", "short_video")
STEP = 5
WARMUP = 60
DWELL_SECONDS = {"fast": (10, 30), "medium": (30, 90), "slow": (120, 300)}


@dataclass(frozen=True)
class Recording:
    """One source from the chosen platform and split, in original pool order."""

    source_id: str
    label: str
    intervals: tuple[tuple[float, float], ...]
    app: str = ""


@dataclass(frozen=True)
class Segment:
    start: float
    end: float
    label: str | None
    source_id: str | None = None
    source_start: float | None = None
    warmup: bool = False

    def __post_init__(self):
        if not (isfinite(self.start) and isfinite(self.end) and self.start < self.end):
            raise ValueError("Expected a positive finite interval")
        if self.label is not None and self.label not in LABELS:
            raise ValueError(f"Unknown activity {self.label!r}")


def _allocate(blocks, sources, seed, group_apps):
    sources = tuple(sources)
    spans = {s.source_id: sorted(s.intervals) for s in sources}
    if len(spans) != len(sources):
        raise ValueError("Duplicate recording ID")
    for intervals in spans.values():
        last = -float("inf")
        for a, b in intervals:
            if not (isfinite(a) and isfinite(b) and last <= a < b):
                raise ValueError("Invalid or overlapping source coverage")
            last = b
    by_label = defaultdict(list)
    for source in sources:
        by_label[source.label].append(source)
    for attempt in range(20 if group_apps else 1):
        rng = np.random.default_rng(seed + attempt * 10_000)
        free = {key: value.copy() for key, value in spans.items()}
        result = []
        for block in blocks:
            if block.label is None:
                result.append(block)
                continue
            first = not result
            length = block.end - block.start + (WARMUP if first else 0)
            eligible = [s for s in by_label[block.label]
                        if any(b - a >= length for a, b in free[s.source_id])]
            if not eligible:
                break
            if group_apps:
                apps = sorted({s.app for s in eligible})
                app = apps[rng.integers(len(apps))]
                eligible = [s for s in eligible if s.app == app]
            source = eligible[rng.integers(len(eligible))]
            slots = free[source.source_id]
            choices = [i for i, (a, b) in enumerate(slots) if b - a >= length]
            a, b = slots.pop(choices[rng.integers(len(choices))])
            begin = rng.uniform(a, b - length) if b - a > length else a
            if a < begin:
                slots.append((a, begin))
            if begin + length < b:
                slots.append((begin + length, b))
            if first:
                result.append(Segment(0, WARMUP, block.label, source.source_id, begin, True))
                begin += WARMUP
            result.append(Segment(block.start, block.end, block.label, source.source_id, begin))
        else:
            return result
    raise ValueError("Insufficient nonoverlapping recording time for this layout")


def random_timeline(seed, profile, sources):
    """Draw a 15–30 minute layout and allocate disjoint, app-grouped crops."""
    low, high = DWELL_SECONDS[profile]
    parameters = np.random.default_rng(seed + 73_000_000)
    remaining = STEP * int(parameters.integers(180, 361))
    background = parameters.uniform(0.05, 0.35)
    weights = np.r_[background, (1 - background) * parameters.dirichlet(np.full(5, 2.0))]
    rng = np.random.default_rng(seed)
    blocks = []
    start = WARMUP
    previous = None
    while remaining:
        legal = [n for n in range(low, min(high, remaining) + 1, STEP)
                 if ceil((remaining - n) / high) <= (remaining - n) // low]
        duration = int(rng.choice(legal))
        probabilities = weights.copy()
        if previous is not None:
            probabilities[previous] = 0
        previous = int(rng.choice(len(LABELS), p=probabilities / probabilities.sum()))
        blocks.append(Segment(start, start + duration, LABELS[previous]))
        start += duration
        remaining -= duration
    return _allocate(blocks, sources, seed + 50, True)


def guided_timeline(template, sources):
    """Use retained LSApp timings and synthetic activity assignments."""
    blocks = [Segment(WARMUP + r["start_s"], WARMUP + r["end_s"], r["synthetic_activity"])
              for r in template["segments"]]
    blocks.extend(Segment(WARMUP + r["start_s"], WARMUP + r["end_s"], None)
                  for r in template["gaps"])
    blocks.sort(key=lambda b: b.start)
    if (not blocks or blocks[0].start != WARMUP or blocks[0].label is None
            or blocks[-1].end != WARMUP + template["elapsed_s"]
            or any(a.end != b.start for a, b in zip(blocks, blocks[1:]))):
        raise ValueError("Template must cover the elapsed time, including explicit gaps")
    seed = int(sha256(template["trace_id"].encode()).hexdigest()[:8], 16)
    return _allocate(blocks, sorted(sources, key=lambda s: s.source_id), seed, False)


def replay_packets(layout, recordings: Mapping):
    """Yield (time, namespaced flow, metadata) from chronological source rows.

    Each input row is (source time, flow ID, metadata). Supply service metadata
    associated in the original recording so that a crop keeps earlier evidence.
    """
    previous = None
    namespace = 0
    for block in layout:
        if block.label is None:
            continue
        if block.source_start is None or block.source_id is None:
            raise ValueError("Labeled block is missing its recording crop")
        continues_warmup = (previous is not None and previous.warmup
                            and previous.source_id == block.source_id
                            and previous.end == block.start
                            and previous.source_start + (previous.end - previous.start) == block.source_start)
        if not continues_warmup:
            namespace += 1
        rows = recordings[block.source_id]
        start = block.source_start
        first = bisect_left(rows, start, key=lambda row: row[0])
        stop = bisect_left(rows, start + (block.end - block.start), key=lambda row: row[0])
        for i in range(first, stop):
            timestamp, flow, metadata = rows[i]
            yield block.start + (timestamp - start), (namespace, flow), metadata
        previous = block

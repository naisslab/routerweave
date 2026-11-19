"""Prepare operation-labelled classifier inputs from frozen localizer predictions."""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass

import numpy as np

from .supervision import reviewed_indices


BACKGROUND = "__background__"
OPERATION = {
    "power_on": "power_operation", "power_off": "power_operation",
    "fan_speed_up": "fan_speed", "fan_speed_down": "fan_speed",
    "lock": "lock_operation", "unlock": "lock_operation",
    "curtain_open": "curtain_operation", "curtain_close": "curtain_operation",
    "brightness_up": "brightness", "brightness_down": "brightness",
    "volume_up": "volume", "volume_down": "volume",
    "play": "playback_control", "pause": "playback_control",
    "live_view_start": "video_active", "live_view_stop": "video_active",
    "talk_session": "video_active",
}


@dataclass
class Reference:
    members: set
    cores: list
    label: str


def reference_groups(sample):
    groups, negative = reviewed_indices(sample)
    references = []
    for group, ref in zip(groups, sample["references"]):
        members = set(group)
        required = set(ref.get("required_packet_indices", group))
        optional = set(ref.get("optional_packet_indices", []))
        if not required or required & optional or required | optional != members:
            raise ValueError("Required and optional members must partition the fingerprint")
        cores = [required, *(set(core) for core in ref.get("equivalent_first_stage_cores", []))]
        if any(not core or not core <= members for core in cores):
            raise ValueError("Invalid alternative fingerprint core")
        action = ref["original_action"]
        if not action or action.startswith("__"):
            raise ValueError("An annotated event needs an operation label")
        label = sample["device_type"] + "/" + OPERATION.get(action, action)
        references.append(Reference(members, cores, label))
    return references, negative


def candidate_label(ids, references, negative):
    members = set(ids)
    if members <= negative:
        return BACKGROUND
    owners = [ref for ref in references if members & ref.members]
    if len(owners) != 1:
        return None
    ref = owners[0]
    if not members <= (ref.members | negative):
        return None
    if members <= ref.members or any(core <= members for core in ref.cores):
        return ref.label
    return None


def background_groups(traffic, negative):
    by_burst = defaultdict(list)
    for i, burst in enumerate(traffic.bursts):
        by_burst[int(burst)].append(i)
    remaining = negative.copy()
    for burst in sorted(by_burst):
        ids = by_burst[burst]
        if negative.issuperset(ids):
            yield ids
            remaining.difference_update(ids)
    for i in sorted(remaining):
        yield [i]


def augmented_members(times, members, negative, rng):
    """Add up to eight known background units within one second of the event."""
    ids = sorted(members)
    start, end = times[ids[0]], times[ids[-1]]
    pool = [i for i in range(bisect_left(times, start - 1), bisect_right(times, end + 1))
            if i in negative]
    if not pool:
        return
    nearest = sorted(pool, key=lambda i: max(start - times[i], times[i] - end, 0))
    for use_nearest in (True, False):
        count = int(rng.integers(1, min(8, len(pool)) + 1))
        extra = nearest[:count] if use_nearest else rng.choice(pool, count, replace=False)
        yield sorted(members.union(extra))


@dataclass
class TrainingRow:
    device: str
    label: str
    ids: tuple
    features: tuple


def sample_rows(sample, traffic, candidates, rng, counts):
    """Deduplicate member sets within each training sample, across all sources."""
    if sample["role"] != "train":
        raise ValueError("Expected a training sample")
    refs, negative = reference_groups(sample)
    if set(sample.get("protected_indices", [])) & negative:
        raise ValueError("Protected packets cannot be known background")
    seen = set()
    base, extra = [], []

    def add(ids, rows):
        key = tuple(sorted(ids))
        label = candidate_label(key, refs, negative)
        if label is None or key in seen:
            return label
        seen.add(key)
        rows.append(TrainingRow(sample["device_id"], label, key, traffic.candidate(key)))
        return label

    for candidate in candidates:
        counts["locator_candidates"] += 1
        label = add(candidate.packet_indices, base)
        counts["labelled_locator_candidates"] += label is not None
    for ref in refs:
        add(ref.members, base)
    for ids in background_groups(traffic, negative):
        add(ids, base)
    for ref in refs:
        for ids in augmented_members(traffic.times, ref.members, negative, rng):
            add(ids, extra)
    return base, extra


def normalization(rows):
    """Estimate feature scales on the original rows, before background augmentation."""
    count = sum(len(r.features[0]) for r in rows)
    mean = sum(r.features[0].sum(0, dtype=np.float64) for r in rows) / count
    variance = sum(((r.features[0] - mean) ** 2).sum(0, dtype=np.float64) for r in rows) / count
    result = dict(token_mean=mean.astype(np.float32),
                  token_scale=np.sqrt(variance).clip(.05).astype(np.float32))
    for index, name in [(1, "flat"), (2, "context")]:
        values = np.stack([r.features[index] for r in rows])
        result[name + "_mean"] = values.mean(0, dtype=np.float64).astype(np.float32)
        result[name + "_scale"] = values.std(0, dtype=np.float64).clip(.1).astype(np.float32)
    return result

"""Train one localizer on sample-local, reviewed fingerprint membership."""

from dataclasses import dataclass
from collections import defaultdict
from math import ceil
from numbers import Integral

import numpy as np
import torch
from torch.nn import functional as F

from .localizer import Localizer, blocks, clip_inputs
from .traffic_features import Traffic


@dataclass
class Clip:
    traffic: Traffic
    left: int
    right: int
    start_known: np.ndarray
    anchors: list
    members: list


def bind_fingerprints(sample):
    """Bind reviewed observations to this trace before either network is fitted."""
    if sample["role"] != "train":
        raise ValueError("Only training samples may enter fitting")
    if "fingerprints" not in sample:
        return sample
    if "references" in sample:
        raise ValueError("Supply fingerprints or indexed references, not both")

    def key(row):
        # Optional trailing frame and record-offset fields distinguish equal-size units.
        return (round(row[0], 5), *row[1:])

    lookup = defaultdict(list)
    for i, packet in enumerate(sample["packets"]):
        lookup[key(packet)].append(i)
    def align(members):
        indices = []
        for member in members:
            matches = lookup.get(key(member), ())
            if len(matches) != 1:
                raise ValueError("Reviewed fingerprint member has no unique match in the trace")
            indices.append(matches[0])
        if len(indices) != len(set(indices)):
            raise ValueError("Duplicate member in reviewed fingerprint")
        return sorted(indices)

    references = []
    for event in sample["fingerprints"]:
        ids = align(event["members"])
        ref = dict(original_action=event["action"], packet_indices=ids)
        if "optional_members" in event:
            optional = align(event["optional_members"])
            ref["optional_packet_indices"] = optional
            ref["required_packet_indices"] = sorted(set(ids) - set(optional))
        if "equivalent_cores" in event:
            ref["equivalent_first_stage_cores"] = [align(core) for core in event["equivalent_cores"]]
        references.append(ref)
    bound = dict(sample)
    del bound["fingerprints"]
    bound["references"] = references
    return bound


def reviewed_indices(sample):
    """Read the final, reviewed fingerprint indices in this sample's packet order.

    Background is limited to the annotated scope outside protected intervals.
    Unlabelled sensor traffic therefore remains unknown as a possible start.
    """
    packets = sample["packets"]
    length = len(packets)

    def checked(values):
        ids = set(values)
        if len(ids) != len(values) or any(not isinstance(i, Integral) or not 0 <= i < length for i in ids):
            raise ValueError("Duplicate or out-of-range annotation index")
        return ids

    groups = []
    positive = set()
    for reference in sample["references"]:
        ids = checked(reference["packet_indices"])
        if not ids or ids & positive:
            raise ValueError("Each fingerprint requires a nonempty, disjoint member set")
        positive.update(ids)
        groups.append(sorted(ids))
    negative = checked(sample["negative_indices"])
    if negative & positive:
        raise ValueError("A fingerprint member is also labelled background")
    if sample.get("supervision_policy") == "complete_nonfingerprint_background":
        scope = checked(sample["supervision_scope_indices"])
        times = np.asarray([p[0] for p in packets])
        protected = set()
        for start, end in sample["unknown_intervals"]:
            if not np.isfinite([start, end]).all() or end < start:
                raise ValueError("Invalid protected interval")
            protected.update(np.flatnonzero((times >= start) & (times <= end)))
        if negative != scope - positive - protected:
            raise ValueError("Background labels disagree with the reviewed scope")
    return groups, negative


def training_clips(samples, device_id, owned=256):
    reviewed = []
    span = 0
    for sample in samples:
        sample = bind_fingerprints(sample)
        if sample["role"] != "train" or sample["device_id"] != device_id:
            raise ValueError("Training requires one physical device and training samples only")
        traffic = Traffic(sample["packets"])
        groups, negative = reviewed_indices(sample)
        for group in groups:
            span = max(span, group[-1] - group[0] + 1)
        reviewed.append((traffic, groups, negative))
    if not span:
        raise ValueError("At least one reviewed positive fingerprint is required")
    context = max(128, span)
    clips = []
    for traffic, groups, negative in reviewed:
        known = negative.union(*(set(group) for group in groups))
        for start, stop, left, right in blocks(len(traffic.times), owned, context):
            events = [group for group in groups if start <= group[0] < stop]
            if not events and not any(start <= i < stop for i in negative):
                continue
            start_known = np.asarray([start <= i < stop and i in known for i in range(left, right)])
            members = [[i - left for i in group] for group in events]
            clips.append(Clip(traffic, left, right, start_known, [g[0] for g in members], members))
    return clips, context


def balanced_loss(logits, truth):
    terms = [F.softplus(-logits[truth]), F.softplus(logits[~truth])]
    return torch.stack([v.mean() for v in terms if v.numel()]).mean()


def hardest(values, count=8):
    return values.topk(min(count, values.numel())).values.mean()


def clip_loss(model, clip, mean, scale):
    """Use the first fingerprint member as start and the last as the end class.

    Start supervision masks unknown positions. For an annotated anchor, its
    fingerprint supplies the full member set, including noncontiguous members.
    """
    device = next(model.parameters()).device
    x, flows, bursts, times = clip_inputs(clip.traffic, clip.left, clip.right, mean, scale, device)
    hidden, starts = model(x, flows, bursts)
    anchors = torch.as_tensor(clip.anchors, dtype=torch.long, device=device)
    known = torch.as_tensor(clip.start_known, device=device)
    truth = torch.zeros_like(known)
    truth[anchors] = True
    value = balanced_loss(starts[known], truth[known])
    negatives = starts[known & ~truth]
    hard_start = hardest(F.softplus(negatives)) if negatives.numel() else None
    if not len(anchors):
        return value, hard_start

    member, end = model.member_and_end_logits(hidden, anchors, times, flows, bursts)
    member_losses = []
    for row, (anchor, ids) in enumerate(zip(clip.anchors, clip.members)):
        logits = member[row, anchor:]
        target = torch.zeros_like(logits, dtype=torch.bool)
        target[[i - anchor for i in ids]] = True
        loss = balanced_loss(logits, target) + 0.5 * hardest(F.softplus(-logits[target]))
        if (~target).any():
            loss = loss + 0.5 * hardest(F.softplus(logits[~target]))
        member_losses.append(loss)
    last = torch.tensor([ids[-1] for ids in clip.members], device=device)
    return value + torch.stack(member_losses).mean() + F.cross_entropy(end, last), hard_start


def fit_localizer(samples, device_id, *, epochs=None, seed=42, device="cpu", minimum_updates=200):
    """Use the study's update budget unless an explicit epoch count is supplied."""
    if epochs is not None and (not isinstance(epochs, int) or epochs < 1):
        raise ValueError("Expected a positive epoch count")
    if not isinstance(minimum_updates, int) or minimum_updates < 1:
        raise ValueError("Expected a positive minimum number of updates")
    owned, batch_size = 256, 16
    clips, context = training_clips(samples, device_id, owned)
    if epochs is None:
        epochs = max(30, ceil(minimum_updates / ceil(len(clips) / batch_size)))
    arrays = [c.traffic.features[c.left:c.right] for c in clips]
    count = sum(len(a) for a in arrays)
    mean = (sum(a.sum(0, dtype=np.float64) for a in arrays) / count).astype(np.float32)
    variance = sum(((a - mean) ** 2).sum(0, dtype=np.float64) for a in arrays) / count
    scale = np.sqrt(variance).clip(.1).astype(np.float32)
    rng = np.random.default_rng(seed)
    torch.manual_seed(seed)
    model = Localizer().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001)
    order = sorted(range(len(clips)), key=lambda i: len(arrays[i]))
    bucket_size = batch_size * 16
    for _ in range(epochs):
        batches = []
        for offset in range(0, len(order), bucket_size):
            bucket = rng.permutation(order[offset:offset + bucket_size])
            batches.extend(bucket[i:i + batch_size] for i in range(0, len(bucket), batch_size))
        rng.shuffle(batches)
        for batch in batches:
            optimizer.zero_grad()
            losses = [clip_loss(model, clips[i], mean, scale) for i in batch]
            objective = torch.stack([v for v, _ in losses]).mean()
            hard = [h for _, h in losses if h is not None]
            if hard:
                objective = objective + 0.5 * torch.stack(hard).mean()
            if not torch.isfinite(objective):
                raise ValueError("Nonfinite localization loss")
            objective.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5)
            optimizer.step()
    return dict(architecture="anchored_end", arm="B", device_id=device_id, state=model.cpu().state_dict(),
                mean=torch.from_numpy(mean), scale=torch.from_numpy(scale), context=context,
                policy=dict(hidden=32, owned_packets=owned, threshold=.5, epochs=epochs, seed=seed))

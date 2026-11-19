"""Anchor-conditioned start, member and end predictions for one physical device."""

from dataclasses import dataclass
from math import sqrt

import numpy as np
import torch
from torch import nn


@dataclass(frozen=True)
class Candidate:
    anchor: int
    predicted_end: int
    packet_indices: tuple[int, ...]
    start_probability: float


def blocks(length, owned, context):
    for start in range(0, length, owned):
        stop = min(start + owned, length)
        yield start, stop, max(0, start - context), min(length, stop + context)


def group_means(values, groups):
    keys, inverse = torch.unique(groups, return_inverse=True)
    sums = values.new_zeros(len(keys), values.shape[1])
    sums.index_add_(0, inverse, values)
    return (sums / torch.bincount(inverse)[:, None])[inverse]


class Localizer(nn.Module):
    def __init__(self, hidden=32):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(10, hidden), nn.GELU())
        self.structure = nn.Linear(hidden * 3, hidden)
        self.sequence = nn.GRU(hidden, hidden, batch_first=True, bidirectional=True)
        self.packet = nn.Linear(hidden * 2, hidden)
        self.start_head = nn.Linear(hidden, 1)
        self.query = nn.Linear(hidden, hidden)
        self.key = nn.Linear(hidden, hidden)
        self.relative = nn.Sequential(nn.Linear(5, hidden), nn.GELU(), nn.Linear(hidden, 1))
        self.end_query = nn.Linear(hidden, hidden)
        self.end_key = nn.Linear(hidden, hidden)
        self.end_relative = nn.Sequential(nn.Linear(5, hidden), nn.GELU(), nn.Linear(hidden, 1))

    def forward(self, x, flows, bursts):
        encoded = self.encoder(x)
        structure = torch.cat((encoded, group_means(encoded, flows), group_means(encoded, bursts)), -1)
        sequence, _ = self.sequence(self.structure(structure)[None])
        hidden = self.packet(sequence[0])
        return hidden, self.start_head(hidden).squeeze(-1)

    def member_and_end_logits(self, hidden, anchors, times, flows, bursts):
        positions = torch.arange(len(hidden), device=hidden.device)
        distance = positions[None] - anchors[:, None]
        elapsed = times[None] - times[anchors, None]
        relations = torch.stack((
            torch.log1p(elapsed.abs() * 1000), elapsed.sign(),
            torch.log1p(distance.abs().to(hidden.dtype)),
            flows[None] == flows[anchors, None], bursts[None] == bursts[anchors, None],
        ), -1).to(hidden.dtype)
        def scores(query, key, relative):
            attention = query(hidden[anchors]) @ key(hidden).T / sqrt(hidden.shape[-1])
            return attention + relative(relations).squeeze(-1)
        member = scores(self.query, self.key, self.relative).masked_fill(distance < 0, -20)
        end = scores(self.end_query, self.end_key, self.end_relative).masked_fill(distance < 0, -1e9)
        return member, end


def resolve_ownership(proposals):
    owners = {}
    accepted = []
    for anchor, end, start_score, ids, scores in proposals:
        if anchor in owners and owners[anchor][0] >= scores[0]:
            continue
        index = len(accepted)
        accepted.append((anchor, end, start_score))
        for member, score in zip(ids, scores):
            if member not in owners or score > owners[member][0]:
                owners[member] = (score, index)
    members = [[] for _ in accepted]
    for member, (_, index) in sorted(owners.items()):
        members[index].append(member)
    return [Candidate(anchor, end, tuple(ids), score)
            for (anchor, end, score), ids in zip(accepted, members)]


def clip_inputs(traffic, left, right, mean, scale, device):
    times = np.asarray(traffic.times[left:right]) - traffic.times[left]
    return tuple(torch.as_tensor(a, device=device) for a in (
        (traffic.features[left:right] - mean) / scale, traffic.flows[left:right],
        traffic.bursts[left:right], times.astype(np.float32),
    ))


@torch.inference_mode()
def locate(model, traffic, mean, scale, *, context, owned=256, threshold=0.5):
    proposals = []
    device = next(model.parameters()).device
    for start, stop, left, right in blocks(len(traffic.times), owned, context):
        x, flows, bursts, times = clip_inputs(traffic, left, right, mean, scale, device)
        hidden, start_logits = model(x, flows, bursts)
        scores = start_logits.sigmoid()
        positions = torch.arange(right - left, device=device)
        anchors = torch.where((scores >= threshold) & (positions >= start-left) & (positions < stop-left))[0]
        if not len(anchors):
            continue
        logits, ends = model.member_and_end_logits(hidden, anchors, times, flows, bursts)
        probabilities = logits.sigmoid()
        for row, (anchor, end) in enumerate(zip(anchors.tolist(), ends.argmax(1).tolist())):
            if probabilities[row, anchor] < threshold:
                continue
            ids = torch.where((positions >= anchor) & (positions <= end) & (probabilities[row] >= threshold))[0]
            proposals.append((anchor + left, end + left, float(scores[anchor]),
                              (ids + left).tolist(), logits[row, ids].tolist()))
    return resolve_ownership(proposals)

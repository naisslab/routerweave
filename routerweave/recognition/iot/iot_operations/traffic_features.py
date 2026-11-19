"""Traffic features for chronological, device-local canonical transport units."""

from bisect import bisect_left
from collections import defaultdict
from numbers import Integral
import math

import numpy as np


class Traffic:
    """Packet fields are time (s), transport bytes, direction, flow ID and UDP flag."""

    def __init__(self, packets):
        self.packets = packets
        self.times = []
        self.features = np.zeros((len(packets), 10), np.float32)
        self.flows = np.empty(len(packets), np.int64)
        self.bursts = np.empty(len(packets), np.int64)
        connections = {}
        by_flow = defaultdict(list)
        for i, packet in enumerate(packets):
            time, size, direction, flow, udp = packet[:5]
            if (not math.isfinite(time) or (i and time < self.times[-1])
                    or not isinstance(size, Integral) or size <= 0
                    or direction not in (-1, 1) or udp not in (0, 1)):
                raise ValueError(f"Invalid canonical transport unit at index {i}")
            previous = by_flow[flow]
            self.features[i, :5] = (
                np.log1p(size), direction, udp,
                np.log1p((time - self.times[-1]) * 1000) if i else 0,
                np.log1p((time - self.times[previous[-1]]) * 1000) if previous else 0,
            )
            self.times.append(time)
            self.flows[i] = connections.setdefault(flow, len(connections))
            previous.append(i)

        groups = []
        for indices in by_flow.values():
            group = []
            for i in indices:
                if (not group or self.times[i] - self.times[group[-1]] > 0.5
                        or self.times[i] - self.times[group[0]] >= 5):
                    group = []
                    groups.append(group)
                group.append(i)
        groups.sort(key=lambda g: (self.times[g[0]], self.times[g[-1]], g[0]))
        for burst_id, ids in enumerate(groups):
            self.bursts[ids] = burst_id
            start = self.times[ids[0]]
            count = len(ids)
            duration = self.times[ids[-1]] - start
            for position, i in enumerate(ids):
                self.features[i, 5:] = (
                    np.log1p(count), position / max(1, count - 1),
                    np.log1p((self.times[i] - start) * 1000),
                    np.log1p(duration * 1000), float(position == 0),
                )

    def summary(self, ids):
        if not len(ids):
            return np.zeros(40, np.float32)
        rows = [self.packets[i] for i in ids]
        times = np.array([p[0] for p in rows], dtype=float)
        sizes = np.array([p[1] for p in rows], dtype=float)
        direction = np.array([p[2] for p in rows])
        udp = np.array([p[4] for p in rows])
        flows = self.flows[ids]
        directions = defaultdict(set)
        for flow, sign in zip(flows, direction):
            directions[flow].add(sign)
        gaps = np.diff(times) * 1000
        outgoing = direction == 1
        log = np.log1p
        statistics = [
            log(len(ids)), log(sizes.sum()), log((times[-1] - times[0]) * 1000),
            outgoing.mean(), sizes[outgoing].sum() / sizes.sum(), log(len(directions)),
            log(len(np.unique(self.bursts[ids]))), (udp == 0).mean(), (udp == 1).mean(),
            log(sizes.min()), log(sizes.max()), log(sizes.mean()), log(sizes.std()),
            *log(np.quantile(sizes, [.25, .5, .75])),
            log(gaps.mean()) if gaps.size else 0, log(gaps.std()) if gaps.size else 0,
            log(gaps.max()) if gaps.size else 0,
            (direction[1:] != direction[:-1]).mean() if gaps.size else 0,
            (flows[1:] != flows[:-1]).mean() if gaps.size else 0,
            np.mean([len(signs) == 2 for signs in directions.values()]), direction[0], direction[-1],
        ]
        width = min(8, len(ids))
        signed = direction * log(sizes)
        first, last = np.zeros(8), np.zeros(8)
        first[:width], last[-width:] = signed[:width], signed[-width:]
        return np.asarray([*statistics, *first, *last], np.float32)

    def candidate(self, ids):
        """Describe the sparse member list and the history preceding its first member."""
        if not len(ids) or list(ids) != sorted(set(ids)) or ids[0] < 0 or ids[-1] >= len(self.times):
            raise ValueError("Expected a nonempty, ordered set of packet indices")
        ids = np.asarray(ids)
        flows, bursts = self.flows[ids], self.bursts[ids]
        tokens = np.column_stack((self.features[ids], np.r_[False, flows[1:] == flows[:-1]],
                                  np.r_[False, bursts[1:] == bursts[:-1]])).astype(np.float32)
        start = self.times[ids[0]]
        history = list(range(bisect_left(self.times, start - 5), ids[0]))
        available = min(5, start - self.times[0])
        context = np.r_[self.summary(history), np.log1p(available * 1000), bool(history)]
        quality = (len(ids) / (len(ids) + 16), len(set(tokens[:, 1])) == 2,
                   len(np.unique(flows)) / len(ids))
        return tokens, self.summary(ids), context.astype(np.float32), np.asarray(quality, np.float32)

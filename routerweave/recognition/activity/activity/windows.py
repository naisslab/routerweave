"""Construct the traffic and service views of one half-open device window."""

import numpy as np

WINDOW = 30
STRIDE = 5
SIZE_EDGES = (64, 100, 200, 400, 800, 1200, 1500, 3000)
GAP_EDGES = (0.001, 0.01, 0.1, 1, 5, 10, 30)


def grid(start, stop, stride=STRIDE):
    if not np.isfinite([start, stop]).all() or stop - start < WINDOW:
        raise ValueError("A complete 30-second observation is required")
    return [start + WINDOW + stride * i for i in range(int((stop - start - WINDOW) // stride) + 1)]


def device_features(time, side, size, protocol, second):
    device = np.zeros((WINDOW, 40))
    for direction in (0, 1):
        mask = side == direction
        bins = second[mask]
        offset = 20 * direction
        np.add.at(device[:, offset], bins, 1)
        np.add.at(device[:, offset + 1], bins, size[mask])
        np.add.at(device[:, offset + 2], bins, protocol[mask] == 6)
        lengths = np.searchsorted(SIZE_EDGES, size[mask], side="right")
        np.add.at(device, (bins, offset + 3 + lengths), 1)
        gaps = np.searchsorted(GAP_EDGES, np.diff(time[mask]), side="right")
        np.add.at(device, (bins[1:], offset + 12 + gaps), 1)
    return np.log1p(device).astype(np.float32)


def connection_features(time, side, size, protocol, second, flow, start):
    valid = np.flatnonzero(flow >= 0)
    ordered = valid[np.argsort(flow[valid], kind="stable")]
    groups = np.split(ordered, np.flatnonzero(np.diff(flow[ordered])) + 1) if len(ordered) else []
    attrs = np.empty((len(groups), 16))
    series = np.zeros((len(groups), WINDOW, 2))
    total = size.sum()
    for index, ids in enumerate(groups):
        lengths = size[ids]
        times = time[ids]
        volume = lengths.sum()
        np.add.at(series[index], (second[ids], side[ids]), lengths)
        up, down = series[index].sum(0)
        gaps = np.diff(times)
        proto = protocol[ids[0]]
        attrs[index] = (up, down, (side[ids] == 0).sum(), side[ids].sum(),
                        (times[0] - start) / WINDOW, (times[-1] - start) / WINDOW,
                        len(np.unique(second[ids])) / WINDOW, *np.quantile(lengths, (0.5, 0.9)),
                        *(np.quantile(gaps, (0.5, 0.9)) if len(gaps) else (0, 0)),
                        up / volume, volume / total, proto == 6, proto == 17, proto not in (6, 17))
    log_columns = (0, 1, 2, 3, 7, 8, 9, 10)
    attrs[:, log_columns] = np.log1p(attrs[:, log_columns])
    return attrs.astype(np.float32), np.log1p(series).astype(np.float32)


def header_features(side, size, protocol, ttl, payload, flags, advertised):
    profile = np.zeros((2, 20))
    for direction, out in enumerate(profile):
        take = side == direction
        count = take.sum()
        if not count:
            continue
        volume = size[take].sum()
        out[:4] = (np.log1p(count), np.log1p(volume), (protocol[take] == 6).mean(),
                   (protocol[take] == 17).mean())
        out[10:14] = np.bincount(np.searchsorted((32, 64, 128), ttl[take]), minlength=4) / count
        tcp = take & (advertised >= 0)
        if tcp.any():
            length, flag = payload[tcp], flags[tcp]
            out[4] = length.sum() / volume
            out[5] = ((length == 0) & ((flag & 16) != 0) & ((flag & 7) == 0)).mean()
            out[6:10] = [((flag & bit) != 0).mean() for bit in (2, 1, 4, 8)]
            bins = np.searchsorted((0, 1024, 8192, 32768, 65534), advertised[tcp])
            out[14:] = np.bincount(bins, minlength=6) / len(flag)
    return profile.ravel().astype(np.float32)


def service_context(rows, side, size, protocol, payload, flow, second, connections):
    result = np.zeros(380)
    total = size.sum()
    if total == 0:
        return result
    result[:3] = (total, len(rows), connections)
    bits = np.array([p.bits for p in rows])
    for group in range(27):
        mask = (bits & (1 << group)) != 0
        if not mask.any():
            continue
        mass = size[mask].sum()
        tagged = mask & (flow >= 0)
        keys, inverse, counts = np.unique(flow[tagged], return_inverse=True, return_counts=True)
        volumes = np.bincount(inverse, weights=size[tagged])
        down = mask & (side == 1)
        series = np.bincount(second[down], weights=size[down], minlength=WINDOW)
        active = series > 0
        runs = int(active[0]) + np.count_nonzero(active[1:] & ~active[:-1])
        positive = series[active]
        start = 3 + group * 12
        result[start:start + 12] = (
            mass / total, mask.mean(), len(keys) / connections if connections else 0,
            series.sum() / mass, payload[mask].sum() / mass, size[mask & (protocol == 17)].sum() / mass,
            active.mean(), positive.std() / positive.mean() if len(positive) else 0,
            positive.max() / positive.sum() if len(positive) else 0, runs,
            counts.max() / mask.sum() if len(keys) else 0, volumes.max() / mass if len(keys) else 0)
    for packet in rows:
        for column, event in packet.events:
            for group in range(22):
                if event & (1 << group):
                    result[327 + 2 * group + column] += 1
    result[371:379] = size @ np.array([p.quality for p in rows], dtype=np.float64) / total
    result[379] = size[flow >= 0].sum() / total
    return np.log1p(result)


def window_features(rows, start):
    time = np.fromiter((r.time for r in rows), dtype=np.float64)
    def values(field):
        return np.fromiter((getattr(r, field) for r in rows), dtype=np.int64)
    side, size, protocol, flow = map(values, ("incoming", "size", "protocol", "flow"))
    second = np.floor(time - start).astype(int)
    payload = values("payload")
    attrs, series = connection_features(time, side, size, protocol, second, flow, start)
    return dict(device=device_features(time, side, size, protocol, second),
                connection_attributes=attrs, connection_temporal=series,
                header_profile=header_features(side, size, protocol, values("ttl"), payload,
                                               values("flags"), values("advertised")),
                context=service_context(rows, side, size, protocol, payload, flow, second, len(attrs)))

"""Fit the numerical BehavIoT and FlowPrint adapters on labeled training units."""

from collections import Counter
import numpy as np
from sklearn.ensemble import RandomForestClassifier


def fit_forests(bursts, labels, idle, rng, *, cap=300_000, workers=1):
    """Fit one device's binary forests. Idle rows are negatives for every activity."""
    x, y = np.asarray(bursts), np.asarray(labels)
    if len(x) != len(y):
        raise ValueError("Each training burst requires a label")
    if cap is not None and len(x) > cap:
        chosen = rng.choice(len(x), cap, replace=False)
        x, y = x[chosen], y[chosen]
    negatives = np.asarray(idle).reshape(-1, 22)
    if len(negatives) > max(1, len(x)):
        negatives = negatives[rng.choice(len(negatives), len(x), replace=False)]
    features = np.concatenate([x, negatives])
    models = {}
    for activity in np.unique(y):
        target = np.r_[y == activity, np.zeros(len(negatives), dtype=bool)]
        if len(np.unique(target)) == 2:
            model = RandomForestClassifier(n_estimators=100, random_state=100, n_jobs=workers)
            models[int(activity)] = model.fit(features, target)
    return models


def forest_vote(models, features, *, background=None, itc=False):
    """ITC votes over all positive forests. The other adapters choose one label per burst."""
    fallback = -1 if background is None else background
    if not models or not len(features):
        return fallback
    labels = np.array(sorted(models))
    scores = np.column_stack([models[c].predict_proba(features)[:, 1] for c in labels])
    if itc:
        counts = (scores > 0.5).sum(axis=0)
        if not counts.max():
            return fallback
        tied = np.flatnonzero(counts == counts.max())
        return int(labels[tied[scores[:, tied].max(axis=0).argmax()]])
    best = scores.argmax(axis=1)
    confidence = scores[np.arange(len(scores)), best]
    votes = [(int(labels[i]), p) if p > 0.5 else (-1, 0.0) for i, p in zip(best, confidence)]
    if background is None:
        votes = [v for v in votes if v[0] != -1]
    return event_vote(votes, fallback)


def burst_features(arrays, *, return_intervals=False):
    """Return (n, 22) features, optionally with their aligned burst intervals."""

    def moments(values):
        """scipy.stats skew and Fisher kurtosis, without its per-call overhead."""
        centered = values - values.mean()
        second = (centered**2).mean()
        if second <= 0:
            return 0.0, 0.0
        return float((centered**3).mean() / second**1.5), float(
            (centered**4).mean() / second**2 - 3.0
        )

    rows, intervals = [], []
    for flow in np.unique(arrays["flow"]):
        mask = arrays["flow"] == flow
        t, size = arrays["t"][mask], arrays["size"][mask].astype(np.float64)
        direction, local = arrays["direction"][mask], arrays["local"][mask]
        if len(t) < 2:
            continue
        order = np.argsort(t, kind="stable")
        t, size, direction, local = t[order], size[order], direction[order], local[order]
        delta = np.r_[0.0, np.diff(t)]
        cuts = np.r_[0, np.flatnonzero(delta > 1.0), len(t)]
        for start, end in zip(cuts, cuts[1:]):
            if end - start < 2:
                continue
            s, d = size[start:end], delta[start:end].copy()
            d[0] = 0.0
            out, loc = direction[start:end] == 1, local[start:end]
            median = np.median(s)
            skew_s, kurtosis_s = moments(s)
            skew_d, kurtosis_d = moments(d)
            out_external, in_external = out & ~loc, ~out & ~loc
            out_local, in_local = out & loc, ~out & loc
            rows.append(
                [
                    s.mean(),
                    s.min(),
                    s.max(),
                    np.median(np.abs(s - median)) / 0.6744897501960817,
                    skew_s,
                    kurtosis_s,
                    d.mean(),
                    d.var(ddof=1),
                    np.median(d),
                    kurtosis_d,
                    skew_d,
                    float(len(s)),
                    float(in_external.sum()),
                    float(out_external.sum()),
                    float((~loc).sum()),
                    float(loc.sum()),
                    float(in_local.sum()),
                    float(out_local.sum()),
                    s[out_external].mean() if out_external.any() else 0.0,
                    s[in_external].mean() if in_external.any() else 0.0,
                    s[out_local].mean() if out_local.any() else 0.0,
                    s[in_local].mean() if in_local.any() else 0.0,
                ]
            )
            if return_intervals:
                intervals.append((float(t[start]), float(t[end - 1])))
    features = np.asarray(rows, np.float32).reshape(-1, 22)
    return (features, intervals) if return_intervals else features


def event_vote(votes, fallback):
    """Upstream step two: most frequent label, ties to the higher probability; none is its own label."""
    if not votes:
        return fallback
    labels = [label for label, _ in votes]
    frequencies = Counter(labels)
    counter, chosen, probability = 0, labels[0], 0.0
    for label, value in votes:
        frequency = frequencies[label]
        if frequency > counter or (frequency == counter and value > probability):
            counter, chosen, probability = frequency, label, value
    return fallback if chosen == -1 else chosen

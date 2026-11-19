"""Fit a baseline on supplied labeled units and predict separate unlabeled units."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

import numpy as np

from baselines import burst_features, fit_forests, forest_vote
from flowprint_adapter import fingerprint_vote, fit_fingerprints


def features(unit):
    names = ("t", "size", "direction", "flow", "local")
    arrays = {k: np.asarray(unit["packets"][k]) for k in names}
    if len({len(a) for a in arrays.values()}) != 1:
        raise ValueError("Packet columns have different lengths")
    arrays["local"] = arrays["local"].astype(bool)
    return np.nan_to_num(burst_features(arrays), nan=-1.0, posinf=-1.0, neginf=-1.0)


def run(dataset, method, train, test, background=None):
    if not train or not test:
        raise ValueError("Expected nonempty training and prediction partitions")
    train_ids = [u["id"] for u in train]
    test_ids = [u["id"] for u in test]
    if len(set(train_ids + test_ids)) != len(train_ids) + len(test_ids):
        raise ValueError("Each unit needs a distinct ID across the two partitions")
    if method == "flowprint":
        samples = [
            (frozenset(f["tokens"]), f["flows"], row["label"])
            for row in train
            for f in row["fingerprints"]
        ]
        if not samples:
            raise ValueError("Training requires at least one fingerprint")
        model = fit_fingerprints(samples)
        fallback = (
            Counter(y for _, _, y in samples).most_common(1)[0][0]
            if dataset == "itc"
            else model.fingerprints[max(model.fingerprints, key=lambda fp: fp.n_flows)]
        )
        return [
            fingerprint_vote(model, [f["tokens"] for f in r["fingerprints"]], fallback)
            for r in test
        ]

    groups = defaultdict(list)
    for row in train:
        groups[row["group"]].append(row)
    labels = sorted({r["label"] for r in train if not r.get("idle")})
    rng = np.random.default_rng(42)
    models = {}
    for group in sorted(groups):
        x, y, idle, background_bursts = [], [], [], []
        has_idle_capture = any(u.get("idle") for u in groups[group])
        for row in groups[group]:
            f = features(row)
            if row.get("idle"):
                idle.extend(f)
            elif row["label"] == background:
                background_bursts.extend(f)
            else:
                x.extend(f)
                y.extend([labels.index(row["label"])] * len(f))
        models[group] = fit_forests(
            np.asarray(x).reshape(-1, 22),
            y,
            idle if has_idle_capture else background_bursts,
            rng,
            cap=None if dataset == "itc" else 300_000,
        )
    predictions = []
    for unit in test:
        index = forest_vote(
            models.get(unit["group"], {}),
            features(unit),
            background=labels.index(background) if background in labels else None,
            itc=dataset == "itc",
        )
        predictions.append(labels[index] if index >= 0 else "__abstain__")
    return predictions


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", choices=["app", "iot", "behaviot", "itc"])
    p.add_argument("method", choices=["behaviot", "flowprint"])
    p.add_argument("input", type=Path)
    args = p.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    result = run(args.dataset, args.method, data["train"], data["test"], data.get("background"))
    print(
        json.dumps(
            [{"id": r["id"], "prediction": v} for r, v in zip(data["test"], result)], indent=2
        )
    )


if __name__ == "__main__":
    main()

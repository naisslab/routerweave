"""Train device localizers and a shared operation classifier from reviewed samples."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import tempfile

import numpy as np
import torch
from torch.nn import functional as F
from torch.nn.utils.rnn import pad_sequence

from .classifier import OperationClassifier, size_features
from .localizer import Localizer, locate
from .supervision import bind_fingerprints, fit_localizer
from .traffic_features import Traffic
from .training_data import BACKGROUND, normalization, sample_rows


def prepare_rows(samples, bundles, device):
    localizers = {}
    for name, bundle in bundles.items():
        model = Localizer(bundle["policy"]["hidden"])
        model.load_state_dict(bundle["state"])
        localizers[name] = model.to(device).eval()
    rng = np.random.default_rng(0)
    rows, augmented, counts = [], [], Counter()
    for sample in samples:
        name = sample["device_id"]
        bundle = bundles[name]
        traffic = Traffic(sample["packets"])
        policy = bundle["policy"]
        candidates = locate(localizers[name], traffic, np.asarray(bundle["mean"]), np.asarray(bundle["scale"]),
                            context=bundle["context"], owned=policy["owned_packets"], threshold=policy["threshold"])
        base, extra = sample_rows(sample, traffic, candidates, rng, counts)
        rows.extend(base)
        augmented.extend(extra)
    if not rows:
        raise ValueError("No labelled classifier inputs")
    norm = normalization(rows)
    counts.update(base_rows=len(rows), augmented_rows=len(augmented))
    return rows + augmented, norm, counts


def batches(lengths, rng, batch_size=128):
    order = np.argsort(lengths, kind="stable")
    groups = []
    for start in range(0, len(order), 16 * batch_size):
        block = order[start:start + 16 * batch_size].copy()
        rng.shuffle(block)
        groups.extend(block[i:i + batch_size] for i in range(0, len(block), batch_size))
    rng.shuffle(groups)
    return groups


def fit_classifier(rows, norm, *, epochs=40, seed=42, device="cpu"):
    if epochs < 1:
        raise ValueError("Expected at least one classifier epoch")
    devices = sorted({row.device for row in rows})
    classes = [BACKGROUND] + sorted({row.label for row in rows} - {BACKGROUND})
    if len(classes) < 2:
        raise ValueError("No labelled operation found")
    device_ids = {name: i for i, name in enumerate(devices)}
    class_ids = {name: i for i, name in enumerate(classes)}
    identities = torch.tensor([device_ids[r.device] for r in rows])
    labels = torch.tensor([class_ids[r.label] for r in rows])
    support = torch.zeros((len(devices), len(classes)), dtype=torch.bool)
    support[:, 0] = True
    support[identities, labels] = True
    counts = Counter((r.device, r.label) for r in rows)
    weights = torch.tensor([1 / np.sqrt(counts[r.device, r.label]) for r in rows], dtype=torch.float32)

    tokens = [torch.from_numpy(r.features[0]) for r in rows]
    numeric = [torch.from_numpy(size_features(r.features[0])) for r in rows]
    flat, history, quality = (torch.from_numpy(np.stack([r.features[j] for r in rows])) for j in (1, 2, 3))
    lengths = np.asarray([len(x) for x in tokens])
    torch.manual_seed(seed)
    model = OperationClassifier(norm, support).to(device).train()
    optimizer = torch.optim.AdamW(model.parameters(), lr=.001, weight_decay=.0001)
    rng = np.random.default_rng(seed)
    for _ in range(epochs):
        for ids in batches(lengths, rng):
            packet_batch = pad_sequence([tokens[i] for i in ids], batch_first=True).to(device)
            size_batch = pad_sequence([numeric[i] for i in ids], batch_first=True).to(device)
            signals = [x[ids].to(device) for x in (flat, history, quality, identities)]
            optimizer.zero_grad()
            logp = model(packet_batch, lengths[ids].tolist(), *signals, size_batch)
            w = weights[ids].to(device)
            loss = (F.nll_loss(logp, labels[ids].to(device), reduction="none") * w).sum() / w.sum()
            if not torch.isfinite(loss):
                raise ValueError("Nonfinite classifier loss")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5)
            optimizer.step()
    return dict(arm="numeric", seed=seed, state=model.cpu().state_dict(), devices=devices, classes=classes)


def fit(samples, settings, localizer_epochs, classifier_epochs, device):
    samples = [bind_fingerprints(s) for s in samples]
    by_device = defaultdict(list)
    for sample in samples:
        if not isinstance(sample["device_type"], str) or not sample["device_type"]:
            raise ValueError("A device category is required to construct operation labels")
        by_device[sample["device_id"]].append(sample)
    if not by_device:
        raise ValueError("Expected training samples")
    bundles = {}
    settings = dict(settings)
    overrides = settings.pop("minimum_updates_by_device", {})
    for name, group in sorted(by_device.items()):
        if len({s["device_type"] for s in group}) != 1:
            raise ValueError("Conflicting categories for one physical device")
        recipe = dict(settings)
        if name in overrides:
            recipe["minimum_updates"] = overrides[name]
        bundles[name] = fit_localizer(group, name, epochs=localizer_epochs, device=device, **recipe)
    rows, norm, counts = prepare_rows(samples, bundles, device)
    classifier = fit_classifier(rows, norm, epochs=classifier_epochs, device=device)
    return bundles, classifier, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True, help="Localizer training settings")
    parser.add_argument("--output", type=Path, required=True, help="New checkpoint directory")
    parser.add_argument("--localizer-epochs", type=int, help="Override the device update budget")
    parser.add_argument("--classifier-epochs", type=int, default=40)
    parser.add_argument("--device", default="cpu", choices=["cpu", "cuda"])
    args = parser.parse_args()
    if args.output.exists():
        parser.error("The output directory already exists")
    if args.classifier_epochs < 1 or (args.localizer_epochs is not None and args.localizer_epochs < 1):
        parser.error("Epoch counts must be positive")
    samples = json.loads(args.samples.read_text(encoding="utf-8"))
    settings = json.loads(args.config.read_text(encoding="utf-8"))
    bundles, classifier, counts = fit(samples, settings, args.localizer_epochs, args.classifier_epochs, args.device)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as tmp:
        stage = Path(tmp) / "checkpoints"
        stage.mkdir()
        files = {}
        for i, (name, bundle) in enumerate(bundles.items(), 1):
            files[name] = f"localizer-{i}.pt"
            torch.save(bundle, stage / files[name])
        torch.save(classifier, stage / "classifier.pt")
        stage.rename(args.output)
    print(json.dumps(dict(localizers=files, classifier="classifier.pt", **counts)))


if __name__ == "__main__":
    main()

"""Select epochs by recording-grouped validation, then fit a fresh activity classifier."""

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path

import numpy as np
import torch
from torch.nn.functional import nll_loss

from .checkpoint import load_model, save_model
from .recording_dataset import Recording, check_splits, new_directory, read_manifest
from .model import ActivityFiLM, LABELS
from .normalization import fit as fit_stats, tensors
from .predict import probabilities


@dataclass(frozen=True)
class Recipe:
    epochs: int = 25
    steps: int = 31
    batch: int = 256
    microbatch: int = 32
    seed: int = 7


def sampling_mass(entries):
    per_recording = Counter(source for source, _ in entries)
    strata = Counter((s.meta["platform"], s.target) for s in per_recording)
    mass = np.array([1 / (per_recording[s] * strata[s.meta["platform"], s.target]) for s, _ in entries])
    return mass / mass.sum()


def project_gradients(gradients, seed):
    projected = [g.clone() for g in gradients]
    rng = np.random.default_rng(seed)
    for i, value in enumerate(projected):
        for j in rng.permutation(len(gradients)):
            if i == j:
                continue
            other = gradients[j]
            dot, norm = value.dot(other), other.square().sum()
            if dot < 0 and norm > 1e-20:
                value.add_(other, alpha=-float(dot / norm))
    return torch.stack(projected).sum(0)


def update_batch(model, optimizer, params, entries, batch, stats, device, recipe, seed):
    groups = defaultdict(list)
    for index in batch:
        source, window = entries[index]
        groups[source.meta["platform"]].append((source, window))
    gradients = []
    for platform in sorted(groups):
        optimizer.zero_grad(set_to_none=True)
        group = groups[platform]
        for offset in range(0, len(group), recipe.microbatch):
            chunk = group[offset:offset + recipe.microbatch]
            traffic, context = tensors([s.window(i) for s, i in chunk], stats, device)
            target = torch.tensor([s.target for s, _ in chunk], device=device)
            loss = nll_loss(model(traffic, context), target, reduction="sum") / len(batch)
            loss.backward()
        gradients.append(torch.cat([(p.grad if p.grad is not None else torch.zeros_like(p)).flatten()
                                    for p in params]))
    update = project_gradients(gradients, seed)
    for p, part in zip(params, update.split([p.numel() for p in params]), strict=True):
        p.grad = part.view_as(p)
    torch.nn.utils.clip_grad_norm_(params, 5, error_if_nonfinite=True)
    optimizer.step()


def score(model, stats, sources, device):
    model.eval()
    confusion = np.zeros((len(LABELS), len(LABELS)), dtype=np.int64)
    accuracies = []
    for s in sources:
        rows = (s.window(i) for i in s.evaluation)
        predicted = np.fromiter((p.argmax() for p in probabilities(model, rows, stats, device)), dtype=int)
        counts = np.bincount(predicted, minlength=len(LABELS))
        confusion[s.target] += counts
        accuracies.append(counts[s.target] / len(predicted))
    supported = confusion.sum(1) > 0
    f1 = 2 * confusion.diagonal() / np.maximum(1, confusion.sum(1) + confusion.sum(0))
    return dict(mean_recording_accuracy=float(np.mean(accuracies)), macro_f1=float(f1[supported].mean()),
                confusion=confusion.tolist(), windows=int(confusion.sum()))


def fit(sources, validation, epochs, recipe, device):
    entries = [(s, i) for s in sources for i in s.fit]
    mass = sampling_mass(entries)
    stats = fit_stats(entries, mass)
    torch.manual_seed(recipe.seed)
    model = ActivityFiLM().to(device)
    params = list(model.parameters())
    optimizer = torch.optim.AdamW(params, lr=0.001, weight_decay=0.001)
    rng = np.random.default_rng(recipe.seed)
    best, selected, best_scores = None, 0, None
    for epoch in range(1, epochs + 1):
        model.train()
        draws = rng.choice(len(entries), recipe.steps * recipe.batch, p=mass, replace=True)
        for step, batch in enumerate(draws.reshape(recipe.steps, recipe.batch)):
            update_batch(model, optimizer, params, entries, batch, stats, device, recipe,
                         recipe.seed + epoch * recipe.steps + step)
        if validation:
            scores = score(model, stats, validation, device)
            key = (scores["mean_recording_accuracy"], scores["macro_f1"])
            if best is None or key > best:
                best, selected, best_scores = key, epoch, scores
            if epoch - selected >= 5:
                break
    return model, stats, selected, best_scores


def train(manifest, output, recipe, device):
    records = read_manifest(manifest)
    check_splits(records)
    development = [Recording(manifest.parent, s) for s in records if s["fold"] != "test"]
    with new_directory(output) as root:
        folds = []
        for fold in range(3):
            fitting = [s for s in development if s.meta["fold"] != fold]
            validation = [s for s in development if s.meta["fold"] == fold]
            _, _, epoch, scores = fit(fitting, validation, recipe.epochs, recipe, device)
            folds.append({"fold": fold, "selected_epoch": epoch, **scores})
        epochs = int(np.median([v["selected_epoch"] for v in folds]))
        model, stats, _, _ = fit(development, [], epochs, recipe, device)
        save_model(root / "model.pt", model, stats)
        model, stats = load_model(root / "model.pt", device)
        test = [Recording(manifest.parent, s) for s in records if s["fold"] == "test"]
        report = {"recipe": asdict(recipe), "labels": LABELS, "folds": folds, "refit_epochs": epochs,
                  "test": score(model, stats, test, device) if test else None}
        (root / "training.json").write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--epochs", type=int, default=Recipe.epochs)
    parser.add_argument("--steps", type=int, default=Recipe.steps)
    parser.add_argument("--batch", type=int, default=Recipe.batch)
    args = parser.parse_args()
    if min(args.epochs, args.steps, args.batch) < 1:
        parser.error("Training budgets must be positive")
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = True
    torch.set_num_threads(2)
    train(args.manifest, args.output, Recipe(args.epochs, args.steps, args.batch), args.device)

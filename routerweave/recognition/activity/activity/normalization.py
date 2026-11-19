"""Fit per-window weighted moments and apply checkpoint-frozen statistics."""

import numpy as np
import torch

from .recording_dataset import SHAPES


def fit(entries, weights):
    means = {k: np.zeros(shape[-1]) for k, shape in SHAPES.items()}
    squares = {k: np.zeros_like(v) for k, v in means.items()}
    masses = dict.fromkeys(means, 0.0)
    for (recording, index), weight in zip(entries, weights, strict=True):
        for key, value in recording.window(index).items():
            data = value.reshape(-1, SHAPES[key][-1]).astype(np.float64)
            if not len(data):
                continue
            if not np.isfinite(data).all():
                raise ValueError(f"Nonfinite fitting data in {key}")
            means[key] += weight * data.mean(0)
            squares[key] += weight * (data * data).mean(0)
            masses[key] += weight
    stats = {}
    for key, total in masses.items():
        if not total:
            raise ValueError(f"No fitting observations for {key}")
        mean = means[key] / total
        scale = np.sqrt(np.maximum(0, squares[key] / total - mean * mean))
        scale[scale < 1e-6] = 1
        stats[key] = {"mean": mean.tolist(), "std": scale.tolist()}
    return stats


def tensors(windows, stats, device):
    traffic, contexts = [], []
    for window in windows:
        row = {}
        for key, shape in SHAPES.items():
            mean, std = (np.asarray(stats[key][k], dtype=np.float64) for k in ("mean", "std"))
            if (mean.shape != (shape[-1],) or std.shape != mean.shape
                    or not np.isfinite(std).all() or (std <= 0).any()):
                raise ValueError(f"Invalid checkpoint statistics for {key}")
            value = (window[key] - mean) / std
            if not np.isfinite(value).all():
                raise ValueError(f"Nonfinite normalized {key}")
            if key in ("context", "header_profile"):
                value = np.clip(value, -10, 10)
            tensor = torch.as_tensor(value, dtype=torch.float32, device=device)
            if key == "context":
                contexts.append(tensor)
            else:
                row[key] = tensor
        traffic.append(row)
    return traffic, torch.stack(contexts)

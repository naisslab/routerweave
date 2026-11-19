"""Predict six activity probabilities per complete window of one device capture."""

import argparse
from itertools import islice
import json
from pathlib import Path

import torch

from .capture import observations
from .checkpoint import load_model
from .model import LABELS
from .normalization import tensors
from .windows import grid


def probabilities(model, windows, stats, device):
    iterator = iter(windows)
    with torch.inference_mode():
        while batch := list(islice(iterator, 24)):
            values = model(*tensors(batch, stats, device)).exp()
            if not torch.isfinite(values).all():
                raise ValueError("Model produced a nonfinite probability")
            yield from values.cpu().numpy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--packet-table", type=Path, help="CSV frame selection and canonical timestamps")
    parser.add_argument("--start", type=float, required=True, help="Observation start, Unix seconds")
    parser.add_argument("--stop", type=float, required=True, help="Observation stop, Unix seconds")
    args = parser.parse_args()
    torch.set_num_threads(2)
    model, stats = load_model(args.checkpoint)
    ends = grid(args.start, args.stop)
    windows = observations(args.capture, args.ip, ends, args.packet_table)
    for end, p in zip(ends, probabilities(model, windows, stats, "cpu"), strict=True):
        print(json.dumps({"end": end, "label": LABELS[p.argmax()],
                          "probabilities": dict(zip(LABELS, p.tolist(), strict=True))}, allow_nan=False))


if __name__ == "__main__":
    main()

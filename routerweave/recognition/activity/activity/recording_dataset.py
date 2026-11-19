"""Recording-level splits and numeric, memory-mapped window arrays."""

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import re

import numpy as np

from .model import LABELS

SHAPES = {"device": (30, 40), "connection_attributes": (16,),
          "connection_temporal": (30, 2), "header_profile": (40,), "context": (380,)}
CONNECTION_FIELDS = ("connection_attributes", "connection_temporal")


@contextmanager
def new_directory(path):
    path = path.resolve()
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=path.parent) as tmp:
        work = Path(tmp) / "data"
        work.mkdir()
        yield work
        if path.exists():
            raise FileExistsError(path)
        work.rename(path)


def check_splits(records):
    groups, captures, ids = {}, {}, set()
    for row in records:
        fold = row["fold"]
        if not (type(fold) is int and fold in (0, 1, 2) or fold == "test"):
            raise ValueError("Expected development fold 0, 1, 2 or test")
        if row["label"] not in LABELS or not all(isinstance(row[k], str) and row[k].strip()
                                                 for k in ("id", "group", "platform")):
            raise ValueError("Invalid source identity, platform, group or activity")
        if not re.fullmatch(r"[a-f0-9]{64}", row["capture_sha256"]):
            raise ValueError("Invalid capture digest")
        if row["id"] in ids:
            raise ValueError("Duplicate recording ID")
        ids.add(row["id"])
        for lookup, key in ((groups, "group"), (captures, "capture_sha256")):
            if lookup.setdefault(row[key], fold) != fold:
                raise ValueError("A group or capture crosses split boundaries")
    if not {0, 1, 2}.issubset({s["fold"] for s in records}):
        raise ValueError("Each of the three development folds needs observations")


class Recording:
    def __init__(self, root, metadata):
        self.meta = metadata
        self.target = LABELS.index(metadata["label"])
        directory = (root / metadata["directory"]).resolve()
        if not directory.is_relative_to(root.resolve()):
            raise ValueError("Prepared recording directory lies outside the manifest directory")
        def load(field):
            return np.load(directory / (field + ".npy"), mmap_mode="r", allow_pickle=False)
        self.ends, self.offsets = load("ends"), load("offsets")
        n = len(self.ends)
        if (self.ends.shape != (n,) or not n or not np.isfinite(self.ends).all()
                or (np.diff(self.ends) <= 0).any()):
            raise ValueError("Invalid observation endpoints")
        if (self.offsets.shape != (n + 1,) or self.offsets.dtype.kind != "i"
                or self.offsets[0] != 0 or (np.diff(self.offsets) < 0).any()):
            raise ValueError("Invalid connection offsets")
        self.fields = {key: load(key) for key in SHAPES}
        for key, array in self.fields.items():
            length = self.offsets[-1] if key in CONNECTION_FIELDS else n
            if array.shape != (length, *SHAPES[key]) or array.dtype.kind != "f":
                raise ValueError(f"Invalid {key} array")
        self.fit, self.evaluation = load("fit"), load("evaluation")
        for indices in (self.fit, self.evaluation):
            if (indices.ndim != 1 or indices.dtype.kind != "i" or (indices < 0).any()
                    or (indices >= n).any() or (np.diff(indices) <= 0).any()):
                raise ValueError("Invalid window selection")
        if not len(self.evaluation) or (metadata["fold"] != "test" and not len(self.fit)):
            raise ValueError("Empty required window selection")

    def window(self, i):
        flows = slice(self.offsets[i], self.offsets[i+1])
        return {k: v[flows if k in CONNECTION_FIELDS else i] for k, v in self.fields.items()}


def read_manifest(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

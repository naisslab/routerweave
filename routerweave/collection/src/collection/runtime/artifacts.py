"""Small platform-neutral helpers for timestamped JSON artifacts."""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Any

RETAINED_RECEIPT = ".retained-artifacts.json"


@lru_cache(maxsize=128)
def _retained_receipt(path: str, modified: int, size: int) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


@lru_cache(maxsize=256)
def _check_retained_digest(path: str, identity: tuple, expected: str) -> None:
    with Path(path).open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError("Retained capture hash differs from its ownership receipt")
    if _artifact_identity(Path(path)) != identity:
        raise ValueError("Retained capture changed during verification")


def _artifact_identity(path: Path) -> tuple:
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def resolve_artifact_path(path: str | Path, *, workspace: Path | None = None) -> Path:
    """Resolve capture paths relative to this collection workspace."""
    root = (workspace or Path(__file__).resolve().parents[3]).resolve()
    current = Path(str(path).replace("\\", "/"))
    if not current.is_absolute():
        current = root / current
    current = current.resolve()
    if not current.is_relative_to(root / "runs"):
        return current
    if current.suffix.lower() not in {".pcap", ".pcapng"}:
        return current
    for owner in current.parents:
        if not owner.is_relative_to(root / "runs"):
            break
        receipt = owner / RETAINED_RECEIPT
        if not receipt.is_file():
            continue
        info = receipt.stat()
        value = _retained_receipt(str(receipt), info.st_mtime_ns, info.st_size)
        if value.get("schema_version") != "retained-captures-v1":
            raise ValueError("Unknown retained capture receipt")
        item = value.get("sources", {}).get(current.relative_to(owner).as_posix())
        if item is None:
            continue
        family = item.get("dataset_family")
        if family not in {"screen-time", "iot", "iot-v2"}:
            raise ValueError("Unknown retained dataset family")
        relative = Path(item["path"])
        if relative.is_absolute():
            raise ValueError("Retained capture location must be relative")
        target = (owner / relative).resolve()
        if not target.is_relative_to(root / "datasets" / family) or target.suffix.lower() not in {".pcap", ".pcapng"}:
            raise ValueError("Retained capture escapes its dataset tree")
        identity = _artifact_identity(target)
        if identity[2] != item["bytes"]:
            raise ValueError("Retained capture size differs from its receipt")
        _check_retained_digest(str(target), identity, item["sha256"])
        return target
    return current


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


class EventLog:
    """Append timestamped JSONL events while keeping operator feedback concise."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **data: object) -> None:
        payload = {"ts": now_iso(), "event": event, **data}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        print(f"[{payload['ts']}] {event}")

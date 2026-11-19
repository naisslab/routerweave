"""Screen Time original ownership and byte-preserving capture references.

IoT does not use this store. Sources start in runs; successful publication
owns a hash-verified, content-addressed copy and only new-policy closed runs may
retire their capture path after the committed publication has been verified.
"""
from __future__ import annotations

import csv
from contextlib import contextmanager
from contextvars import ContextVar
import functools
import hashlib
import io
import inspect
import json
import math
import os
from pathlib import Path
import shutil
import struct
import stat
import time
from uuid import uuid4

POLICY = "screen-time-single-original-v1"
VIEW = "screen-time-pcap-view-v1"
RECEIPT = "screen_time_originals.json"
_LOCKED_STORES = ContextVar('screen_time_locked_stores', default=())
_PUBLICATIONS = ContextVar('screen_time_publications', default=())


@contextmanager
def _locked_store(store):
    """OS-owned lock: concurrent publishers cannot race rollback against reuse."""
    store = Path(store).resolve(); key = str(store)
    if key in _LOCKED_STORES.get():
        yield; return
    store.mkdir(parents=True, exist_ok=True)
    with (store / '.publication.lock').open('a+b') as handle:
        if handle.tell() == 0: handle.write(b'0'); handle.flush()
        deadline = time.monotonic() + 60
        while True:
            handle.seek(0)
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline: raise TimeoutError('Screen Time publication store is busy')
                time.sleep(.05)
        token = _LOCKED_STORES.set((*_LOCKED_STORES.get(), key))
        try: yield
        finally:
            _LOCKED_STORES.reset(token); handle.seek(0)
            if os.name == 'nt': msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else: fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _committed_original_paths(root):
    """Read published inventories only; a staging directory is not a commit."""
    paths = set()
    def visit(value):
        if isinstance(value, dict):
            if value.get('storage_mode') == 'original_reference':
                paths.add((root / value['path']).resolve())
            for child in value.values(): visit(child)
        elif isinstance(value, list):
            for child in value: visit(child)
    manifest = root / 'dataset_manifest.json'
    if manifest.exists():
        visit(json.loads(manifest.read_text(encoding='utf-8-sig')))
        for sample in root.glob('sample-*/sample_manifest.json'):
            visit(json.loads(sample.read_text(encoding='utf-8-sig')))
    # Compatibility packaging can commit an inventory without a direct-sample root.
    for manifest in (root / 'manifests').glob('*.json'):
        visit(json.loads(manifest.read_text(encoding='utf-8-sig')))
    return paths


def original_publication(function):
    """Rollback only this publisher's new, unreferenced original copies."""
    signature = inspect.signature(function)
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        bound = signature.bind(*args, **kwargs); bound.apply_defaults()
        root = bound.arguments.get('dataset_root')
        if root is None:
            record = bound.arguments.get('plan') or bound.arguments.get('report')
            root = record['dataset_root']
        root = Path(root).resolve(); store = publication_store(root); key = str(store)
        if key in _PUBLICATIONS.get(): return function(*args, **kwargs)
        with _locked_store(store):
            before = {p.name for p in store.glob('*.pcap')}
            token = _PUBLICATIONS.set((*_PUBLICATIONS.get(), key))
            try:
                result = function(*args, **kwargs)
                repository = Path(__file__).resolve().parents[3]
                if root.is_relative_to(repository / 'datasets' / 'screen-time'):
                    import subprocess
                    import sys
                    subprocess.run([sys.executable, '-B', str(repository / 'scripts/datasets/build_screen_time_docs.py'), '--write'],
                                   cwd=repository, check=True, stdout=subprocess.DEVNULL)
                return result
            except BaseException:
                # If commit succeeded but source retirement failed, retain its originals.
                try: referenced = _committed_original_paths(root)
                except (OSError, ValueError, KeyError, TypeError): referenced = None
                if referenced is not None:
                    for target in store.glob('*.pcap'):
                        if target.name not in before and target.resolve() not in referenced:
                            if sha256(target) == target.stem:
                                target.chmod(stat.S_IREAD | stat.S_IWRITE); target.unlink()
                raise
            finally: _PUBLICATIONS.reset(token)
    return wrapped


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""): h.update(block)
    return h.hexdigest()


def publication_store(dataset_root):
    root = Path(dataset_root).resolve()
    for parent in [root, *root.parents]:
        if parent.name == "screen-time": return parent / "originals"
    return root.parent / "originals"


def store_original(source, store):
    """Publish an independent content-addressed original; never modify the source."""
    with _locked_store(store):
        return _store_original(source, store)


def _store_original(source, store):
    source, store = Path(source).resolve(), Path(store).resolve()
    before = source.stat(); digest = sha256(source)
    target = store / f"{digest}.pcap"
    store.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.stat().st_size != before.st_size or sha256(target) != digest:
            raise ValueError(f"Original store conflict: {target}")
    else:
        temporary = store / f".{digest}.{uuid4().hex}.tmp"
        try:
            shutil.copy2(source, temporary)
            temporary.chmod(stat.S_IREAD | stat.S_IWRITE)
            after = source.stat()
            if (after.st_size, after.st_mtime_ns) != (before.st_size, before.st_mtime_ns) or sha256(temporary) != digest:
                raise ValueError("Source changed while storing original")
            # Exclusive publication: never replace an existing original.
            try: os.link(temporary, target)
            except FileExistsError:
                if sha256(target) != digest: raise ValueError("Concurrent original store conflict")
            temporary.unlink()
        finally:
            if temporary.exists(): temporary.unlink()
    target.chmod(stat.S_IREAD)
    return {"path": str(target), "bytes": before.st_size, "sha256": digest}


def write_view(path, sources, *, window=None, attribution=None, retained=False, relative_base=None):
    """Persist a small reference, not another PCAP. relative_base is final location."""
    path = Path(path); base = Path(relative_base or path.parent).resolve()
    records = []
    for source in sources:
        p = Path(source["path"]).resolve()
        records.append({**source, "source_type": source.get("source_type", "content_original"),
                        "path": os.path.relpath(p, base).replace("\\", "/")})
    value = {"schema_version": VIEW, "storage_policy": POLICY, "sources": records,
             "window": list(window) if window else None, "inclusive_end": True}
    if attribution:
        p = Path(attribution).resolve()
        value["attribution"] = {"path": os.path.relpath(p, path.parent.resolve()).replace("\\", "/"), "sha256": sha256(p)}
        value["retained"] = bool(retained)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return value


def validate_view(path, *, verify_hashes=True):
    path = Path(path).resolve(); value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != VIEW or value.get("storage_policy") != POLICY:
        raise ValueError("Unknown capture reference schema")
    sources = value.get("sources")
    if not isinstance(sources, list) or not sources: raise ValueError("Capture reference has no originals")
    result = []
    for source in sources:
        raw = Path(str(source["path"]))
        if raw.is_absolute(): raise ValueError("Capture reference must be relative")
        p = (path.parent / raw).resolve(); digest = str(source.get("sha256", ""))
        kind = source.get("source_type", "content_original")
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest): raise ValueError("Invalid original digest")
        if kind == "content_original":
            if p.parent.name != "originals" or p.name != f"{digest}.pcap":
                raise ValueError("Capture reference does not identify a content-addressed original")
        elif kind == "run_original":
            if path.parent.parent not in p.parents or p.suffix.lower() != '.pcap':
                raise ValueError("Run original escapes the collection directory")
            p = resolve_run_original(path.parent.parent, p)
        else: raise ValueError("Unknown original reference type")
        if p.stat().st_size != int(source["bytes"]) or (verify_hashes and sha256(p) != digest):
            raise ValueError("Original capture hash/size mismatch")
        result.append(p)
    window = value.get("window")
    segments = value.get('attribution_index_segments')
    if segments is not None:
        if len(sources) != 1 or not value.get('retained') or window is not None:
            raise ValueError('Index origin requires a single complete original')
        if not isinstance(segments, list) or not segments: raise ValueError('Missing attribution index segments')
        previous = 0
        for segment in segments:
            if set(segment) != {'view_packet_index', 'source_file', 'packet_index'} or not all(type(v) is int for v in segment.values()):
                raise ValueError('Invalid attribution index segment')
            if segment['source_file'] < 0 or segment['packet_index'] < 1 or segment['view_packet_index'] <= previous:
                raise ValueError('Invalid attribution index segment')
            previous = segment['view_packet_index']
        if segments[0]['view_packet_index'] != 1: raise ValueError('Index segments must start at the first packet')
    if window is not None and (len(window) != 2 or not all(math.isfinite(float(v)) for v in window) or float(window[0]) > float(window[1])):
        raise ValueError("Invalid capture view time window")
    if value.get("retained"):
        ref = value.get("attribution", {}); p = (path.parent / str(ref.get("path", ""))).resolve()
        if p.parent != path.parent or p.name != "packet_attribution.csv": raise ValueError("Unsafe attribution reference")
        if verify_hashes and sha256(p) != ref.get("sha256"): raise ValueError("Attribution index hash mismatch")
    return value, result


def view_chunks(path):
    """Project original records in order; fail closed on index/record mismatch."""
    from .capture.pcap import pcap_format, pcap_timestamp
    path = Path(path).resolve(); view, sources = validate_view(path)
    index_file = None; reader = None; index_row = None
    if view.get("retained"):
        index_file = (path.parent / view["attribution"]["path"]).open(encoding="utf-8", newline="")
        reader = iter(csv.DictReader(index_file)); index_row = next(reader, None)
    expected_header = None
    segments = iter(view.get('attribution_index_segments', []))
    current_segment = next(segments, None); next_segment = next(segments, None)
    try:
        for file_index, source in enumerate(sources):
            with source.open("rb") as f:
                header = f.read(24); endian, nano = pcap_format(header)
                if expected_header is None: expected_header = header; yield header
                elif header != expected_header: raise ValueError("Original PCAP headers differ")
                snaplen = struct.unpack_from(endian + "I", header, 16)[0]; ordinal = 0
                while rh := f.read(16):
                    ordinal += 1
                    if len(rh) != 16: raise ValueError("Truncated original packet header")
                    _, _, cap, wire = struct.unpack(endian + "IIII", rh); data = f.read(cap)
                    if len(data) != cap or cap > snaplen or cap > wire: raise ValueError("Invalid original packet record")
                    epoch = pcap_timestamp(endian, nano, rh); window = view.get("window")
                    if window and not float(window[0]) <= epoch <= float(window[1]): continue
                    if reader is not None:
                        if next_segment and ordinal == next_segment['view_packet_index']:
                            current_segment = next_segment; next_segment = next(segments, None)
                        expected_index = ((current_segment['source_file'], current_segment['packet_index'] + ordinal - current_segment['view_packet_index'])
                                          if current_segment else (file_index, ordinal))
                        if index_row is None or (int(index_row["source_file"]), int(index_row["packet_index"])) != expected_index:
                            raise ValueError("Attribution index does not match original packet order")
                        if abs(float(index_row["timestamp"]) - epoch) > 1e-6 or int(index_row["original_bytes"]) != wire:
                            raise ValueError("Attribution index does not match original packet identity")
                        role = index_row["classification"]
                        if role not in {"target", "background", "unknown", "excluded"}: raise ValueError("Invalid attribution class")
                        index_row = next(reader, None)
                        if role == "excluded": continue
                    yield rh + data
        if reader is not None and index_row is not None: raise ValueError("Attribution index has extra packet rows")
        if next_segment is not None: raise ValueError('Attribution segment exceeds the capture')
    finally:
        if index_file: index_file.close()


class _ViewStream(io.RawIOBase):
    def __init__(self, chunks):
        self.chunks = iter(chunks); self.buffer = b""; self.position = 0
    def readable(self): return True
    def readinto(self, output):
        if not self.buffer:
            self.buffer = next(self.chunks, b"")
        n = min(len(output), len(self.buffer)); output[:n] = self.buffer[:n]
        self.buffer = self.buffer[n:]; self.position += n; return n
    def tell(self): return self.position
    def close(self):
        if hasattr(self.chunks, "close"): self.chunks.close()
        super().close()


def open_capture(path):
    path = Path(path)
    if path.suffix.lower() == ".json": return io.BufferedReader(_ViewStream(view_chunks(path)))
    return path.open("rb")


def inventory_path(root, item):
    root = Path(root).resolve(); path = (root / item['path']).resolve()
    if item.get('storage_mode') == 'original_reference':
        if path.parent != publication_store(root) or path.name != f"{item['sha256']}.pcap":
            raise ValueError('Original inventory reference escapes its store')
    elif root not in path.parents:
        raise ValueError('Inventory artifact escapes its dataset')
    return path


def resolve_run_original(run, source, *, _seen=frozenset()):
    """Legacy provenance paths stay unchanged; new run receipts resolve ownership."""
    run, source = Path(run).resolve(), Path(source).resolve()
    if source in _seen: raise ValueError('Original ownership receipt has a cycle')
    if source.is_file(): return source
    from .artifacts import resolve_artifact_path
    workspace = next((p.parent.parent for p in run.parents
                      if p.name == 'collection' and p.parent.name == 'runs'), None)
    receipt = run / RECEIPT
    if not receipt.is_file():
        # Collections in a relocated workspace use that workspace's ownership
        # receipts too; never bind their resolver to this module's checkout.
        return resolve_artifact_path(source, workspace=workspace)
    value = json.loads(receipt.read_text(encoding="utf-8"))
    if value.get("storage_policy") != POLICY: raise ValueError("Unknown original ownership receipt")
    key = source.relative_to(run).as_posix(); item = value.get("sources", {}).get(key)
    if item is None: return resolve_artifact_path(source, workspace=workspace)
    p = (run / item["path"]).resolve()
    kind = item.get('source_type', 'content_original')
    if kind == 'run_original':
        if p == source or run not in p.parents or p.suffix.lower() != '.pcap':
            raise ValueError('Original alias escapes its preserved run')
        p = resolve_run_original(run, p, _seen=_seen | {source})
    elif kind != 'content_original' or p.parent.name != "originals" or p.name != f"{item['sha256']}.pcap":
        raise ValueError('Transferred original does not identify its content store')
    if p.stat().st_size != item["bytes"] or sha256(p) != item["sha256"]:
        raise ValueError("Transferred original does not match receipt")
    return p


def retire_run_originals(run, entries):
    """Only committed new-policy captures; existing historical captures stay intact."""
    run = Path(run).resolve()
    manifests = [run / "windows_capture_manifest.json", run / "collection_manifest.json"]
    manifest = next((json.loads(p.read_text(encoding="utf-8")) for p in manifests if p.is_file()), {})
    if manifest.get("storage_policy") != POLICY: return False
    if manifest.get("status") != "complete": raise ValueError("Cannot transfer an unfinished capture")
    mapping = {}; checked = []
    for source, item in entries:
        source = Path(source).resolve(); target = Path(item["path"]).resolve()
        if run not in source.parents or source.suffix.lower() != ".pcap": raise ValueError("Original source escapes run")
        if target == source or target.parent.name != "originals" or target.name != f"{item['sha256']}.pcap":
            raise ValueError("Invalid original destination")
        if sha256(target) != item["sha256"] or target.stat().st_size != item["bytes"]: raise ValueError("Published original is not intact")
        if source.exists() and (source.stat().st_size != item["bytes"] or sha256(source) != item["sha256"]):
            raise ValueError("Source changed before original transfer")
        mapping[source.relative_to(run).as_posix()] = {**item, "path": os.path.relpath(target, run).replace("\\", "/")}
        checked.append(source)
    receipt = run / RECEIPT
    current = json.loads(receipt.read_text(encoding="utf-8")) if receipt.exists() else {"storage_policy": POLICY, "sources": {}}
    current["sources"].update(mapping)
    temp = receipt.with_name(f".{receipt.name}.{uuid4().hex}.tmp")
    temp.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8"); temp.replace(receipt)
    for source in checked:
        if source.exists(): source.unlink()
    return True

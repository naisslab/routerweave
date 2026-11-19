"""Explicit end-of-round cleanup of disposable collection payloads.

Validated collectors and committed publications invoke the same closeout.
Unvalidated and partly accepted collections remain explicitly pending.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[3]
REPORT = 'collection_round_cleanup.json'
LIFECYCLE_FILES = ('collection_task.json', 'collection_manifest.json', 'windows_capture_manifest.json',
                   'batch_manifest.json', 'ios_single_app_batch_manifest.json',
                   'android_single_app_batch_manifest.json')
PAYLOAD_SUFFIXES = {'.pcap', '.pcapng', '.csv', '.jsonl', '.gz', '.png', '.jpg',
                    '.jpeg', '.webp', '.xml', '.mp4', '.wav', '.bin', '.log'}

def _native(path: Path) -> Path:
    value = str(path.absolute())
    if os.name == 'nt' and not value.startswith('\\\\?\\'):
        return Path('\\\\?\\UNC\\' + value.lstrip('\\') if value.startswith('\\\\') else '\\\\?\\' + value)
    return path


def read(path: Path) -> dict:
    native = _native(path)
    return json.loads(native.read_text(encoding='utf-8-sig')) if native.is_file() else {}


def purpose_for_task(task: dict | None) -> str:
    if not task:
        return 'review'
    meta = task.get('metadata', {})
    if (meta.get('dataset_promotion') == 'disabled'
            or meta.get('formal_sample_units') == 0
            or any(word in task.get('id', '').split('-') for word in ('smoke', 'readiness', 'diagnostic'))):
        return 'validation'
    return 'formal'


def _stamp(path: Path) -> list[int]:
    s = _native(path).stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_nlink]


def _payload(path: Path, owner: Path) -> bool:
    return (path.suffix.lower() in PAYLOAD_SUFFIXES
            or (path.suffix.lower() == '.json' and 'operator_evidence' in path.relative_to(owner).parts[:-1]))


def _handoff_evidence(path: Path, owner: Path) -> bool:
    # These are read by continuation_source/recovery_source and later archived
    # into formal samples. Their hashes must remain stable after closeout.
    relative = path.relative_to(owner).as_posix()
    return (relative == 'environment_events.jsonl'
            or (relative.startswith('platform_evidence/process-') and relative.endswith('.stderr.log')))


def _write_report(run: Path, value: dict) -> None:
    _write_atomic(run / REPORT, value)


def _write_atomic(path: Path, value: dict) -> None:
    temporary = _native(path.with_name(f'.{path.name}.{uuid4().hex}.tmp'))
    with temporary.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')
    temporary.replace(_native(path))


def _workspace(run: Path) -> Path | None:
    return next((p.parent.parent for p in run.parents
                 if p.name == 'collection' and p.parent.name == 'runs'), None)


def closeout_run(run: Path, *, validation_finished: bool = False) -> dict:
    """Automatic collector boundary; an exit code alone is not validation."""
    run = Path(run).absolute()
    root = _workspace(run)
    if root is None:
        return {'status': 'unmanaged', 'reason': 'outside_runs_collection'}
    _safe(run / REPORT, root)
    task = read(run / 'collection_task.json')
    previous = read(run / REPORT)
    if not validation_finished:
        # A second outer wrapper must not undo an inner collector's closeout.
        if previous.get('status') == 'cleaned':
            return previous
        result = {'status': 'pending', 'reason': 'independent_validation_required'}
    elif task.get('artifact_purpose') != 'validation':
        details = task.get('details', {})
        wholly_rejected = (task.get('status') in {'failed', 'cancelled'}
                            and not task.get('completed_units')
                            and details.get('accepted_windows') == 0
                            and (details.get('collection_ready') is False
                                 or details.get('validation_ok') is False))
        if not wholly_rejected:
            result = {'status': 'pending', 'reason': 'publication_or_partial_data_review_required'}
        else:
            result = None
    else:
        result = None
    if result is None:
        plan = plan_cleanup(root, [run])
        if plan['refused']:
            result = {'status': 'pending', 'reason': plan['refused'][0]['reason']}
        else:
            # Persist a preview before applying, including zero-file closeouts.
            _write_report(run, {**previous, 'status': 'planned', 'plan': plan})
            apply_cleanup(plan, root=root)
            return read(run / REPORT)
    result = {**result, 'updated_at': datetime.now(timezone.utc).isoformat()}
    _write_report(run, result)
    return result


def defer_closeout_run(run: Path, *, wait_pid: int) -> None:
    """Close a validated round after its log-owning process exits on Windows."""
    run = Path(run).absolute()
    if os.name != 'nt' or _workspace(run) is None or type(wait_pid) is not int or wait_pid <= 0:
        raise ValueError('Deferred closeout needs a managed Windows run and exact owner PID')
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    # WaitForExit holds the selected process object; it never kills a process.
    command = (f"$p=Get-Process -Id {wait_pid} -ErrorAction SilentlyContinue;"
               "if($p -and -not $p.WaitForExit(180000)){exit 2};"
               f"$env:PYTHONPATH={quote(ROOT / 'src')};Set-Location -LiteralPath {quote(ROOT)};"
               f"& {quote(sys.executable)} -B -m collection.runtime.run_retention "
               f"--closeout-run {quote(run)} --validation-finished;exit $LASTEXITCODE")
    subprocess.Popen(['powershell', '-NoProfile', '-WindowStyle', 'Hidden', '-Command', command],
                     cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))


def _safe(path: Path, root: Path) -> Path:
    path = path.absolute()
    base = root / 'runs/collection'
    if not path.is_relative_to(base) or path == base:
        raise ValueError(f'Not a collection child: {path}')
    for p in (path, *path.parents):
        if p == root:
            break
        native = _native(p)
        if native.is_symlink() or (native.exists() and getattr(native.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError(f'Reparse path: {p}')
    return path


def _source_runs(root: Path) -> set[Path]:
    """Protect capture runs referenced by published dataset manifests."""
    result = set()
    for family, pattern in [('screen-time', '*/*/*/*/dataset_manifest.json'),
                            ('iot', '*/*/*/dataset_manifest.json'),
                            ('iot-v2', '*/*/*/dataset_manifest.json')]:
        for manifest in (root / 'datasets' / family).glob(pattern):
            value = read(manifest)
            refs = [r.get('source_run') for r in value.get('samples', [])]
            refs += value.get('source_runs', [])
            refs += [r.get('run') for r in value.get('sources', [])]
            for ref in refs:
                if not isinstance(ref, str):
                    continue
                spelling = ref.replace('\\', '/')
                p = Path(spelling)
                if not p.is_absolute():
                    p = root / p
                elif not p.is_relative_to(root) and '/runs/' in spelling.casefold():
                    p = root / spelling[spelling.casefold().index('/runs/') + 1:]
                result.add(p.absolute())
    return result


def plan_cleanup(root: Path, runs: list[Path], validation_runs: list[Path] = ()) -> dict:
    root = root.resolve()
    runs = [p if p.is_absolute() else root / p for p in runs]
    validation_runs = [p if p.is_absolute() else root / p for p in validation_runs]
    explicit = {p.absolute() for p in validation_runs}
    published = _source_runs(root)
    selected: dict[str, dict] = {}
    owners = []
    refused = []
    for supplied in dict.fromkeys([*runs, *validation_runs]):
        run = _safe(supplied, root)
        task = read(_safe(run / 'collection_task.json', root))
        purpose = 'validation' if run in explicit else task.get('artifact_purpose')
        if run in explicit and task.get('artifact_purpose') == 'formal':
            refused.append({'run': str(run), 'reason': 'explicit_formal_run'})
            continue
        details = task.get('details', {})
        # An explicit independent rejection permits discarding a wholly failed
        # attempt; a partial accepted collection remains pending publication.
        failed = (task.get('status') in {'failed', 'cancelled'}
                  and not task.get('completed_units')
                  and (details.get('collection_ready') is False or details.get('validation_ok') is False))
        if purpose != 'validation' and not failed:
            refused.append({'run': str(run), 'reason': 'formal_or_unclassified_data'})
            continue
        manifests = [read(_safe(run / name, root)) for name in LIFECYCLE_FILES[1:]]
        status = task.get('status') or next((m.get('status') for m in manifests if m.get('status')), None)
        if any(m.get('status') in {'running', 'starting', 'collecting', 'stopping'} for m in manifests):
            refused.append({'run': str(run), 'reason': 'capture_not_terminal'})
            continue
        if status not in {'complete', 'failed', 'cancelled', 'stopped', 'saved'} | ({'blocked'} if purpose == 'validation' else set()):
            # --validation-run explicitly confirms a closed legacy test. Bare
            # diagnostics can have no lifecycle report; an existing live state
            # still overrides the operator classification.
            if status or run not in explicit:
                refused.append({'run': str(run), 'reason': 'not_terminal'})
                continue
        if any(run.is_relative_to(source) for source in published):
            refused.append({'run': str(run), 'reason': 'published_source_requires_publication_retirement'})
            continue
        guards = []
        for name in (*LIFECYCLE_FILES, 'collection_validation.json', 'strategy_validation.json'):
            p = _safe(run / name, root)
            guards.append({'path': str(p), 'stamp': _stamp(p) if _native(p).is_file() else None})
        owners.append({'run': str(run), 'purpose': purpose or 'failed', 'guards': guards,
                       'task_state': task,
                       'status': status, 'task_id': task.get('task_id'), 'message': task.get('message')})
        def walk_error(error):
            raise error
        for directory, dirs, names in os.walk(_native(run), followlinks=False, onerror=walk_error):
            parent = run / Path(directory).relative_to(_native(run))
            if parent != run and (any(_native(parent / n).is_file() for n in LIFECYCLE_FILES)
                                  or parent in published):
                # A validation campaign may contain a formal or live child.
                dirs[:] = []
                continue
            for name in list(dirs):
                _safe(parent / name, root)
            for name in names:
                p = parent / name
                if not _payload(p, run) or _handoff_evidence(p, run):
                    continue
                _safe(p, root)
                # Only remove run paths. Dataset files, including another link
                # to these same bytes, are never deletion targets.
                selected[str(p)] = {'path': str(p), 'stamp': _stamp(p), 'owner': str(run)}
    return {'schema_version': 'collection-round-cleanup-v1', 'root': str(root),
            'owners': owners, 'candidates': list(selected.values()), 'refused': refused,
            'bytes': sum(r['stamp'][2] for r in selected.values())}


def apply_cleanup(plan: dict, *, root: Path) -> dict:
    root = root.resolve()
    if plan.get('schema_version') != 'collection-round-cleanup-v1' or plan.get('root') != str(root):
        raise ValueError('Cleanup plan does not belong to this workspace')
    published = _source_runs(root)
    for owner in plan['owners']:
        run = _safe(Path(owner['run']), root)
        _safe(run / REPORT, root)
        if any(run.is_relative_to(source) for source in published):
            raise ValueError('Run was published after cleanup preview')
        if read(run / 'collection_task.json') != owner['task_state']:
            raise ValueError('Run restarted or task state changed after preview')
        for guard in owner['guards']:
            path = _safe(Path(guard['path']), root)
            current = _stamp(path) if _native(path).is_file() else None
            if current != guard['stamp']:
                raise ValueError('Run state changed after preview')
    # Check every target before removing the first file.
    owner_paths = {owner['run'] for owner in plan['owners']}
    for row in plan['candidates']:
        p = _safe(Path(row['path']), root)
        owner = Path(row['owner'])
        if (row['owner'] not in owner_paths or not p.is_relative_to(owner) or not _payload(p, owner)
                or _stamp(p) != row['stamp']):
            raise ValueError('Cleanup target changed or escapes its run')
        for ancestor in p.parents:
            if ancestor in published:
                raise ValueError('A candidate became a published source after preview')
            if ancestor == owner:
                break
            if any(_native(ancestor / n).is_file() for n in LIFECYCLE_FILES):
                raise ValueError('A nested collection started after preview')
    removed = {}
    identities: dict[tuple[int, int], int] = {}
    for row in plan['candidates']:
        p = _safe(Path(row['path']), root)
        current = _stamp(p)
        identity = tuple(current[:2])
        expected_links = row['stamp'][4] - identities.get(identity, 0)
        if current[:4] != row['stamp'][:4] or current[4] != expected_links:
            raise ValueError('Cleanup target changed immediately before deletion')
        _native(p).unlink()
        identities[identity] = identities.get(identity, 0) + 1
        count, size = removed.get(row['owner'], (0, 0))
        removed[row['owner']] = count + 1, size + row['stamp'][2]
    for owner in plan['owners']:
        run = Path(owner['run'])
        previous = read(run / REPORT)
        count, size = removed.get(str(run), (0, 0))
        receipt = {**owner, 'status': 'cleaned', 'finished_at': datetime.now(timezone.utc).isoformat(),
                   'deleted_files': previous.get('deleted_files', 0) + count,
                   'deleted_bytes': previous.get('deleted_bytes', 0) + size}
        _write_report(run, receipt)
    return {'deleted_files': len(plan['candidates']), 'deleted_bytes': plan['bytes'],
            'refused': plan['refused']}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--run', action='append', type=Path, default=[])
    parser.add_argument('--validation-run', action='append', type=Path, default=[],
                        help='Explicitly classify a legacy/IoT test at the closed round boundary')
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--closeout-run', type=Path, help='Automatic validated round boundary')
    parser.add_argument('--validation-finished', action='store_true')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.closeout_run:
        if args.plan or args.apply or args.run or args.validation_run:
            parser.error('--closeout-run cannot be combined with plan/apply inputs')
        result = closeout_run(args.closeout_run, validation_finished=args.validation_finished)
        print(json.dumps(result, indent=2))
        return 0 if result.get('status') == 'cleaned' else 2
    if not args.plan:
        parser.error('--plan is required for preview/apply')
    if args.apply:
        result = apply_cleanup(read(args.plan), root=args.root)
    else:
        result = plan_cleanup(args.root, args.run, args.validation_run)
        args.plan.parent.mkdir(parents=True, exist_ok=True)
        args.plan.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in {'candidates', 'owners'}}, indent=2))
    return 1 if result['refused'] else 0


if __name__ == '__main__':
    raise SystemExit(main())

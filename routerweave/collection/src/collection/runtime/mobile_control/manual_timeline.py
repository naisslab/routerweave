"""Shared operator schedule: planned time is never actual behavior evidence."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import uuid

from .manual_ground_truth import timestamp, write_json


def validate_plan(plan):
    if not isinstance(plan, dict):
        raise ValueError('Timeline must be an object')
    if plan.get('version') != 1 or plan.get('mode') not in ('Screen Time', 'IoT Events'):
        raise ValueError('Unsupported timeline format')
    rows = plan.get('steps')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise ValueError('Add between 1 and 500 steps')
    clean = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Each step must be an object')
        try:
            seconds = float(row.get('seconds', 0))
            pre = float(row.get('pre_seconds', 0))
        except (ValueError, TypeError):
            raise ValueError('Duration must be a number') from None
        if not math.isfinite(seconds) or not 0 < seconds <= 86400 or not math.isfinite(pre) or not 0 <= pre < seconds:
            raise ValueError('Each duration must be positive and longer than its baseline')
        kind = row.get('kind', 'activity')
        label, app = str(row.get('label', '')).strip(), str(row.get('app', '')).strip()
        if kind not in ('activity', 'wait', 'transition') or not label or len(label) > 160 or len(app) > 160:
            raise ValueError('Choose an activity or wait and a short label')
        clean.append(dict(kind=kind, label=label, app=app, seconds=seconds, pre_seconds=pre))
        if 'suggested_start_seconds' in row:
            suggested = float(row['suggested_start_seconds'])
            previous_end = (clean[-2].get('suggested_start_seconds', 0) + clean[-2]['seconds']) if len(clean)>1 else 0
            if not math.isfinite(suggested) or suggested < previous_end:
                raise ValueError('Suggested start times must be finite, nonnegative and non-overlapping')
            clean[-1]['suggested_start_seconds'] = suggested
    try:
        gap = float(plan.get('transition_seconds', 10))
    except (ValueError, TypeError):
        raise ValueError('Transition duration must be a number') from None
    if not math.isfinite(gap) or not 0 <= gap <= 3600:
        raise ValueError('Transition duration must be between 0 and 3600 seconds')
    expanded = []
    for i, row in enumerate(clean):
        expanded.append(row)
        if gap and row['kind'] == 'activity' and i + 1 < len(clean) and clean[i+1]['kind'] == 'activity':
            expanded.append(dict(kind='transition', label='Switch task', app=clean[i+1]['app'], seconds=gap, pre_seconds=0))
    return dict(version=1, mode=plan['mode'], transition_seconds=gap, steps=expanded)


class MarkPacedProgress:
    """Per-device task budget; operator marks, never wall time, end activities."""
    def __init__(self, steps, at):
        self.steps, self.index, self.phase = steps, 0, 'ready'
        self.entered, self.task_started = at, None
        self.actual = []

    def view(self, at):
        # Explicit baseline/quiet waits run from the actual preceding boundary.
        while self.index < len(self.steps) and self.steps[self.index]['kind'] == 'wait':
            duration = self.steps[self.index]['seconds']
            if at['monotonic'] - self.entered['monotonic'] < duration:
                return dict(index=self.index, phase='wait', elapsed=at['monotonic']-self.entered['monotonic'], seconds=duration)
            self.entered = dict(pc_epoch=self.entered['pc_epoch']+duration, monotonic=self.entered['monotonic']+duration)
            self.index += 1
        if self.index >= len(self.steps):
            return dict(index=None, phase='complete', elapsed=0, seconds=0)
        step = self.steps[self.index]
        phase = 'switching' if step['kind'] == 'transition' else self.phase
        elapsed = at['monotonic'] - (self.task_started or self.entered)['monotonic']
        return dict(index=self.index, phase=phase, elapsed=max(0, elapsed), seconds=step['seconds'])

    def next_activity(self):
        return next((i for i in range(self.index, len(self.steps)) if self.steps[i]['kind'] == 'activity'), None)

    def begin(self, at):
        state = self.view(at)
        if state['phase'] in ('wait', 'complete', 'running'):
            raise ValueError('This track is not ready for a new task')
        index = self.next_activity()
        if index is None:
            raise ValueError('No remaining task')
        self.index, self.phase, self.task_started = index, 'running', dict(at)

    def end(self, at):
        if self.phase != 'running':
            return
        self.actual.append(dict(index=self.index, start=self.task_started, end=dict(at),
                                duration_seconds=at['monotonic']-self.task_started['monotonic']))
        self.index += 1
        self.phase, self.task_started, self.entered = 'ready', None, dict(at)


class OperatorTimeline:
    def __init__(self, capture_root, plan, *, at=None, clock=None, target=None, mark_paced=False):
        self.plan = validate_plan(plan)
        self.started = at or timestamp()
        self.progress = MarkPacedProgress(self.plan['steps'], self.started) if mark_paced else None
        self.root = Path(capture_root) / ('timeline-' + uuid.uuid4().hex[:10])
        self.root.mkdir(exist_ok=False)
        self.events, self.current, self.stopped, self.ended = [], -1, False, None
        self.offsets = []
        total = 0.0
        for step in self.plan['steps']:
            self.offsets.append(total)
            total += step['seconds']
        self.duration = total
        write_json(self.root / 'plan.json', {**self.plan, 'started': self.started, 'clock': clock or {},
                   'target': target, 'timing_basis': 'operator_marks' if self.progress else 'fixed_monotonic_schedule',
                   'planned_times_are_not_behavior_evidence': True})
        self.append('timeline_start', self.started)
        self.export()

    def append(self, event, at, **fields):
        row = dict(event=event, pc_epoch=at['pc_epoch'], monotonic=at['monotonic'], **fields)
        with (self.root / 'events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        self.events.append(row)
        return row

    def index_at(self, at):
        if self.progress:
            return self.progress.view(at)['index']
        elapsed = at['monotonic'] - self.started['monotonic']
        return next((i for i, (offset, step) in enumerate(zip(self.offsets, self.plan['steps']))
                     if offset <= elapsed < offset + step['seconds']), None)

    def advance(self, at=None):
        if self.stopped:
            return None
        at = at or timestamp()
        index = self.index_at(at)
        if not self.progress and at['monotonic'] >= self.started['monotonic'] + self.duration:
            self.finish('schedule_elapsed', at)
            return None
        if index is not None and index != self.current:
            self.append('step_prompt', at, step_index=index,
                        planned_offset_seconds=self.offsets[index])
            self.current = index
            self.export()
        return index

    def record(self, kind, label, at, *, reference='', app='', outcome=None):
        # Results refer to their command's step, even when confirmation is late.
        prior_kind = 'task_start' if kind == 'task_end' else 'command'
        prior = next((e for e in self.events if e['event'] == 'actual' and reference
                      and e.get('reference') == reference and e.get('kind') == prior_kind), None)
        if self.stopped and not (kind in ('result', 'task_end', 'void') and prior):
            return
        if reference and any(e['event'] == 'actual' and e.get('kind') == kind and e.get('reference') == reference for e in self.events):
            self.export()
            return
        if self.progress and kind == 'task_start':
            self.progress.begin(at)
        index = prior['step_index'] if kind in ('result', 'task_end', 'void') and prior else self.index_at(at)
        step = self.plan['steps'][index] if index is not None else None
        expected = bool(step and step['kind'] in ('activity', 'transition') and step['label'] == label
                        and (not step['app'] or step['app'] == app))
        planned = self.offsets[index] + step['pre_seconds'] if step else None
        self.append('actual', at, kind=kind, label=label, app=app, reference=reference,
                    outcome=outcome, step_index=index, matches_plan=expected,
                    delay_seconds=at['monotonic'] - self.started['monotonic'] - planned if planned is not None and not self.progress else None)
        if self.progress and kind == 'task_end':
            self.progress.end(at)
        self.export()

    def finish(self, reason, at=None):
        if self.stopped:
            return
        self.ended = self.append('timeline_stop', at or timestamp(), reason=reason)
        self.stopped = True
        self.export()

    def export(self):
        actual = [e for e in self.events if e['event'] == 'actual']
        voided = {e['reference'] for e in actual if e['kind'] == 'void'}
        steps = []
        end = (self.ended or self.events[-1])['monotonic'] - self.started['monotonic']
        for i, step in enumerate(self.plan['steps']):
            records = [dict(e, voided=e['reference'] in voided) for e in actual if e['step_index'] == i]
            matched = any(not e['voided'] and e['matches_plan'] and e['kind'] in ('task_start', 'command') for e in records)
            status = ('not_reached' if self.stopped and end <= self.offsets[i] else
                      'wait' if step['kind'] == 'wait' else 'recorded' if matched else
                      'not_recorded' if end >= self.offsets[i] + step['seconds'] or self.stopped else 'pending')
            actual_duration = None
            if self.progress:
                actual_duration = next((a['duration_seconds'] for a in self.progress.actual if a['index'] == i), None)
                status = 'recorded' if matched else 'not_recorded' if self.stopped else 'pending'
            steps.append(dict(index=i, **step, planned_offset_seconds=self.offsets[i],
                              planned_pc_epoch=None if self.progress else self.started['pc_epoch'] + self.offsets[i],
                              actual_duration_seconds=actual_duration,
                              duration_met=actual_duration >= step['seconds'] if actual_duration is not None else None,
                              status=status, actual=records))
        write_json(self.root / 'summary.json', dict(stopped=self.stopped, steps=steps,
                   reason=self.ended.get('reason') if self.ended else None,
                   evidence_basis='operator_input', independent_device_verification=False))

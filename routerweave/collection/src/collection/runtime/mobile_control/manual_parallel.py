import os
"""One operator session coordinating existing device capture/annotation owners."""
from dataclasses import replace
from pathlib import Path
import json
import re
import uuid
import copy

from collection.runtime.registry.tasks import require_collection_task
from .manual_ground_truth import ManualGroundTruthSession, timestamp, write_json
from .manual_marker import MarkerSession, marker_protocol
from .manual_timeline import OperatorTimeline, validate_plan
from .manual_network import resolve_task_identity, match_router_client, read_router_clients, phone_source
from .device_ip import detect_android_wifi_ip, detect_ios_wifi_ip, validate_router_visible_ip


def parallel_plan(value, task_loader=require_collection_task):
    if value.get('version') != 2 or not isinstance(value.get('devices'), list) or not 1 <= len(value['devices']) <= 16:
        raise ValueError('Use version 2 with 1–16 device tracks')
    devices, ids = [], set()
    for source in value['devices']:
        key = source.get('id', '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', key) or key in ids:
            raise ValueError('Each device needs a unique short id')
        ids.add(key)
        task = task_loader(source['collection_task_id'])
        mode = 'IoT Events' if task['kind'] == 'iot' else 'Screen Time'
        if task['kind'] not in ('iot', 'manual'):
            raise ValueError('Choose a registered manual or IoT collection task')
        plan = validate_plan(dict(version=1, mode=mode, steps=source['steps'],
                                  transition_seconds=source.get('transition_seconds', value.get('transition_seconds', 10))))
        if mode == 'IoT Events':
            allowed = {r['key'] for r in task['breakdown']}
            for step in plan['steps']:
                if step['kind'] == 'activity':
                    if step['label'] not in allowed:
                        raise ValueError(f"{key}: unsupported registered action {step['label']}")
                    protocol = marker_protocol(task, step['label'])
                    step['pre_seconds'] = protocol['pre_seconds']
                    if step['seconds'] <= sum(protocol[k] for k in ('pre_seconds', 'post_seconds', 'cooldown_seconds')):
                        raise ValueError(f'{key}: action duration must include baseline and quiet period')
        devices.append(dict(id=key, name=source.get('name', task['title']),
                            collection_task_id=task['id'], network=source.get('network', {}),
                            mode=mode, plan=plan))
    return dict(version=2, devices=devices)


def device_identity(device, task, router):
    network = device['network']
    method = network.get('method', 'registry' if task['kind'] == 'iot' else task['platform'])
    source = phone_source(device)
    if source == 'participant' and (method != 'mac' or not network.get('mac')):
        raise ValueError('Register the participant phone before starting collection.')
    if source == 'lab' and method != task['platform']:
        raise ValueError('The lab phone configuration differs from the planned platform. Select another phone source.')
    if method == 'registry':
        return resolve_task_identity(task, router)
    if method == 'android':
        ip = detect_android_wifi_ip(network.get('serial', os.environ.get("ANDROID_SERIAL", "")))
    elif method == 'ios':
        ip = detect_ios_wifi_ip(network.get('wda_url', 'http://127.0.0.1:8100'))
    elif method == 'mac':
        mac = network.get('mac', '').lower()
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
            raise ValueError('Device network identity needs a valid MAC')
        identity = match_router_client(dict(mac=mac, scope='direct_device', identity_key=device['id']),
                                      read_router_clients(router))
        if network.get('participant_id'):
            identity['participant_id'] = network['participant_id']
        if source:
            identity['phone_source'] = source
        return identity
    else:
        raise ValueError('Use registry, Android, iOS, or MAC address discovery')
    if not ip:
        raise ValueError(f"{device['name']}: current Wi-Fi address not available")
    identity = dict(ip=validate_router_visible_ip(ip), method=method, scope='direct_device')
    if source:
        identity['phone_source'] = source
    return identity


class ParallelSession:
    def __init__(self, parent, plan, router, *, identity_resolver=device_identity,
                 manual_factory=ManualGroundTruthSession, marker_factory=MarkerSession,
                 task_loader=require_collection_task):
        self.plan = parallel_plan(plan, task_loader)
        self.root = Path(parent) / ('parallel-' + uuid.uuid4().hex[:12])
        self.router, self.resolve = router, identity_resolver
        self.manual_factory, self.marker_factory, self.task_loader = manual_factory, marker_factory, task_loader
        self.sessions, self.timelines, self.identities = {}, {}, {}
        self.state, self.error, self.started = 'idle', '', None
        self.pending = {}

    def save(self):
        write_json(self.root / 'parallel_session.json', dict(status=self.state, error=self.error,
                   started=self.started, devices=[dict(d, identity=self.identities.get(d['id']),
                   source_run=str(self.sessions[d['id']].root) if d['id'] in self.sessions else None)
                   for d in self.plan['devices']], planned_time_is_not_actual_behavior=True))

    def start(self):
        if self.state != 'idle':
            raise ValueError('Session already started')
        self.root.mkdir(parents=True, exist_ok=False)
        self.state = 'preparing'; self.save()
        try:
            addresses = set()
            for d in self.plan['devices']:
                task = self.task_loader(d['collection_task_id'])
                identity = self.resolve(d, task, self.router)
                address = validate_router_visible_ip(identity['ip'])
                if address in addresses:
                    raise ValueError('Two tracks resolve to the same address; separate physical devices are required')
                addresses.add(address); self.identities[d['id']] = identity
            for d in self.plan['devices']:
                key, identity = d['id'], self.identities[d['id']]
                router = replace(self.router, phone_ip=identity['ip'])
                if d['mode'] == 'IoT Events':
                    session = self.marker_factory(self.root / key, router)
                    self.sessions[key] = session
                    session.start_capture(d['collection_task_id'], router,
                                          identity_resolver=lambda _task, _router, identity=identity: identity)
                else:
                    session = self.manual_factory(self.root / key, router, d['collection_task_id'])
                    self.sessions[key] = session
                    session.start()
                    session.manifest['network_identity'] = identity
                    write_json(session.root / 'collection_manifest.json', session.manifest)
            if problem := self.health():
                raise RuntimeError(problem)
            self.started = timestamp()
            for d in self.plan['devices']:
                s = self.sessions[d['id']]
                self.timelines[d['id']] = OperatorTimeline(s.root, d['plan'], at=self.started,
                                                         clock=s.manifest.get('clock_start'), target=d['id'],
                                                         mark_paced=d['mode'] == 'Screen Time')
            self.state = 'running'; self.save()
        except Exception as exc:
            self.error = str(exc)
            self.stop(error=self.error)
            raise

    def device(self, key):
        return next(d for d in self.plan['devices'] if d['id'] == key)

    def mark(self, key, label, app, *, end=False, outcome=None, at=None):
        if self.state != 'running':
            raise ValueError('Start the session first')
        at = at or timestamp()
        d, s, timeline = self.device(key), self.sessions[key], self.timelines[key]
        if d['mode'] == 'IoT Events':
            if outcome:
                command = self.pending[key]
                s.confirm(command['event_id'], outcome, at=at)
                timeline.record('result', command['action'], at, reference=command['event_id'], app=command['app'], outcome=outcome)
                del self.pending[key]
            else:
                if key in self.pending:
                    raise ValueError('Confirm the previous command first')
                index = timeline.index_at(at)
                if index is None or timeline.plan['steps'][index]['kind'] != 'activity':
                    raise ValueError('Wait for an activity before sending a command')
                protocol = marker_protocol(self.task_loader(d['collection_task_id']), label)
                baseline = self.started['monotonic'] + timeline.offsets[index]
                if at['monotonic'] < baseline + protocol['pre_seconds']:
                    raise ValueError('Baseline is still running')
                prior = next((e for e in reversed(s.events) if e['event'] in ('event_result', 'event_mark')), None)
                if prior and at['monotonic'] < prior['monotonic'] + protocol['post_seconds'] + protocol['cooldown_seconds']:
                    raise ValueError('Quiet period is still running')
                payload = dict(request_id=str(uuid.uuid4()), task_id=d['collection_task_id'], action=label,
                               input_source='button', baseline_start_monotonic=baseline, baseline_ready=True,
                               pre_seconds=protocol['pre_seconds'], post_seconds=protocol['post_seconds'],
                               cooldown_seconds=protocol['cooldown_seconds'], requires_outcome=True)
                row = s.mark(payload, at=at)
                self.pending[key] = dict(row, app=app)
                timeline.record('command', label, at, reference=row['event_id'], app=app)
        else:
            progress = timeline.progress
            if progress and not end and not s.active:
                state = progress.view(at)
                if state['phase'] in ('wait', 'complete'):
                    return
            if s.active and not end and s.active['label'] == label.strip() and s.active['app'] == app.strip():
                # A mark on another device must not split or reset this task.
                return
            if progress and not end:
                prospective = copy.deepcopy(progress)
                if s.active:
                    prospective.end(at)
                prospective.begin(at)
            if not end:
                if timeline.stopped:
                    raise ValueError('This device timeline has ended')
                if not label.strip() or len(label) > 160 or len(app) > 160:
                    raise ValueError('Task and app must be at most 160 characters; task is required')
                if problem := s.health_error():
                    raise RuntimeError(problem)
            if s.active:
                previous = dict(s.active)
                s.end_segment(at=at)
                timeline.record('task_end', previous['label'], at, reference=previous['segment_id'], app=previous['app'])
            if not end:
                s.begin_segment(label, app, at=at)
                timeline.record('task_start', label, at, reference=s.active['segment_id'], app=app)

    def health(self):
        for key, s in self.sessions.items():
            status = s.capture_status() if self.device(key)['mode'] == 'IoT Events' else {'error': s.health_error()}
            if status.get('error'):
                return f'{key}: {status["error"]}'
        return ''

    def stop(self, error=''):
        if self.state in ('saved', 'failed'):
            return
        self.state = 'stopping'; self.error = error or self.error
        errors = []
        for key, s in self.sessions.items():
            try:
                timeline = self.timelines.get(key)
                previous = dict(getattr(s, 'active', None) or {})
                if self.device(key)['mode'] == 'IoT Events':
                    if s.manifest.get('status') == 'recording':
                        s.stop()
                elif s.state == 'recording':
                    s.stop(error=self.error)
                owner = getattr(s, 'capture_session', s)
                capture = getattr(owner, 'capture', None)
                proc = getattr(capture, 'proc', None)
                if proc is not None and proc.poll() is None:
                    owner._stop_capture()
                    if proc.poll() is None:
                        raise RuntimeError('Capture still running; retry Stop & save')
                if timeline:
                    if previous:
                        end = next(e for e in reversed(s.events) if e['event'] == 'segment_end')
                        timeline.record('task_end', previous['label'], end, reference=previous['segment_id'], app=previous['app'])
                    timeline.finish('capture_stopped')
            except Exception as exc:
                errors.append(f'{key}: {exc}')
        self.error = '; '.join(filter(None, [self.error, *errors]))
        self.state = 'cleanup_required' if errors else 'failed' if self.error else 'saved'
        self.save()
        if errors:
            raise RuntimeError(self.error)

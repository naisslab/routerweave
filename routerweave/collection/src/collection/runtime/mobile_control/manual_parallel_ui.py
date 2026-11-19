"""Parallel device tracks and one capture/timeline start button."""
import json
import math
from pathlib import Path
import queue
import threading
import uuid
from collections import deque
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from .manual_parallel import ParallelSession, parallel_plan
from .manual_ground_truth import timestamp, write_json
from .manual_timeline import validate_plan, MarkPacedProgress
from .collection import RouterCaptureConfig
from .manual_network import (read_router_clients, registration_candidates, registered_network,
                             PHONE_SOURCES, phone_source, phone_network_for_source)


class ParallelWindow:
    def __init__(self, parent, args, plan):
        self.parent, self.args = parent, args
        self.plan_metadata = {k: v for k, v in plan.items() if k not in ('version', 'devices')}
        self.plan = parallel_plan(plan)
        self.root = tk.Toplevel(parent)
        self.root.title('Collection · Multi-device timeline')
        self.root.geometry('1120x800'); self.root.minsize(960, 640)
        self.session, self.busy, self.closing = None, False, False
        self.demo_started, self.demo_elapsed, self.demo_marks = None, 0, []
        self.demo_progress = {}
        self.messages, self.rows = queue.Queue(), {}
        self.jobs, self.stop_requested = deque(), False
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        header = ttk.Frame(self.root, padding=20); header.pack(fill='x')
        ttk.Label(header, text='Multi-device timeline', font=('Segoe UI', 18, 'bold')).pack(side='left')
        self.clock = tk.StringVar(value='00:00')
        ttk.Label(header, textvariable=self.clock, font=('Consolas', 20)).pack(side='right')
        bar = ttk.Frame(self.root, padding=(20, 0, 20, 12)); bar.pack(fill='x')
        self.start_button = ttk.Button(bar, text='Start session', style='Primary.TButton', command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(bar, text='Stop & save', command=self.stop, state='disabled')
        self.stop_button.pack(side='left', padx=8)
        self.save_button = ttk.Button(bar, text='Save plan', command=self.save_plan)
        self.save_button.pack(side='left')
        self.demo_button = ttk.Button(bar, text='Try demo', command=self.start_demo)
        self.demo_button.pack(side='left', padx=8)
        self.status = tk.StringVar(value='Ready · all devices share one clock')
        ttk.Label(bar, textvariable=self.status, wraplength=600).pack(side='left', padx=16)
        viewport = tk.Canvas(self.root, highlightthickness=0, bg='#f4f6f8')
        scroll = ttk.Scrollbar(self.root, orient='vertical', command=viewport.yview)
        scroll.pack(side='right', fill='y'); viewport.pack(fill='both', expand=True)
        viewport.configure(yscrollcommand=scroll.set)
        self.body = ttk.Frame(viewport, padding=(20, 0, 20, 20))
        item = viewport.create_window(0, 0, window=self.body, anchor='nw')
        viewport.bind('<Configure>', lambda e: viewport.itemconfigure(item, width=e.width))
        self.body.bind('<Configure>', lambda _e: viewport.configure(scrollregion=viewport.bbox('all')))
        self.build()
        self.root.after(100, self.tick)

    def serializable(self):
        return dict(getattr(self, 'plan_metadata', {}), version=2, devices=[dict(id=d['id'], name=d['name'], collection_task_id=d['collection_task_id'],
                    network=d['network'], transition_seconds=d['plan']['transition_seconds'], steps=d['plan']['steps'])
                    for d in self.plan['devices']])

    def build(self):
        for child in self.body.winfo_children():
            child.destroy()
        self.rows = {}
        for device in self.plan['devices']:
            frame = tk.Frame(self.body, bg='white', padx=14, pady=12)
            frame.pack(fill='x', pady=(0, 12))
            info = tk.StringVar(value=device['name'])
            tk.Label(frame, textvariable=info, bg='white', fg='#183e4c', font=('Segoe UI', 12, 'bold'), anchor='w').pack(fill='x')
            network_bar = ttk.Frame(frame); network_bar.pack(fill='x', pady=(2, 6))
            registration, source_choice = None, None
            if device['mode'] == 'Screen Time':
                source = phone_source(device)
                if source:
                    source_var = tk.StringVar(value=PHONE_SOURCES[source])
                    source_choice = ttk.Combobox(network_bar, textvariable=source_var,
                                  values=tuple(PHONE_SOURCES.values()), state='readonly', width=23)
                    source_choice.pack(side='left', padx=(0, 8))
                    source_choice.bind('<<ComboboxSelected>>', lambda _e, key=device['id'], var=source_var:
                                       self.select_phone_source(key, next(k for k,v in PHONE_SOURCES.items() if v==var.get())))
                if source != 'lab':
                    registration = ttk.Button(network_bar, text='Register device / detect IP',
                        command=lambda key=device['id']: self.register_device(key))
                    registration.pack(side='left')
                else:
                    model = 'Android · Redmi 14R 5G' if device['collection_task_id'].startswith('android') else 'iPhone'
                    ttk.Label(network_bar, text=f'{model} · IP detected at start').pack(side='left', padx=8)
                registered = device['network'].get('registration', {})
                if registered:
                    ttk.Label(network_bar, text=f"{device['network'].get('participant_id', '')} · Registered IP {registered['ip']} · Rechecked at start").pack(side='left', padx=12)
            canvas = tk.Canvas(frame, bg='white', height=78, highlightthickness=0); canvas.pack(fill='x')
            form = tk.Frame(frame, bg='white'); form.pack(fill='x')
            task, app = tk.StringVar(), tk.StringVar()
            for column, (title, variable) in enumerate((('Task', task), ('App', app))):
                tk.Label(form, text=title, bg='white', fg='#60727d').grid(row=0, column=column, sticky='w')
                ttk.Entry(form, textvariable=variable).grid(row=1, column=column, sticky='ew', padx=(0, 10))
                form.columnconfigure(column, weight=1)
            key = device['id']
            mark = ttk.Button(form, text='Mark start', style='Primary.TButton', command=lambda key=key: self.mark(key))
            mark.grid(row=1, column=2, padx=4)
            if device['mode'] == 'IoT Events':
                mark.configure(text='Command sent')
            outcome = tk.StringVar(value='success')
            if device['mode'] == 'IoT Events':
                choice = ttk.Combobox(form, textvariable=outcome, values=('success', 'failed', 'uncertain'), state='readonly', width=10)
                choice.grid(row=1, column=3, padx=4)
                end = ttk.Button(form, text='Confirm', command=lambda key=key: self.mark(key, confirm=True))
            else:
                end = None
            if end is not None:
                end.grid(row=1, column=4)
            self.rows[key] = dict(device=device, info=info, canvas=canvas, task=task, app=app,
                                  mark=mark, end=end, outcome=outcome, index=None, blocks=[], registration=registration,
                                  phone_source=source_choice)
            canvas.bind('<Configure>', lambda _e, key=key: self.render(key))
            canvas.bind('<Double-1>', lambda e, key=key: self.edit_step(key, e.x))
            self.render(key)
    def progress_for(self, key):
        if key in getattr(self, 'demo_progress', {}):
            return self.demo_progress[key]
        if self.session and key in getattr(self.session, 'timelines', {}):
            return self.session.timelines[key].progress
        return None

    def edit_step(self, key, x):
        if self.busy or self.session or self.demo_started is not None:
            return
        row = self.rows[key]
        index = next((i for i, (left, right) in enumerate(row['blocks']) if left <= x <= right), None)
        if index is None:
            return
        step = row['device']['plan']['steps'][index]
        dialog = tk.Toplevel(self.root); dialog.title('Edit step'); dialog.transient(self.root); dialog.grab_set()
        values = {}
        for i, key_field in enumerate(('label', 'app', 'seconds')):
            ttk.Label(dialog, text={'label': 'Task', 'app': 'App', 'seconds': 'Seconds'}[key_field]).grid(row=i, column=0, padx=12, pady=8)
            values[key_field] = tk.StringVar(value=str(step[key_field]))
            ttk.Entry(dialog, textvariable=values[key_field], width=36).grid(row=i, column=1, padx=12, pady=8)
        def save():
            original = dict(step)
            try:
                step.update({k: v.get() for k, v in values.items()})
                self.plan = parallel_plan(self.serializable())
                dialog.destroy(); self.build()
            except (ValueError, TypeError) as exc:
                step.clear(); step.update(original)
                messagebox.showerror('Timeline', str(exc), parent=dialog)
        ttk.Button(dialog, text='Done', command=save).grid(row=3, column=1, sticky='e', padx=12, pady=12)

    def save_plan(self):
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension='.json', filetypes=[('Timeline', '*.json')])
        if path:
            write_json(path, self.serializable())

    def select_phone_source(self, key, source):
        if self.busy or self.session or self.demo_started is not None:
            return
        device = self.rows[key]['device']
        device['network'] = phone_network_for_source(device, source)
        participant = getattr(self, 'plan_metadata', {}).get('experiment', {}).get('participant_id', '')
        prefix = participant + ' · ' if participant else ''
        platform = 'Android' if device['collection_task_id'].startswith('android') else 'iPhone'
        device['name'] = prefix + ('Participant phone' if source=='participant' else f'Lab {platform}')
        self.plan = parallel_plan(self.serializable())
        self.build()
        self.status.set('Register the participant phone. Its IP will be checked at the start.' if source=='participant' else
                        f'Using a lab {platform} for this plan. Its IP will be detected at the start.')

    def register_device(self, key):
        if self.busy or self.session or self.demo_started is not None:
            return
        device = self.rows[key]['device']
        router = RouterCaptureConfig('', host=self.args.router_host, user=self.args.router_user,
                    interface=getattr(self.args, 'router_interface', 'br-lan'), identity_file=self.args.router_identity)
        dialog = tk.Toplevel(self.root); dialog.title('Register device and detect IP')
        dialog.transient(self.root); dialog.grab_set(); dialog.geometry('780x460')
        body = ttk.Frame(dialog, padding=18); body.pack(fill='both', expand=True)
        fields = ttk.Frame(body); fields.pack(fill='x', pady=(0, 12))
        participant = tk.StringVar(value=device['network'].get('participant_id') or
                         getattr(self, 'plan_metadata', {}).get('experiment', {}).get('participant_id', ''))
        platform = tk.StringVar(value={'ios': 'iOS / iPadOS', 'android': 'Android', 'windows': 'Windows'}.get(
                         device['collection_task_id'].split('-')[0], 'Android'))
        ttk.Label(fields, text='Participant or device ID').pack(side='left')
        ttk.Entry(fields, textvariable=participant, width=18).pack(side='left', padx=(8, 20))
        ttk.Label(fields, text='Platform').pack(side='left')
        ttk.Combobox(fields, textvariable=platform, values=('Android', 'iOS / iPadOS', 'Windows'),
                     state='readonly', width=15).pack(side='left', padx=8)
        ttk.Label(body, text='Read the device list before connecting the phone, then connect it to the collection Wi-Fi and refresh. If already connected, select it from the list.',
                  wraplength=720).pack(anchor='w', pady=(0, 12))
        table = ttk.Treeview(body, columns=('new', 'name', 'ip', 'mac'), show='headings', selectmode='browse', height=8)
        for column, title, width in (('new', 'Status', 85), ('name', 'Router device name', 210), ('ip', 'Detected IP', 150), ('mac', 'Wi-Fi MAC address', 190)):
            table.heading(column, text=title); table.column(column, width=width, minwidth=70)
        table.pack(fill='both', expand=True)
        scroll = ttk.Scrollbar(body, orient='horizontal', command=table.xview); scroll.pack(fill='x')
        table.configure(xscrollcommand=scroll.set)
        status = tk.StringVar(value='Reading devices from the router…')
        ttk.Label(body, textvariable=status, wraplength=720).pack(anchor='w', pady=10)
        buttons = ttk.Frame(body); buttons.pack(fill='x')
        state = dict(clients={}, baseline=None, loading=False)
        results = queue.Queue()
        excluded = {d['network'].get('mac', '').lower() for d in self.plan['devices'] if d['id'] != key}

        def load(reset=False, confirm=False):
            if state['loading']:
                return
            selection = table.selection()
            if confirm and not selection:
                status.set('Select the participant phone. Multiple devices connected at the same time.'); return
            selected_mac = selection[0] if confirm else None
            selected_participant = participant.get()
            selected_platform = platform.get()
            state['loading'] = True
            for button in (snapshot_button, refresh_button, confirm_button):
                button.configure(state='disabled')
            status.set('Checking the current device IP…' if confirm else 'Reading devices from the router…')
            def work():
                try:
                    clients = read_router_clients(router)
                    network = registered_network(selected_participant, key, selected_mac, clients) if confirm else None
                    results.put((clients, network, None))
                except Exception as exc:
                    results.put((None, None, str(exc)))
            threading.Thread(target=work, daemon=True).start()
            def poll():
                if not dialog.winfo_exists():
                    return
                try:
                    clients, network, error = results.get_nowait()
                except queue.Empty:
                    dialog.after(100, poll); return
                state['loading'] = False
                for button in (snapshot_button, refresh_button, confirm_button):
                    button.configure(state='normal')
                if error:
                    status.set(error); return
                if confirm:
                    try:
                        self.bind_registered_device(key, selected_platform, network)
                    except Exception as exc:
                        status.set(str(exc)); return
                    dialog.destroy(); self.build()
                    self.status.set(f"{selected_participant} · Registered IP {network['registration']['ip']} · Rechecked at start")
                    return
                state['clients'] = clients
                if reset or state['baseline'] is None:
                    state['baseline'] = {str(r.get('mac', '')).lower() for r in clients.values() if r.get('online') is True}
                choices = registration_candidates(clients, baseline_macs=state['baseline'], excluded_macs=excluded)
                table.delete(*table.get_children())
                for row in choices:
                    table.insert('', 'end', iid=row['mac'], values=('New' if row['new_connection'] else 'Online',
                                 row['router_name'] or 'Unnamed', row['ip'], row['mac']))
                new = [row for row in choices if row['new_connection']]
                if len(new) == 1:
                    table.selection_set(new[0]['mac']); table.see(new[0]['mac'])
                    status.set('One new device detected. Confirm that it is the participant phone, then register it.')
                elif len(new) > 1:
                    status.set('Multiple new devices detected. Select the participant phone.')
                elif selection and table.exists(selection[0]):
                    table.selection_set(selection[0]); status.set('IP refreshed. Confirm the selected device.')
                else:
                    status.set('Initial device list recorded. Connect the phone to Wi-Fi and refresh, or select an already connected device.')
            dialog.after(100, poll)

        snapshot_button = ttk.Button(buttons, text='Read initial device list', command=lambda: load(reset=True))
        snapshot_button.pack(side='left')
        refresh_button = ttk.Button(buttons, text='Refresh devices', command=load)
        refresh_button.pack(side='left', padx=8)
        confirm_button = ttk.Button(buttons, text='Confirm registration', command=lambda: load(confirm=True))
        confirm_button.pack(side='right')
        load(reset=True)

    def bind_registered_device(self, key, platform, network):
        """Persist the operator-confirmed identity, not a cached capture IP."""
        if self.busy or self.session or self.demo_started is not None:
            raise ValueError('Register the device before starting collection.')
        if any(d['id'] != key and d['network'].get('mac', '').lower() == network['mac'] for d in self.plan['devices']):
            raise ValueError('This device is registered to another timeline. Select a separate device.')
        task_id = {'Android': 'android-manual-screen-time', 'iOS / iPadOS': 'ios-manual-screen-time',
                   'Windows': 'windows-manual-screen-time'}[platform]
        candidate = self.serializable()
        device = next(d for d in candidate['devices'] if d['id'] == key)
        if phone_source(device):
            lab = phone_network_for_source(device, 'participant')['lab_network']
            network = dict(network, phone_source='participant', lab_network=lab)
        device.update(network=network, collection_task_id=task_id)
        validated = parallel_plan(candidate)
        path = Path(self.args.out) / 'device-registrations' / f'registration-{uuid.uuid4().hex[:12]}.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, dict(version=1, device_id=key, device_name=device['name'], platform=platform,
                             collection_task_id=task_id, network=network))
        self.plan = validated

    def worker(self, action, done=None):
        if self.busy:
            self.jobs.append((action, done))
            return
        self.busy = True
        def work():
            try:
                action(); self.messages.put((done, None))
            except Exception as exc:
                self.messages.put((done, str(exc)))
        threading.Thread(target=work, daemon=False).start()

    def start(self):
        if self.busy or self.session or self.demo_started is not None:
            return
        router = RouterCaptureConfig('', host=self.args.router_host, user=self.args.router_user,
                                      interface=getattr(self.args, 'router_interface', 'br-lan'), identity_file=self.args.router_identity)
        self.session = ParallelSession(self.args.out, self.serializable(), router)
        self.status.set('Preparing captures · timeline has not started')
        self.worker(self.session.start, lambda: self.status.set('Running · mark each device when you act'))

    def start_demo(self):
        if self.busy or self.session:
            return
        if not hasattr(self, 'original_plan'):
            self.original_plan = json.loads(json.dumps(self.plan))
        for device in self.plan['devices']:
            for step in device['plan']['steps']:
                step['seconds'] = 5 if step['kind'] in ('wait', 'transition') else 20
        self.demo_marks = []
        self.demo_elapsed = 0
        self.demo_started = timestamp()['monotonic']
        self.demo_ended = None
        now = timestamp()
        self.demo_progress = {d['id']: MarkPacedProgress(d['plan']['steps'], now)
                              for d in self.plan['devices'] if d['mode'] == 'Screen Time'}
        self.build()
        self.root.title('Collection · DEMO — no packet capture')
        self.status.set('DEMO · no devices needed · no packet capture')

    def end_demo(self):
        self.demo_ended = timestamp()
        self.demo_elapsed = self.demo_ended['monotonic'] - self.demo_started
        self.demo_started = None
        self.status.set(f'Demo finished · {len(self.demo_marks)} marks · Try demo to replay')

    def mark(self, key, end=False, confirm=False, at=None):
        at = at or timestamp()
        row = self.rows[key]
        if row['device'].get('mode', 'Screen Time') == 'Screen Time':
            end = end or not row['task'].get().strip()
        progress = self.progress_for(key)
        if progress:
            state = progress.view(at)
            if state['phase'] in ('wait', 'complete'):
                return
            if state['phase'] == 'running':
                end = True
        if getattr(self, 'demo_started', None) is not None:
            if progress:
                if end:
                    progress.end(at)
                elif state['phase'] == 'running':
                    return
                else:
                    progress.begin(at)
            row = self.rows[key]
            self.demo_marks.append(dict(device=key, task=row['task'].get(), app=row['app'].get(),
                                        event='confirm' if confirm else 'end' if end else 'start', at=at))
            self.status.set(f"DEMO · {row['device']['name']} · {row['task'].get() or 'No task'} · mark {len(self.demo_marks)}")
            return
        if self.stop_requested or not self.session or self.session.state != 'running':
            return
        row = self.rows[key]
        label, app = row['task'].get(), row['app'].get()
        outcome = row['outcome'].get() if confirm else None
        self.worker(lambda: self.session.mark(key, label, app, end=end, outcome=outcome, at=at),
                    lambda: self.status.set(f"{row['device']['name']} · mark saved"))

    def stop(self):
        if self.demo_started is not None:
            self.end_demo()
            return
        if not self.session or self.stop_requested:
            return
        self.stop_requested = True
        self.status.set('Stopping & saving all devices')
        def finish():
            self.stop_requested = False
            self.status.set(f'{self.session.state.title()} · {self.session.root}')
        self.worker(self.session.stop, finish)

    def close(self):
        if self.busy:
            self.closing = True
            return
        if self.session and self.session.state in ('running', 'preparing', 'stopping', 'cleanup_required'):
            self.closing = True; self.stop()
        else:
            self.root.destroy(); self.parent.deiconify()

    def render(self, key):
        row = self.rows[key]; steps = row['device']['plan']['steps']
        total = sum(s['seconds'] for s in steps)
        elapsed = max(0, timestamp()['monotonic'] - self.session.started['monotonic']) if self.session and self.session.started else 0
        if hasattr(self, 'original_plan'):
            elapsed = timestamp()['monotonic'] - self.demo_started if self.demo_started is not None else self.demo_elapsed
        if self.session and self.session.state in ('saved', 'failed'):
            elapsed = getattr(self, 'last_elapsed', elapsed)
        self.last_elapsed = elapsed
        index, cursor = None, 0
        for i, step in enumerate(steps):
            if cursor <= elapsed < cursor + step['seconds']:
                index = i; break
            cursor += step['seconds']
        current = steps[index] if index is not None else None
        progress = self.progress_for(key)
        observed_at = getattr(self, 'demo_ended', None) or timestamp()
        if self.session and key in self.session.timelines:
            observed_at = self.session.timelines[key].ended or observed_at
        paced = progress.view(observed_at) if progress else None
        if paced:
            index = paced['index']
            current = steps[index] if index is not None else None
            cursor = sum(s['seconds'] for s in steps[:index]) if index is not None else total
            elapsed = cursor + (min(paced['elapsed'], paced['seconds']) if paced['phase'] in ('running', 'wait') else 0)
        if index != row['index']:
            suggested = current
            if paced and paced['phase'] == 'switching':
                following = progress.next_activity()
                suggested = steps[following] if following is not None else None
            if suggested:
                row['task'].set(suggested['label']); row['app'].set(suggested['app'])
            else:
                row['task'].set(''); row['app'].set('')
            row['index'] = index
        remaining = math.ceil(cursor + current['seconds'] - elapsed) if current else 0
        prefix = 'DEMO' if hasattr(self, 'original_plan') else 'NOW' if self.session and self.session.state == 'running' else 'PREVIEW'
        row['info'].set(f"{row['device']['name']}   ·   {prefix}: {current['label'] if current else 'Ended'}   ·   {remaining}s")
        if paced:
            phase = paced['phase']
            text = ('Complete' if phase == 'complete' else
                    f"Switching · {int(paced['elapsed'])}s · Mark when ready" if phase == 'switching' else
                    'Ready · Mark to start' if phase == 'ready' else
                    f"Time reached · +{int(paced['elapsed']-paced['seconds'])}s · Mark to end" if phase == 'running' and paced['elapsed'] >= paced['seconds'] else
                    f"{phase.title()} · {max(0, math.ceil(paced['seconds']-paced['elapsed']))}s remaining")
            row['info'].set(f"{row['device']['name']} · {text}")
            if phase == 'running' and paced['elapsed'] >= paced['seconds'] and row.get('alerted') != index:
                row['alerted'] = index
                self.root.bell()
        canvas = row['canvas']; canvas.delete('all'); row['blocks'] = []
        scale = max(300, canvas.winfo_width() - 4) / max(1, self.duration())
        offset = 0
        for i, step in enumerate(steps):
            offset = step.get('suggested_start_seconds', offset)
            x, end = offset * scale, (offset + step['seconds']) * scale
            row['blocks'].append((x, end))
            color = '#b36b20' if step['kind'] == 'transition' and i == index else '#087b78' if i == index else '#f5e7d3' if step['kind'] == 'transition' else '#dcebea'
            canvas.create_rectangle(x, 19, end-2, 70, fill=color, outline='')
            if end-x > 65:
                canvas.create_text(x+5, 34, text=step['label'].replace('_', ' ')[:26], anchor='w', fill='white' if i == index else '#244753', width=end-x-10)
                canvas.create_text(x+5, 55, text=step['app'][:24], anchor='w', fill='white' if i == index else '#244753', width=end-x-10)
            tick_text = ('Flexible' if step['kind'] == 'transition' else f"{int(step['seconds'])}s") if progress or row['device']['mode'] == 'Screen Time' else f'{int(offset)//60:02}:{int(offset)%60:02}'
            canvas.create_text(x, 9, text=tick_text, anchor='w', fill='#60727d')
            offset += step['seconds']
        if (self.session and self.session.started) or hasattr(self, 'original_plan'):
            x = min(elapsed, self.duration()) * scale
            canvas.create_line(x, 15, x, 75, fill='#df663d', width=3)

    def duration(self):
        ends = []
        for d in self.plan['devices']:
            offset = 0
            for step in d['plan']['steps']:
                offset = step.get('suggested_start_seconds', offset) + step['seconds']
            ends.append(offset)
        return max(ends)

    def tick(self):
        try:
            while True:
                done, error = self.messages.get_nowait(); self.busy = False
                if error:
                    self.status.set(error)
                    if self.session and self.session.state == 'cleanup_required':
                        self.stop_requested = False
                        self.closing = False
                elif done:
                    done()
        except queue.Empty:
            pass
        if not self.busy and self.jobs:
            self.worker(*self.jobs.popleft())
        demo = getattr(self, 'demo_started', None) is not None
        running = bool(self.session and self.session.state == 'running') or demo
        if hasattr(self, 'demo_button'):
            self.demo_button.configure(state='disabled' if self.busy or self.session else 'normal')
        if demo:
            elapsed = timestamp()['monotonic'] - self.demo_started
            self.clock.set(f'{int(elapsed)//60:02}:{int(elapsed)%60:02}')
            if self.demo_progress and all(p.view(timestamp())['phase'] == 'complete' for p in self.demo_progress.values()):
                self.end_demo(); running = False; demo = False
        self.start_button.configure(state='disabled' if self.busy or self.session else 'normal')
        if hasattr(self, 'original_plan'):
            self.start_button.configure(state='disabled')
        self.save_button.configure(state='disabled' if self.busy or running or hasattr(self, 'original_plan') else 'normal')
        can_stop = self.session and self.session.state in ('running', 'cleanup_required') and not self.stop_requested
        self.stop_button.configure(state='normal' if can_stop or demo else 'disabled')
        for key, row in self.rows.items():
            self.render(key)
            if row.get('registration') is not None:
                row['registration'].configure(state='disabled' if self.busy or self.session or demo else 'normal')
            if row.get('phone_source') is not None:
                row['phone_source'].configure(state='disabled' if self.busy or self.session or demo else 'readonly')
            marking = running and not self.stop_requested
            if row['mark'] is not None:
                progress = self.progress_for(key)
                if row['device']['mode'] == 'Screen Time':
                    phase = progress.view(timestamp())['phase'] if progress else 'ready'
                    row['mark'].configure(text='Mark end' if phase=='running' else 'Mark start')
                    marking = marking and phase not in ('wait', 'complete')
                row['mark'].configure(state='normal' if marking and row['index'] is not None else 'disabled')
            if row['end'] is not None:
                row['end'].configure(state='normal' if marking else 'disabled')
        if running and not self.busy and not demo:
            try:
                at = timestamp()
                for timeline in self.session.timelines.values():
                    timeline.advance(at)
                elapsed = at['monotonic'] - self.session.started['monotonic']
                self.clock.set(f'{int(elapsed)//60:02}:{int(elapsed)%60:02}')
                if int(elapsed) // 5 != getattr(self, 'health_bucket', None):
                    self.health_bucket = int(elapsed) // 5
                    if error := self.session.health():
                        raise RuntimeError(error)
                if all(t.progress.view(at)['phase'] == 'complete' if t.progress else t.stopped for t in self.session.timelines.values()):
                    self.stop()
            except Exception as exc:
                self.session.error = str(exc)
                self.status.set(str(exc))
                self.stop()
        if self.closing and not self.busy:
            self.close()
            if not self.root.winfo_exists():
                return
        self.root.after(250, self.tick)

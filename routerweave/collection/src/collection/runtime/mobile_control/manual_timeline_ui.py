"""Shared timeline editor and operator prompts for the existing manual modes."""
import json
import math
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from .manual_ground_truth import timestamp, write_json
from .manual_timeline import OperatorTimeline, validate_plan


class TimelinePanel:
    def __init__(self, shell):
        self.shell = shell
        self.plans, self.run, self.applied, self.error = {}, None, None, ''
        self.style = tk.StringVar(value='Timeline')
        self.frame = ttk.Frame(shell.root, padding=(24, 0, 24, 8))
        self.frame.pack(fill='x')
        self.toolbar = ttk.Frame(self.frame)
        self.toolbar.pack(fill='x')
        self.mode_input = ttk.Combobox(self.toolbar, textvariable=self.style,
                                      values=('Free', 'Timeline'), state='readonly', width=12)
        self.mode_input.pack(side='left')
        self.import_button = ttk.Button(self.toolbar, text='Import timeline', command=self.import_plan)
        self.import_button.pack(side='left', padx=8)
        self.demo_button = ttk.Button(self.toolbar, text='Try demo', command=self.try_demo)
        self.demo_button.pack(side='left', padx=8)
        self.edit_button = ttk.Button(self.toolbar, text='Edit', command=self.edit)
        self.edit_button.pack(side='left', padx=8)
        self.start_button = ttk.Button(self.toolbar, text='Start session', command=self.start, style='Primary.TButton')
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(self.toolbar, text='Stop & save', command=self.stop_session)
        self.stop_button.pack(side='left', padx=8)
        self.prompt = tk.StringVar(value='')
        self.prompt_label = ttk.Label(self.toolbar, textvariable=self.prompt)
        self.visual = tk.Frame(self.frame, bg='white')
        self.visual.pack(fill='x', pady=(10, 0))
        self.headline = tk.StringVar(value='No timeline loaded')
        self.detail = tk.StringVar(value='Import a timeline to see tasks and timing.')
        tk.Label(self.visual, textvariable=self.headline, bg='white', fg='#183e4c',
                 font=('Segoe UI', 17, 'bold'), anchor='w', wraplength=880, justify='left').pack(fill='x', padx=14, pady=(10, 0))
        tk.Label(self.visual, textvariable=self.detail, bg='white', fg='#536975',
                 font=('Segoe UI', 10), anchor='w').pack(fill='x', padx=14, pady=(2, 0))
        self.canvas = tk.Canvas(self.visual, height=108, bg='white', highlightthickness=0)
        self.canvas.pack(fill='x', padx=14)
        self.scroll = ttk.Scrollbar(self.visual, orient='horizontal', command=self.canvas.xview)
        self.scroll.pack(fill='x', padx=14, pady=(0, 8))
        self.canvas.configure(xscrollcommand=self.scroll.set)
        self.canvas.bind('<Configure>', lambda _e: self.draw())
        self.canvas.bind('<Button-1>', self.select_block)
        self.preview_index = 0
        self.draw_key = None
        self.mode_input.bind('<<ComboboxSelected>>', lambda _e: self.update())

    def try_demo(self):
        if self.shell.locked():
            return
        path = Path(__file__).resolve().parents[4] / 'examples' / 'synthetic_timeline.json'
        window = self.import_plan(path)
        if window is not None:
            window.start_demo()

    def import_plan(self, path=None):
        if self.run and not self.run.stopped:
            return
        path = path or filedialog.askopenfilename(parent=self.shell.root,
                initialdir=Path(__file__).resolve().parents[4] / 'configs' / 'manual_timelines',
                filetypes=[('Timeline', '*.json')])
        if path:
            try:
                raw = json.loads(Path(path).read_text(encoding='utf-8-sig'))
                if raw.get('version') == 2:
                    if self.shell.locked():
                        raise ValueError('Finish the current session before importing multiple devices')
                    from .manual_parallel_ui import ParallelWindow
                    self.parallel_window = ParallelWindow(self.shell.root, self.shell.args, raw)
                    self.shell.root.withdraw()
                    return self.parallel_window
                self.plans[self.shell.current_mode] = self.normalize(raw)
                self.preview_index = 0
                self.style.set('Timeline'); self.update()
            except (ValueError, OSError, TypeError) as exc:
                messagebox.showerror('Timeline', str(exc), parent=self.shell.root)

    @staticmethod
    def clock_text(seconds):
        seconds = max(0, int(seconds))
        return f'{seconds // 60:02d}:{seconds % 60:02d}'

    def visible_plan(self):
        if self.run and self.run.plan['mode'] == self.shell.current_mode and not self.run.stopped:
            return self.run.plan
        return self.plans.get(self.shell.current_mode)

    def select_block(self, event):
        if self.run and not self.run.stopped:
            return
        x = self.canvas.canvasx(event.x)
        for i, (left, right) in enumerate(getattr(self, 'blocks', [])):
            if left <= x <= right:
                self.preview_index = i
                self.draw(); break

    def draw(self, elapsed=None, current=None):
        plan = self.visible_plan()
        self.canvas.delete('all'); self.blocks = []
        if not plan:
            self.canvas.pack_forget(); self.scroll.pack_forget()
            self.headline.set('No timeline loaded')
            self.detail.set('Import timeline → Start session')
            if self.shell.current_mode == 'Screen Time':
                self.controller().label.set('—'); self.controller().app.set('—')
            return
        if not self.canvas.winfo_manager():
            self.canvas.pack(fill='x', padx=14)
            self.scroll.pack(fill='x', padx=14, pady=(0, 8))
        steps = plan['steps']; total = sum(s['seconds'] for s in steps)
        active = current is not None
        index = current if active else min(self.preview_index, len(steps) - 1)
        step = steps[index]
        controller = self.controller()
        selection = (self.shell.current_mode, index, step['label'], step['app'])
        if not active and self.shell.current_mode == 'Screen Time' and getattr(self, 'preview_selection', None) != selection:
            controller.label.set(step['label'])
            controller.app.set(step['app'])
            self.preview_selection = selection
        title = step['label'].replace('_', ' ')
        app = step['app'] or ('Quiet period' if step['kind'] == 'wait' else 'No app specified')
        offsets = [0.0]
        for s in steps:
            offsets.append(offsets[-1] + s['seconds'])
        remaining = offsets[index + 1] - (elapsed or 0)
        self.headline.set(f"{'NOW' if active else 'PREVIEW'}  {title}  ·  {app}")
        next_step = steps[index + 1] if index + 1 < len(steps) else None
        next_text = f"{next_step['label'].replace('_', ' ')} / {next_step['app']}" if next_step else 'End'
        self.detail.set((f'{self.clock_text(remaining)} remaining' if active else
                         f'{self.clock_text(offsets[index])}–{self.clock_text(offsets[index + 1])}') +
                        f'   ·   Next: {next_text}   ·   Total {self.clock_text(total)}')
        ended = (not active and self.run and self.run.stopped and self.run.plan == plan
                 and self.controller().session is getattr(self, 'run_session', None))
        if ended:
            self.headline.set('Timeline ended')
            self.detail.set('Capture remains active · Stop & save when finished' if self.recording() else 'Capture stopped')
        width = max(600, self.canvas.winfo_width() - 4)
        scale = max(width / total, 80 / min(s['seconds'] for s in steps))
        # Cap excessive span while keeping every short step selectable.
        x = 2
        for i, s in enumerate(steps):
            size = max(80, s['seconds'] * scale)
            self.blocks.append((x, x + size))
            selected = i == index
            color = '#b36b20' if selected and s['kind'] == 'transition' else '#087b78' if selected else '#c4d2d6' if active and i < index else '#f5e7d3' if s['kind'] == 'transition' else '#e6edf1' if s['kind'] == 'wait' else '#dcebea'
            self.canvas.create_rectangle(x, 25, x + size - 3, 89, fill=color, outline='')
            fg = 'white' if selected else '#264653'
            label = s['label'].replace('_', ' ')
            self.canvas.create_text(x + 9, 39, text=f'{i+1}. {label[:38]}', anchor='w', fill=fg,
                                    font=('Segoe UI', 10, 'bold'), width=size - 18)
            self.canvas.create_text(x + 9, 68, text=(s['app'] or 'Wait')[:32], anchor='w', fill=fg,
                                    font=('Segoe UI', 9), width=size - 18)
            self.canvas.create_text(x, 12, text=self.clock_text(offsets[i]), anchor='w', fill='#536975')
            x += size
        self.canvas.create_text(x - 4, 101, text=self.clock_text(total), anchor='e', fill='#536975')
        self.canvas.configure(scrollregion=(0, 0, x, 108))
        if ended:
            elapsed = self.run.ended['monotonic'] - self.run.started['monotonic']
            index = next((i for i in range(len(steps)) if elapsed < offsets[i+1]), len(steps)-1)
            step = steps[index]
        if active or ended:
            left, right = self.blocks[index]
            cursor = left + (right-left) * min(1, max(0, (elapsed-offsets[index])/step['seconds']))
            self.canvas.create_line(cursor, 20, cursor, 94, fill='#df663d', width=3, tags=('progress_cursor',))
            if active and getattr(self, 'last_visible_step', None) != index:
                self.canvas.xview_moveto(max(0, (left-12)/x))
                self.last_visible_step = index

    def controller(self):
        return self.shell.controllers[self.shell.current_mode][1]

    def recording(self):
        c = self.controller()
        if self.shell.current_mode == 'IoT Events':
            return not c.busy and c.session.capture_status()['recording']
        return bool(c.session and c.session.state == 'recording' and not c.busy)

    def normalize(self, plan):
        plan = validate_plan(plan)
        if plan['mode'] != self.shell.current_mode:
            raise ValueError('This timeline belongs to the other collection type')
        if plan['mode'] == 'IoT Events':
            from .manual_marker import marker_protocol
            c = self.controller()
            task = c.tasks[c.device.get()]
            for step in plan['steps']:
                if step['kind'] in ('wait', 'transition'):
                    step['pre_seconds'] = 0
                    continue
                step['app'] = c.platform.get()
                if step['label'] not in c.actions.values():
                    raise ValueError('Choose actions supported by the selected device')
                protocol = marker_protocol(task, step['label'])
                step['pre_seconds'] = protocol['pre_seconds']
                minimum = sum(protocol[k] for k in ('pre_seconds', 'post_seconds', 'cooldown_seconds'))
                if step['seconds'] <= minimum:
                    raise ValueError(f"{step['label']}: duration must exceed {minimum:g}s (baseline + quiet period)")
        return validate_plan(plan)

    def edit(self):
        if self.run and not self.run.stopped:
            return
        mode = self.shell.current_mode
        dialog = tk.Toplevel(self.shell.root)
        dialog.title('Timeline')
        dialog.transient(self.shell.root)
        dialog.grab_set()
        body = ttk.Frame(dialog, padding=18)
        body.pack(fill='both', expand=True)
        rows = [dict(r) for r in self.plans.get(mode, {}).get('steps', [])]
        table = ttk.Treeview(body, columns=('step', 'app', 'seconds'), show='headings', height=9)
        for key, label, width in (('step', 'Activity / action', 220), ('app', 'App', 170), ('seconds', 'Seconds', 95)):
            table.heading(key, text=label)
            table.column(key, width=width)
        table.pack(fill='both', expand=True)
        editor = {'commit': None}
        def commit_pending():
            return editor['commit']() if editor['commit'] else True
        def refresh():
            table.delete(*table.get_children())
            for i, row in enumerate(rows):
                table.insert('', 'end', iid=str(i), values=(row['label'], row['app'], row['seconds']))
        def edit_cell(event):
            if not commit_pending():
                return
            item, column = table.identify_row(event.y), table.identify_column(event.x)
            if not item or column not in ('#1', '#2', '#3'):
                return
            index, key = int(item), {'#1': 'label', '#2': 'app', '#3': 'seconds'}[column]
            box = table.bbox(item, column)
            if not box:
                return
            value = tk.StringVar(value=str(rows[index][key]))
            field = ttk.Entry(table, textvariable=value)
            field.place(x=box[0], y=box[1], width=box[2], height=box[3])
            field.focus_set(); field.select_range(0, 'end')
            def commit(_event=None):
                if not field.winfo_exists():
                    return True
                editor['commit'] = None
                updated = dict(rows[index], **{key: value.get()})
                try:
                    rows[index] = self.normalize(dict(version=1, mode=mode, steps=[updated]))['steps'][0]
                    field.destroy(); refresh()
                    return True
                except (ValueError, TypeError) as exc:
                    field.destroy()
                    messagebox.showerror('Timeline', str(exc), parent=dialog)
                    return False
            editor['commit'] = commit
            field.bind('<Return>', commit)
            field.bind('<FocusOut>', commit)
            field.bind('<Escape>', lambda _e: field.destroy())
        table.bind('<Double-1>', edit_cell)
        def plan():
            return self.normalize(dict(version=1, mode=mode, steps=rows))
        def save_file():
            if not commit_pending():
                return
            try:
                value = plan()
                path = filedialog.asksaveasfilename(parent=dialog, defaultextension='.json', filetypes=[('Timeline', '*.json')])
                if path:
                    write_json(path, value)
            except (ValueError, OSError) as exc:
                messagebox.showerror('Timeline', str(exc), parent=dialog)
        def load_file():
            if not commit_pending():
                return
            path = filedialog.askopenfilename(parent=dialog,
                    initialdir=Path(__file__).resolve().parents[4] / 'configs' / 'manual_timelines',
                    filetypes=[('Timeline', '*.json')])
            if path:
                try:
                    with open(path, encoding='utf-8-sig') as stream:
                        value = self.normalize(json.load(stream))
                    rows[:] = value['steps']; refresh()
                except (ValueError, OSError, TypeError, AttributeError) as exc:
                    messagebox.showerror('Timeline', str(exc), parent=dialog)
        def use():
            if not commit_pending():
                return
            try:
                self.plans[mode] = plan()
                self.style.set('Timeline')
                dialog.destroy(); self.update()
            except ValueError as exc:
                messagebox.showerror('Timeline', str(exc), parent=dialog)
        footer = ttk.Frame(body); footer.pack(fill='x', pady=(12, 0))
        for title, command in (('Import', load_file), ('Save file', save_file), ('Done', use)):
            ttk.Button(footer, text=title, command=command).pack(side='left', padx=(0, 6))
        ttk.Label(body, text='Double-click a cell to edit. Durations are in seconds.').pack(anchor='w', pady=(10, 0))
        refresh()

    def start(self):
        if getattr(self, 'pending_start', False) or (self.run and not self.run.stopped):
            return
        c = self.controller()
        try:
            if self.shell.current_mode == 'IoT Events' and c.phase not in ('prepare', 'next', 'saved'):
                raise ValueError('Finish the current trial first')
            if self.shell.current_mode == 'Screen Time' and c.session and c.session.active:
                raise ValueError('End the current task first')
            plan = self.normalize(self.plans.get(self.shell.current_mode, {}))
            self.error = ''
            if not self.recording():
                self.pending_start = True
                self.detail.set('Preparing capture · timeline has not started')
                c.start_capture()
                return
            target = c.tasks[c.device.get()]['id'] if self.shell.current_mode == 'IoT Events' else c.selected_task()['id']
            self.run = OperatorTimeline(c.session.root, plan, clock=c.session.manifest.get('clock_start'), target=target,
                                        mark_paced=self.shell.current_mode == 'Screen Time')
            self.run_session = c.session
            self.applied, self.error = None, ''
            self.update()
        except (ValueError, OSError) as exc:
            messagebox.showerror('Timeline', str(exc), parent=self.shell.root)

    def stop_session(self):
        c = self.controller()
        if self.shell.current_mode == 'IoT Events':
            c.stop()
        else:
            c.stop_capture()

    def record(self, kind, label, at, **fields):
        if self.run and self.controller().session is getattr(self, 'run_session', None):
            try:
                if self.run.plan['mode'] == 'IoT Events':
                    fields['app'] = self.controller().platform.get()
                self.run.record(kind, label, at, **fields)
            except OSError as exc:
                self.error = 'Timeline save failed: ' + str(exc)
                self.prompt.set(self.error)

    def finish(self, reason):
        if self.run and not self.run.stopped:
            try:
                self.run.finish(reason)
            except OSError as exc:
                self.error = 'Timeline save failed: ' + str(exc)

    def update(self):
        c = self.controller()
        if getattr(self, 'pending_start', False):
            self.start_button.configure(state='disabled')
            if c.busy:
                return
            self.pending_start = False
            if self.recording():
                self.start()
                return
            self.error = 'Capture did not start. Check settings and retry.'
        active = bool(self.run and not self.run.stopped)
        self.mode_input.configure(state='disabled' if active else 'readonly')
        planned = self.style.get() == 'Timeline'
        for widget in (self.import_button, self.edit_button, self.start_button, self.stop_button):
            show = planned and (widget is self.import_button or
                               (widget is self.stop_button and (active or self.recording())) or
                               (widget is not self.stop_button and bool(self.visible_plan())))
            if show and not widget.winfo_manager():
                widget.pack(side='left', padx=(8, 0))
            elif not show and widget.winfo_manager():
                widget.pack_forget()
        if planned and not self.visual.winfo_manager():
            self.visual.pack(fill='x', pady=(10, 0))
        elif not planned and self.visual.winfo_manager():
            self.visual.pack_forget()
        self.import_button.configure(state='disabled' if active else 'normal')
        self.edit_button.configure(state='disabled' if active else 'normal')
        if hasattr(c, 'table'):
            c.table.configure(height=2 if planned else 4)
        self.start_button.configure(state='normal' if planned and not active and not c.busy and self.shell.current_mode in self.plans else 'disabled')
        for button in (getattr(c, 'capture_button', None), getattr(c, 'stop_button', None)):
            if button is None:
                continue
            if planned:
                button.pack_forget()
            elif not button.winfo_manager():
                button.pack(side='left', padx=(0, 8))
        self.stop_button.configure(state='normal' if (active or self.recording()) and not c.busy else 'disabled')
        if self.error:
            self.prompt.set(self.error)
            self.detail.set(self.error)
            return
        if not active:
            self.prompt.set('Timeline ended · Capture remains active' if self.run and self.recording() else
                            'Import a timeline, then start session.' if planned else '')
            key = (self.shell.current_mode, str(self.visible_plan()), self.preview_index, bool(self.run and self.run.stopped))
            if self.draw_key != key:
                self.draw(); self.draw_key = key
            return
        session = c.session
        running = session.manifest.get('status') == 'recording'
        if not running:
            self.finish('capture_ended'); return
        at = timestamp()
        index = self.run.advance(at)
        if index is None:
            if self.run.progress:
                self.run.finish('tasks_completed', at)
            self.headline.set('Timeline ended')
            self.detail.set('Capture remains active · Stop & save when finished')
            self.shell.root.bell()
            return
        step = self.run.plan['steps'][index]
        remaining = math.ceil(self.run.started['monotonic'] + self.run.offsets[index] + step['seconds'] - at['monotonic'])
        paced = self.run.progress.view(at) if self.run.progress else None
        if paced:
            remaining = math.ceil(paced['seconds'] - paced['elapsed']) if paced['phase'] in ('running', 'wait') else int(paced['seconds'])
        next_label = self.run.plan['steps'][index + 1]['label'] if index + 1 < len(self.run.plan['steps']) else 'End'
        app = step['app'] or (c.platform.get() if self.shell.current_mode == 'IoT Events' else '—')
        self.prompt.set(f"{index + 1}/{len(self.run.plan['steps'])}  {step['label']} · {remaining}s\nApp: {app} · Next: {next_label}")
        key = (index, remaining)
        if self.draw_key != key:
            position = self.run.offsets[index] + min(paced['elapsed'], paced['seconds']) if paced else at['monotonic'] - self.run.started['monotonic']
            self.draw(position, index)
            self.draw_key = key
        if paced:
            self.detail.set('Mark the actual start · full task duration begins then' if paced['phase'] == 'ready' else
                            'Switch at your own pace · start the next task when ready' if paced['phase'] == 'switching' else
                            'Time reached · end the task when you actually stop' if remaining <= 0 else
                            f'{remaining}s remaining · timed from actual start')
        if self.applied != index and not c.busy:
            if self.shell.current_mode == 'IoT Events':
                if c.phase not in ('prepare', 'next', 'saved'):
                    return
                if step['kind'] == 'activity':
                    c.action.set(next(k for k, v in c.actions.items() if v == step['label']))
                    c.select_action(); c.begin_baseline(); c.refresh()
            elif self.shell.current_mode == 'Screen Time':
                suggested = step
                if paced and paced['phase'] == 'switching':
                    following = self.run.progress.next_activity()
                    if following is not None:
                        suggested = self.run.plan['steps'][following]
                c.label.set(suggested['label']); c.app.set(suggested['app'])
            self.applied = index
            self.shell.root.bell()

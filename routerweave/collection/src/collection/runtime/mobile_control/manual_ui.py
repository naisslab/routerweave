"""Local desktop controls for manual screen-time ground truth."""

from __future__ import annotations

from datetime import datetime
from dataclasses import replace
import math
import os
from pathlib import Path
import queue
import threading
import time
import uuid
import copy
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .collection import RouterCaptureConfig
from .manual_ground_truth import CAPTURE_SCOPES, ManualGroundTruthSession, timestamp, EVENT_TIMINGS, event_windows
from .manual_network import resolve_task_identity
from collection.runtime.registry.tasks import load_collection_tasks, RUNNABLE_STATUSES


LABELS = ("short_video", "long_video", "browsing", "messaging", "music",
          "live_stream", "gaming", "productivity", "background", "transition", "other", "unknown")
SCREEN_STATES = {"Screen on": "on", "Screen off": "off", "Unknown": "unknown"}


def timeline_event(controller, kind, label, at, **fields):
    shell = getattr(controller.root, 'shell', None)
    if shell and hasattr(shell, 'schedule'):
        shell.schedule.record(kind, label, at, **fields)


def timeline_finish(controller, reason):
    shell = getattr(controller.root, 'shell', None)
    if shell and hasattr(shell, 'schedule'):
        shell.schedule.finish(reason)


def timeline_preflight_start(controller, switching=False):
    """Check paced readiness before changing the underlying actual segment."""
    shell = getattr(controller.root, 'shell', None)
    run = getattr(getattr(shell, 'schedule', None), 'run', None)
    if run and not run.stopped and run.progress:
        progress = copy.deepcopy(run.progress)
        at = timestamp()
        if switching:
            progress.end(at)
        progress.begin(at)


def collection_theme(root):
    """Shared desktop styling for both collection modes."""
    style = ttk.Style(root)
    style.theme_use('clam')
    root.configure(bg='#f4f6f8')
    for prefix, background in (('', '#f4f6f8'), ('IoT.', '#f4f6f8'), ('IoT.White.', '#ffffff')):
        style.configure(prefix + 'TFrame', background=background)
        style.configure(prefix + 'TLabel', background=background, foreground='#243746', font=('Segoe UI', 10))
    for name in ('TButton', 'Marker.TButton'):
        style.configure(name, font=('Segoe UI', 10), padding=(14, 8), background='#ffffff',
                        foreground='#243746', bordercolor='#d5dde4', relief='flat')
        style.map(name, background=[('active', '#e9eef2'), ('disabled', '#edf1f4')],
                  foreground=[('disabled', '#97a3ad')])
    style.configure('Primary.TButton', background='#087b78', foreground='white')
    style.map('Primary.TButton', background=[('disabled', '#e2e8ec'), ('active', '#086965')],
              foreground=[('disabled', '#8997a2')])
    for name in ('TCombobox', 'IoT.TCombobox'):
        style.configure(name, padding=7, font=('Segoe UI', 10), fieldbackground='white',
                        background='white', bordercolor='#d5dde4', arrowsize=13)
        style.map(name, fieldbackground=[('readonly', 'white')],
                  selectbackground=[('readonly', 'white')], selectforeground=[('readonly', '#243746')])
    style.configure('TEntry', padding=7, fieldbackground='white', bordercolor='#d5dde4')
    for name in ('Treeview', 'IoT.Treeview'):
        style.configure(name, rowheight=29, font=('Segoe UI', 10), background='white',
                        fieldbackground='white', foreground='#243746', borderwidth=0)
        style.configure(name + '.Heading', font=('Segoe UI', 9, 'bold'), padding=8,
                        background='#eaf0f4', foreground='#5a6b78', relief='flat')
    style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'))
    style.configure('Timer.TLabel', font=('Consolas', 20), foreground='#243746')
    style.configure('NextMark.TLabel', font=('Segoe UI', 16, 'bold'))


def event_schedule(protocol, events, now):
    """Earliest disjoint trial; actual linked events may still be marked sooner."""
    if protocol.get("mode") != "event_markers" or not events:
        return None
    last_mark = next((e for e in reversed(events) if e["event"] == "event_mark"), None)
    anchor = last_mark or events[0]
    pre, post = protocol["pre_seconds"], protocol["post_seconds"]
    wait = pre + (post if last_mark else 0)
    # Show a whole-second target that is never earlier than the required window.
    due_pc = math.ceil(anchor["pc_epoch"] + wait)
    due_mono = anchor["monotonic"] + (due_pc - anchor["pc_epoch"])
    remaining = max(0, math.ceil(due_mono - now["monotonic"]))
    tail = max(0, math.ceil(last_mark["monotonic"] + post - now["monotonic"])) if last_mark else 0
    return dict(next_pc_epoch=due_pc, next_monotonic=due_mono, remaining_seconds=remaining,
                post_remaining_seconds=tail, first=last_mark is None,
                phase="ready" if not remaining else "post" if tail else "pre")


class ManualGroundTruthWindow:
    def __init__(self, root: tk.Tk, args, *, session_factory=ManualGroundTruthSession,
                 identity_resolver=resolve_task_identity):
        self.root, self.args = root, args
        self.session_factory = session_factory
        self.identity_resolver = identity_resolver
        self.network_identity = None
        self.session = None
        self.busy = False
        self.closing = False
        self.messages = queue.Queue()
        self.space_down = False
        self.last_mark_mono = -1.0
        self.ready_notice = None
        root.title("Screen Time · Collection Tool")
        root.geometry("1000x720")
        root.minsize(940, 680)
        root.configure(bg="#f3f5f8")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f3f5f8")
        style.configure("TLabel", background="#f3f5f8", font=("Microsoft YaHei UI", 11))
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 23, "bold"))
        style.configure("Timer.TLabel", font=("Consolas", 30, "bold"), foreground="#135cc8")
        style.configure("NextMark.TLabel", font=("Microsoft YaHei UI", 20, "bold"))
        style.configure("TButton", font=("Microsoft YaHei UI", 11), padding=(14, 10))
        style.configure("Primary.TButton", background="#135cc8", foreground="white")
        style.map("Primary.TButton", background=[("disabled", "#adbaca"), ("active", "#104eaa")])
        style.configure("Treeview", font=("Microsoft YaHei UI", 10), rowheight=32)
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 10, "bold"))
        collection_theme(root)
        self.ip = tk.StringVar(value=args.phone_ip)
        self.band = tk.StringVar(value="Not recorded")
        self.label = tk.StringVar(value="short_video")
        self.app = tk.StringVar()
        self.note = tk.StringVar()
        self.screen_state = tk.StringVar(value="Unknown")
        self.tasks = {f"{t['platform_label']} · {t['title']}": t for t in load_collection_tasks()
                      if (t['kind'] == 'manual' and t['configured_status'] in RUNNABLE_STATUSES) or
                      (t['id'] == args.collection_task_id and t['kind'] != 'iot') or
                      (not isinstance(root, ModePanel) and t['kind'] == 'iot' and t['category'] in EVENT_TIMINGS and t['configured_status'] in RUNNABLE_STATUSES)}
        self.task_choice = tk.StringVar(value=next((k for k, t in self.tasks.items() if t['id'] == args.collection_task_id),
                                                   next(iter(self.tasks), "")))
        self.iot_mode = tk.StringVar(value="Event marking")
        self.protocol_hint = tk.StringVar()
        self.status = tk.StringVar(value="Idle")
        self.current = tk.StringVar(value="No active task")
        self.clock = tk.StringVar()
        self.clock_date = tk.StringVar()
        self.timer = tk.StringVar(value="00:00:00")
        self.next_mark = tk.StringVar()
        self.next_mark_status = tk.StringVar()
        self.update_wall_clock()
        self.capture_info = tk.StringVar(value="")
        self.output = tk.StringVar(value="")
        body = ttk.Frame(root, padding=(24, 10, 24, 20))
        body.pack(fill="both", expand=True)
        main_heading = ttk.Frame(body)
        if not isinstance(root, ModePanel):
            main_heading.pack(fill="x")
        ttk.Label(main_heading, text="Screen Time", style="Title.TLabel").pack(side="left")
        if not isinstance(root, ModePanel):
            ttk.Button(main_heading, text="IoT Event Marker", command=lambda: IoTMarkerWindow(tk.Toplevel(self.root), self.args)).pack(side="right")
        selection = ttk.Frame(body)
        selection.pack(fill="x", pady=(10, 0))
        ttk.Label(selection, text="Target").pack(side="left")
        self.task_input = ttk.Combobox(selection, textvariable=self.task_choice, values=tuple(self.tasks), state="readonly", width=67)
        self.task_input.pack(side="left", padx=10, fill="x", expand=True)
        self.mode_input = ttk.Combobox(selection, textvariable=self.iot_mode, values=("Event marking", "Observation"), state="disabled", width=12)
        if not isinstance(root, ModePanel):
            self.mode_input.pack(side="right")
        self.task_input.bind("<<ComboboxSelected>>", self.select_task)
        self.mode_input.bind("<<ComboboxSelected>>", self.select_mode)
        # Detailed protocol guidance remains in the IoT mode; keep this view compact.
        capture_bar = ttk.Frame(body)
        capture_bar.pack(fill='x', pady=(8, 6))
        self.settings_window = tk.Toplevel(root)
        self.settings_window.title('Capture settings')
        self.settings_window.withdraw()
        def hide_settings():
            self.settings_window.grab_release()
            self.settings_window.withdraw()
        self.settings_window.protocol('WM_DELETE_WINDOW', hide_settings)
        settings = ttk.Frame(self.settings_window, padding=20)
        settings.pack(fill='both', expand=True)
        ttk.Label(settings, text="Device IP").grid(row=0, column=0, sticky="w")
        self.ip_entry = ttk.Entry(settings, textvariable=self.ip, width=19, font=("Consolas", 12))
        self.ip_entry.grid(row=1, column=0, pady=6, padx=(0, 20), sticky="w")
        ttk.Label(settings, text="Wi-Fi band").grid(row=0, column=1, sticky="w")
        self.band_input = ttk.Combobox(settings, textvariable=self.band, width=14, state="readonly",
                                       values=("Not recorded", "2.4 GHz", "5 GHz", "6 GHz"))
        self.band_input.grid(row=1, column=1, padx=(0, 20), sticky="w")
        self.capture_button = ttk.Button(capture_bar, text="Start capture", command=self.start_capture, style='Primary.TButton')
        self.capture_button.pack(side='left')
        self.stop_button = ttk.Button(capture_bar, text="Stop & save", command=self.stop_capture, state="disabled")
        self.stop_button.pack(side='left', padx=8)
        self.settings_button = ttk.Button(capture_bar, text='Settings', command=self.open_settings)
        self.settings_button.pack(side='left')
        self.identify_button = ttk.Button(settings, text="Detect device", command=self.identify_device)
        self.identify_button.grid(row=2, column=0, sticky='w', pady=8)
        ttk.Label(settings, text=f'Router: {args.router_host} · {args.router_interface}').grid(row=3, column=0, columnspan=2, sticky='w')
        ttk.Button(settings, text='Done', command=hide_settings).grid(row=4, column=1, sticky='e', pady=(12, 0))
        ttk.Label(capture_bar, textvariable=self.status, wraplength=470).pack(side='right')
        ttk.Label(body, textvariable=self.capture_info, wraplength=910, foreground='#71818d').pack(anchor="w", pady=(0, 8))
        work = ttk.Frame(body, padding=10, style='IoT.White.TFrame')
        work.pack(fill='x', pady=(0, 6))
        form = ttk.Frame(work, style='IoT.White.TFrame')
        form.pack(fill="x", pady=3)
        for i, title in enumerate(("Task", "App", "Note")):
            ttk.Label(form, text=title, style='IoT.White.TLabel').grid(row=0, column=i, sticky="w")
            form.columnconfigure(i, weight=1)
        self.label_input = ttk.Combobox(form, textvariable=self.label, values=LABELS, font=("Microsoft YaHei UI", 11))
        self.label_input.bind("<<ComboboxSelected>>", lambda _e: self.root.focus_set()
                              if self.selected_task().get("kind") == "iot" else None)
        self.app_input = ttk.Entry(form, textvariable=self.app, font=("Microsoft YaHei UI", 11))
        self.screen_input = ttk.Combobox(form, textvariable=self.screen_state, values=tuple(SCREEN_STATES), state="readonly")
        for i, widget in enumerate((self.label_input, self.app_input)):
            widget.grid(row=1, column=i, sticky="ew", padx=(0, 16 if i < 2 else 0), pady=(3, 6))
        self.note_input = ttk.Entry(form, textvariable=self.note, font=("Microsoft YaHei UI", 11))
        self.note_input.bind("<Return>", lambda _e: self.root.focus_set())
        self.note_input.grid(row=1, column=2, sticky="ew", pady=(3, 6))
        timing = ttk.Frame(work, style='IoT.White.TFrame')
        timing.pack(fill="x", pady=(0, 8))
        clock_panel = ttk.Frame(timing, style='IoT.White.TFrame')
        ttk.Label(clock_panel, textvariable=self.clock, style='IoT.White.TLabel', font=('Consolas', 11), foreground='#7b8995').pack(anchor="w")
        ttk.Label(timing, textvariable=self.timer, style='IoT.White.TLabel', font=('Consolas', 20)).pack(side="left", padx=(20, 0))
        self.end_button = ttk.Button(timing, text="End task", command=self.end_segment, state="disabled")
        self.end_button.pack(side="right")
        self.begin_button = ttk.Button(timing, text="Start task", command=self.begin_segment,
                                       style="Primary.TButton", state="disabled")
        self.begin_button.pack(side="right", padx=12)
        self.event_timing_panel = ttk.Frame(work, style='IoT.White.TFrame')
        self.next_mark_label = ttk.Label(self.event_timing_panel, textvariable=self.next_mark, style="NextMark.TLabel")
        self.next_mark_label.pack(anchor="w")
        ttk.Label(self.event_timing_panel, textvariable=self.next_mark_status, wraplength=980).pack(anchor="w", pady=(4, 0))
        switches = ttk.Frame(work, style='IoT.White.TFrame')
        self.switches = switches
        switches.pack(fill="x", pady=(0, 8))
        self.switch_button = ttk.Button(timing, text="Switch task", command=self.switch_segment, state="disabled")
        self.switch_button.pack(side="right", before=self.begin_button, padx=8)
        self.transition_button = ttk.Button(switches, text="Transition", command=lambda: self.quick_segment("transition", "Unknown"), state="disabled")
        self.transition_button.pack(side="left", padx=8)
        self.idle_button = ttk.Button(switches, text="Background", command=lambda: self.quick_segment("background", "Unknown"), state="disabled")
        self.idle_button.pack(side="left")
        self.current_label = ttk.Label(work, textvariable=self.current, wraplength=850, style='IoT.White.TLabel')
        self.current_label.pack(anchor="w", pady=(0, 4))
        ttk.Label(body, text='History', font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 6))
        table_frame = ttk.Frame(body)
        table_frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(table_frame, columns=("label", "app", "start", "end", "duration"),
                                  show="headings", height=5)
        for key, title, width in (("label", "Activity", 190), ("app", "App", 125), ("start", "Start", 135),
                                   ("end", "End", 135), ("duration", "Duration", 100)):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=70)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        footer = ttk.Frame(body)
        footer.pack(side="bottom", fill="x", pady=(16, 0), before=table_frame)
        self.open_button = ttk.Button(footer, text="Open folder", command=self.open_output, state="disabled")
        self.open_button.pack(side="right")
        self.review_button = ttk.Button(footer, text="Review & export", command=self.open_review)
        self.review_button.pack(side="right", padx=8)
        self.load_button = ttk.Button(footer, text="Open session", command=lambda: self.open_review(choose=True))
        self.load_button.pack(side="right")
        self.review_window = None
        self.select_task(initial=True)
        key_tag = f"ManualEventSpace{id(self)}"
        root.bind_class(key_tag, "<KeyPress-space>", self.press_space)
        root.bind_class(key_tag, "<KeyRelease-space>", self.release_space)
        def bind_keys(widget):
            widget.bindtags((key_tag,) + widget.bindtags())
            for child in widget.winfo_children():
                bind_keys(child)
        bind_keys(root)
        root.bind("<FocusOut>", lambda _e: setattr(self, "space_down", False))
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(150, self.tick)

    def run_worker(self, action, callback):
        self.busy = True
        self.update_buttons()
        def work():
            try:
                self.messages.put((callback, action(), None))
            except Exception as exc:
                self.messages.put((callback, None, str(exc)))
        threading.Thread(target=work, daemon=False).start()

    def open_settings(self):
        if not self.busy and not (self.session and self.session.state in ('starting', 'recording', 'stopping')):
            self.settings_window.deiconify()
            self.settings_window.transient(self.root.winfo_toplevel())
            self.settings_window.grab_set()

    def update_buttons(self):
        recording = bool(self.session and self.session.state == "recording" and not self.busy)
        active = bool(self.session and self.session.active)
        iot = self.selected_task().get("kind") == "iot"
        marking = iot and self.iot_mode.get() == "Event marking"
        observation_only = self.selected_task().get("metadata", {}).get("manual_observation_only", False)
        self.capture_button.configure(state="disabled" if self.busy or recording else "normal",
                                      text="New capture" if self.session else "Start capture")
        self.stop_button.configure(state="normal" if recording else "disabled")
        self.settings_button.configure(state='disabled' if self.busy or recording else 'normal')
        self.begin_button.configure(state="normal" if recording and not active and (not iot or marking) else "disabled",
                                    text="Mark [Space]" if iot else "Start task")
        self.end_button.configure(state="normal" if recording and active and not iot else "disabled")
        self.switch_button.configure(state="normal" if recording and active and not iot else "disabled")
        self.transition_button.configure(state="normal" if recording and not iot else "disabled")
        self.idle_button.configure(state="normal" if recording and not iot else "disabled")
        self.review_button.configure(state="disabled" if recording or self.busy else "normal")
        self.load_button.configure(state="disabled" if recording or self.busy else "normal")
        self.ip_entry.configure(state="disabled" if recording or self.busy else "normal")
        self.identify_button.configure(state="normal" if iot and not recording and not self.busy else "disabled")
        self.band_input.configure(state="disabled" if recording or self.busy else "readonly")
        self.task_input.configure(state="disabled" if recording or self.busy else "readonly")
        self.mode_input.configure(state="readonly" if iot and not recording and not self.busy and not observation_only else "disabled")
        for widget in (self.label_input, self.app_input, self.note_input):
            widget.configure(state="disabled" if self.busy else "normal")
        schedule = getattr(getattr(self.root, 'shell', None), 'schedule', None)
        guided = bool(schedule and schedule.style.get() == 'Timeline')
        if guided:
            self.switches.pack_forget()
            self.transition_button.pack_forget()
            self.idle_button.pack_forget()
        else:
            if not self.switches.winfo_manager():
                self.switches.pack(fill='x', pady=(0, 8), before=self.current_label)
            if not self.transition_button.winfo_manager():
                self.transition_button.pack(side='left', padx=8)
            if not self.idle_button.winfo_manager():
                self.idle_button.pack(side='left')
        self.screen_input.configure(state="disabled" if self.busy else "readonly")
        if iot:
            if self.identity_resolver is not None:
                self.ip_entry.configure(state="readonly")
                if self.network_identity is None:
                    self.capture_button.configure(state="disabled")
            self.label_input.configure(state="readonly" if not self.busy and marking else "disabled")
            self.app_input.configure(state="disabled")
        if marking and (self.busy or (self.session and self.session.state != "recording")):
            self.next_mark.set("Connecting or saving. Event marking is paused." if self.busy else "Run complete. Start a new run to reset the timer.")
            self.next_mark_status.set("")
            self.next_mark_label.configure(foreground="#616b78")
        if marking and not self.busy and self.identity_resolver is not None and self.network_identity is None:
            self.next_mark.set("Identify the device before marking an event.")
            self.next_mark_status.set("Check the device connection or MAC address, then detect the IP again.")
            self.next_mark_label.configure(foreground="#616b78")

    def selected_task(self):
        return self.tasks.get(self.task_choice.get(), {})

    def select_task(self, _event=None, *, initial=False):
        task = self.selected_task()
        iot = task.get("kind") == "iot"
        if not initial:
            self.ip.set("")  # A different device must not inherit the previous capture address.
        labels = tuple(row["key"] for row in task["breakdown"]) if iot else LABELS
        self.label_input.configure(values=labels)
        self.label.set("doorbell_press" if "doorbell_press" in labels else labels[0] if labels else "background_observation")
        if task.get("metadata", {}).get("manual_observation_only"):
            self.iot_mode.set("Observation")
        elif _event is not None:
            self.iot_mode.set("Event marking")
        self.app.set("")
        self.table.heading("app", text="Before / after" if iot else "App")
        self.table.heading("start", text="Marked at" if iot else "Start")
        self.table.heading("end", text="Window end" if iot else "End")
        self.table.heading("duration", text="Coverage" if iot else "Duration")
        self.select_mode()
        if iot and self.identity_resolver is not None:
            self.identify_device()

    def select_mode(self, _event=None):
        task = self.selected_task()
        marking = task.get("kind") == "iot" and self.iot_mode.get() == "Event marking"
        self.event_timing_panel.pack_forget()
        self.switches.pack_forget()
        if marking:
            self.event_timing_panel.pack(fill="x", pady=(0, 12), before=self.current_label)
        elif task.get("kind") != "iot":
            self.switches.pack(fill="x", pady=(0, 8), before=self.current_label)
        if task.get("kind") == "iot":
            pre, post = EVENT_TIMINGS[task["category"]]
            if self.iot_mode.get() == "Event marking":
                self.protocol_hint.set(f"Each marker includes {pre} s before and {post} s after the event. Select a label and press Space. After editing a note, press Enter to resume marking.\nMark the time of your action. Sensor state is unverified. Mark clear events manually.")
                self.next_mark.set(f"First marker: wait at least {pre} s after capture starts.")
                self.next_mark_status.set(f"Allow at least {pre + post} s between independent markers. Mark related events whenever they occur.")
                self.next_mark_label.configure(foreground="#135cc8")
            else:
                self.protocol_hint.set("Record routine traffic until collection ends. Motion, clear, temperature, and humidity changes require separate labels.")
        else:
            self.protocol_hint.set("Choose an activity label. Use Start, End, or Switch to record continuous tasks.")
        self.update_buttons()

    def identify_device(self):
        if self.busy or (self.session and self.session.state == "recording"):
            return
        task = self.selected_task()
        if task.get("kind") != "iot" or self.identity_resolver is None:
            return
        self.network_identity = None
        self.ip.set("")
        self.status.set("Looking up the IP address by device MAC…")
        router = RouterCaptureConfig("", self.args.router_host, self.args.router_user,
                                     self.args.router_interface, self.args.router_identity)
        def identified(result):
            self.network_identity = result
            self.ip.set(result["ip"])
            band = {"2.4G": "2.4 GHz", "5G": "5 GHz", "6G": "6 GHz"}.get(result["wifi_band"])
            if band:
                self.band.set(band)
            scope = f"gateway {result['proxy_device']}" if result["scope"] == "home_hub_proxy" else "device"
            self.status.set(f"Matched {scope}: IP {result['ip']}, MAC {result['mac']}. The address will be checked again before capture.")
            self.select_mode()
        self.run_worker(lambda: self.identity_resolver(task, router), identified)

    def press_space(self, event):
        at = timestamp()  # Capture the input boundary before filesystem writes or health checks.
        if self.selected_task().get("kind") != "iot" or self.iot_mode.get() != "Event marking":
            return
        if str(event.widget.winfo_class()) in {"Entry", "TEntry", "Text", "TCombobox", "Spinbox", "TSpinbox"}:
            return
        if event.state & (0x1 | 0x4 | 0x8):
            return
        if not self.space_down:
            self.space_down = True
            self.mark_event(at=at, source="keyboard_space")
        return "break"  # Also suppress the focused button's Space activation.

    def release_space(self, _event):
        intercepted = self.space_down
        self.space_down = False
        if intercepted:
            return "break"

    def mark_event(self, *, at=None, source="button"):
        at = at or timestamp()
        if self.busy or not self.session or self.session.state != "recording":
            return
        if at["monotonic"] - self.last_mark_mono < .35:
            return
        try:
            self.session.mark_event(self.label.get(), self.note.get(), at=at, input_source=source)
            self.last_mark_mono = at["monotonic"]
            self.refresh_rows()
            self.update_event_timing()
            self.current.set(f"Recorded {self.label.get()} · {datetime.fromtimestamp(at['pc_epoch']):%H:%M:%S.%f}"[:-3]
                             + ". Select the next event. Holding a key records one event.")
        except Exception as exc:
            self.status.set("Event marker not saved: " + str(exc))

    def start_capture(self):
        if self.busy or (self.session and self.session.state == "recording"):
            return
        if self.review_window and self.review_window.root.winfo_exists():
            if self.review_window.busy:
                self.status.set("Export in progress. Wait before starting the next run.")
                return
            self.review_window.root.destroy()
            self.review_window = None
        router = RouterCaptureConfig(self.ip.get().strip(), self.args.router_host, self.args.router_user,
                                     self.args.router_interface, self.args.router_identity)
        try:
            router.validate()
        except ValueError as exc:
            messagebox.showerror("Check the target IP address", str(exc), parent=self.root)
            return
        task = self.selected_task()
        prefix = "iot-manual-" if task.get("kind") == "iot" else "ios-manual-"
        run_root = Path(self.args.out) / datetime.now().strftime(prefix + "%Y%m%d-%H%M%S-%f")
        self.session = self.session_factory(run_root, router, task["id"])
        if task.get("kind") == "iot":
            self.session.configure_iot(observation=self.iot_mode.get() == "Observation")
        self.space_down, self.last_mark_mono = False, -1.0
        self.ready_notice = None
        self.table.delete(*self.table.get_children())
        self.timer.set("00:00:00")
        self.current.set("No active task")
        self.capture_info.set("")
        self.output.set(str(run_root.resolve()))
        self.status.set("Starting capture…")
        band = self.band.get()
        def start():
            if task.get("kind") == "iot" and self.identity_resolver is not None:
                self.network_identity = self.identity_resolver(task, router)
                self.session.router = replace(router, phone_ip=self.network_identity["ip"])
            self.session.start()
            from .manual_ground_truth import write_json
            self.session.manifest["network_environment"] = {"wifi_band": band}
            if self.network_identity and task.get("kind") == "iot":
                self.session.manifest["network_identity"] = self.network_identity.copy()
            write_json(self.session.root / "collection_manifest.json", self.session.manifest)
        self.run_worker(start, self.started)

    def started(self, _result):
        self.ip.set(self.session.router.phone_ip)
        clock = self.session.manifest["clock_start"]
        self.status.set(f"Capturing · {self.session.router.phone_ip}")
        self.capture_info.set(f"Clock uncertainty ±{clock['uncertainty_seconds']:.2f}s")
        self.open_button.configure(state="normal")
        if self.session.protocol:
            self.status.set("Continuous capture started. " + ("Press Space when you perform the action." if self.iot_mode.get() == "Event marking" else "Observing routine traffic."))
            self.root.focus_set()
            self.update_event_timing()

    def begin_segment(self):
        if self.selected_task().get("kind") == "iot":
            self.mark_event()
            self.root.focus_set()
            return
        try:
            timeline_preflight_start(self)
            self.session.begin_segment(self.label.get(), self.app.get(), self.note.get(), SCREEN_STATES[self.screen_state.get()])
            timeline_event(self, 'task_start', self.session.active['label'],
                           {k: self.session.active[k] for k in ('pc_epoch', 'monotonic')},
                           reference=self.session.active['segment_id'], app=self.session.active['app'])
            started_at = datetime.fromtimestamp(self.session.active["pc_epoch"]).astimezone()
            self.current.set("Recording · " + self.session.active["label"])
            self.timer.set("00:00:00")
        except Exception as exc:
            messagebox.showerror("Unable to start task", str(exc), parent=self.root)
        self.update_buttons()

    def end_segment(self):
        try:
            previous = dict(self.session.active or {})
            self.session.end_segment()
            if previous:
                timeline_event(self, 'task_end', previous['label'], self.session.events[-1],
                               reference=previous['segment_id'], app=previous['app'])
            self.refresh_rows()
            self.show_duration(self.session.rows[-1]["duration_seconds"])
            self.current.set("Task saved · No active task")
        except Exception as exc:
            messagebox.showerror("Unable to save task", str(exc), parent=self.root)
        self.update_buttons()

    def switch_segment(self):
        try:
            timeline_preflight_start(self, switching=True)
            previous = dict(self.session.active or {})
            self.session.switch_segment(self.label.get(), self.app.get(), self.note.get(), SCREEN_STATES[self.screen_state.get()])
            if previous:
                timeline_event(self, 'task_end', previous['label'], self.session.active,
                               reference=previous['segment_id'], app=previous['app'])
            timeline_event(self, 'task_start', self.session.active['label'],
                           {k: self.session.active[k] for k in ('pc_epoch', 'monotonic')},
                           reference=self.session.active['segment_id'], app=self.session.active['app'])
            self.refresh_rows()
            started_at = datetime.fromtimestamp(self.session.active["pc_epoch"]).astimezone()
            self.current.set("Recording · " + self.session.active["label"])
            self.timer.set("00:00:00")
        except Exception as exc:
            messagebox.showerror("Unable to switch task", str(exc), parent=self.root)
        self.update_buttons()

    def quick_segment(self, label, screen):
        self.label.set(label)
        self.app.set("")
        self.note.set("")
        self.screen_state.set(screen)
        if self.session and self.session.active:
            self.switch_segment()
        else:
            self.begin_segment()

    def open_review(self, choose=False):
        if self.busy or (self.session and self.session.state == "recording"):
            return
        if self.review_window and self.review_window.root.winfo_exists() and not choose:
            self.review_window.root.lift()
            return
        if self.review_window and self.review_window.root.winfo_exists() and self.review_window.busy:
            return
        if self.session and not choose:
            path = self.session.root
        else:
            path = filedialog.askdirectory(parent=self.root, title="Select a completed collection directory", initialdir=self.args.out)
        if path:
            try:
                from .manual_review_ui import ManualReviewWindow
                if self.review_window and self.review_window.root.winfo_exists():
                    self.review_window.root.destroy()
                self.review_window = ManualReviewWindow(self.root, path)
            except Exception as exc:
                messagebox.showerror("Cannot open review", str(exc), parent=self.root)

    def refresh_rows(self):
        self.table.delete(*self.table.get_children())
        if self.session.protocol:
            for row in event_windows(self.session.events, self.session.manifest, now=timestamp()):
                status = "Complete" if row["input_eligible"] else ("Incomplete pre-window" if not row["complete_pre"] else "Waiting for post-window")
                if self.session.state in {"complete", "failed"} and not row["complete_post"]:
                    status = "Incomplete post-window"
                self.table.insert("", "end", values=(row["label"], f"{row['pre_seconds']}s / {row['post_seconds']}s",
                    datetime.fromtimestamp(row["pc_event_epoch"]).strftime("%H:%M:%S.%f")[:-3],
                    datetime.fromtimestamp(row["pc_end_epoch"]).strftime("%H:%M:%S.%f")[:-3], status))
            return
        for row in self.session.rows:
            local = lambda key: datetime.fromtimestamp(row[key]).strftime("%H:%M:%S.%f")[:-3]
            self.table.insert("", "end", values=(row["label"], row["app"], local("pc_start_epoch"),
                              local("pc_end_epoch"), f"{row['duration_seconds']:.1f} s"))
        if self.table.get_children():
            self.table.see(self.table.get_children()[-1])

    def stop_capture(self, error=""):
        if self.busy or not self.session or self.session.state != "recording":
            return
        timeline_finish(self, 'capture_stopped')
        at = timestamp()
        self.status.set("Stopping & saving…")
        self.run_worker(lambda: self.session.stop(error, at=at), self.stopped)

    def stopped(self, validation):
        for event in reversed(self.session.events):
            if event['event'] == 'segment_end':
                start = next((e for e in self.session.events if e['event'] in ('segment_start', 'segment_switch')
                              and e.get('segment_id') == event['segment_id']), None)
                if start:
                    timeline_event(self, 'task_end', start['label'], event,
                                   reference=event['segment_id'], app=start.get('app', ''))
                break
        self.refresh_rows()
        if self.session.rows:
            self.show_duration(self.session.rows[-1]["duration_seconds"])
        self.current.set(f"{len(self.session.rows)} tasks saved")
        if self.session.protocol:
            count = validation.metrics.get("event_count", 0)
            complete = validation.metrics.get("complete_event_windows", 0)
            self.current.set(f"Saved {count} events with {complete} complete windows. The continuous capture was retained.")
        if validation.collection_ready:
            self.status.set("Saved · Capture checks passed")
        else:
            self.status.set("Saved · Review required: " + "; ".join(validation.core_errors))
        self.open_button.configure(state="normal")
        if self.closing:
            self.root.destroy()

    def open_output(self):
        if self.session and self.session.root.is_dir():
            os.startfile(self.session.root)

    def close(self):
        if self.review_window and self.review_window.root.winfo_exists() and self.review_window.busy:
            self.status.set("Exporting…")
        elif self.busy:
            self.status.set("Saving or connecting…")
        elif self.session and self.session.state == "recording":
            self.closing = True
            self.stop_capture()
        else:
            self.root.destroy()

    def update_wall_clock(self):
        now = datetime.now().astimezone()
        offset = now.strftime("%z")
        zone = offset[:3] + ":" + offset[3:]
        self.clock_date.set(f"Host local time · {now:%Y-%m-%d} · UTC{zone}")
        self.clock.set(now.strftime("%H:%M:%S"))

    def show_duration(self, seconds):
        elapsed = max(0, int(seconds))
        self.timer.set(f"{elapsed // 3600:02d}:{elapsed // 60 % 60:02d}:{elapsed % 60:02d}")

    def update_event_timing(self, now=None):
        if self.busy or not self.session or self.session.state != "recording":
            return
        schedule = event_schedule(self.session.protocol, self.session.events, now or timestamp())
        if schedule is None:
            return
        due = datetime.fromtimestamp(schedule["next_pc_epoch"])
        prefix = "First marker" if schedule["first"] else "Next independent marker"
        self.next_mark.set(f"{prefix}: {due:%m-%d %H:%M:%S}")
        remaining, tail = schedule["remaining_seconds"], schedule["post_remaining_seconds"]
        if remaining:
            phase = "Recording previous post-window" if schedule["phase"] == "post" else "Recording next pre-window"
            self.next_mark_status.set(f"{remaining // 60:02d}:{remaining % 60:02d} remaining · {phase}. Related events can be marked immediately.")
            self.next_mark_label.configure(foreground="#9a5700")
        else:
            self.next_mark_status.set("Ready. Once the device has recovered, perform the next action and press Space.")
            self.next_mark_label.configure(foreground="#16743c")
            notice = (id(self.session), schedule["next_monotonic"])
            if notice != self.ready_notice:
                self.ready_notice = notice
                self.root.bell()
        self.timer.set(f"Wait {tail} s before ending collection" if tail else
                       ("Last post-window complete. Collection can end." if not schedule["first"] else "Waiting for first event"))

    def tick(self):
        try:
            callback, result, error = self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            if error:
                if self.session and self.session.state == "failed" and self.session.capture is None:
                    self.status.set("Start failed before packet capture or task recording: " + error)
                else:
                    self.status.set("Operation incomplete. Existing files were retained: " + error)
                if self.session and self.session.state == "stopping":
                    self.session.state = "failed"
                self.closing = False
            else:
                callback(result)
            self.update_buttons()
        if not self.root.winfo_exists():
            return
        self.update_wall_clock()
        if self.session and not self.busy and self.session.state == "recording":
            problem = self.session.health_error()
            if problem:
                self.stop_capture(problem)
            elif self.session.active:
                self.show_duration(time.perf_counter() - self.session.active["monotonic"])
            elif self.session.protocol:
                now = timestamp()
                if self.session.protocol["mode"] == "background_observation":
                    self.show_duration(now["monotonic"] - self.session.events[0]["monotonic"])
                else:
                    self.update_event_timing(now)
                    self.refresh_rows()
            size = (self.session.root / "capture.pcap").stat().st_size
            clock = self.session.manifest["clock_start"]
            self.capture_info.set(f"{size / 1048576:.1f} MB · Clock ±{clock['uncertainty_seconds']:.2f}s")
        self.root.after(150, self.tick)


class IoTMarkerWindow:
    """Guided command-to-result annotations in the existing manual tool."""
    ACTION_LABELS = {"power_on": "Power on", "power_off": "Power off", "change_color": "Change color",
                     "brightness_up": "Brighten", "brightness_down": "Dim", "curtain_open": "Open curtain",
                     "curtain_close": "Close curtain", "lock": "Lock", "unlock": "Unlock",
                     "motion_detected": "Trigger motion", "motion_cleared": "Leave sensor area",
                     "doorbell_press": "Press doorbell", "live_view_start": "Start live view",
                     "live_view_stop": "Stop live view", "play": "Play", "pause": "Pause",
                     "volume_up": "Volume up", "volume_down": "Volume down",
                     "talk_session": "Talk", "voice_query": "Voice query"}

    def __init__(self, root, args):
        from .manual_marker import MarkerSession
        self.root, self.args = root, args
        self.session = MarkerSession(Path(args.out) / "iot-markers", RouterCaptureConfig(
            phone_ip="", host=args.router_host, user=args.router_user, identity_file=args.router_identity))
        self.messages = queue.Queue()
        self.busy = self.closing = self.closed = self.space_down = False
        self.pending = self.pending_result = self.active_event = None
        self.phase, self.baseline_started, self.wait_until = "prepare", 0, 0
        self.last_mark_mono = -1.0
        self.capture_options = dict(phone_ip="", host=args.router_host, user=args.router_user,
                                    interface=getattr(args, "router_interface", "br-lan"), identity_file=args.router_identity)
        self.external_capture = tk.BooleanVar(value=False)
        self.capture_scope = 'device_ip'
        root.title("Screen Time · IoT Event Marker")
        root.geometry("1000x720")
        root.minsize(940, 680)
        root.configure(bg="#f3f5f7")
        style = ttk.Style(root)
        style.theme_use("clam")
        for name, bg in (("IoT", "#f3f5f7"), ("IoT.White", "#ffffff")):
            style.configure(name + ".TFrame", background=bg)
            style.configure(name + ".TLabel", background=bg, foreground="#203342", font=("Segoe UI", 11))
        style.configure("IoT.TCombobox", padding=8, font=("Segoe UI", 11),
                        fieldbackground="white", background="white", bordercolor="#cbd4dc", arrowsize=15)
        style.map("IoT.TCombobox", fieldbackground=[("readonly", "white")],
                  selectbackground=[("readonly", "white")], selectforeground=[("readonly", "#203342")])
        style.configure("IoT.Treeview", rowheight=28, font=("Segoe UI", 10),
                        background="white", fieldbackground="white", borderwidth=0)
        style.configure("IoT.Treeview.Heading", font=("Segoe UI", 10), padding=7, relief="flat")
        style.configure("Marker.TButton", font=("Segoe UI", 10), padding=(12, 8))
        collection_theme(root)
        body = ttk.Frame(root, padding=(24, 10, 24, 20), style="IoT.TFrame")
        body.pack(fill="both", expand=True)
        header = ttk.Frame(body, style="IoT.TFrame")
        if not isinstance(root, ModePanel):
            header.pack(fill="x")
        ttk.Label(header, text="Device events", style="IoT.TLabel",
                  font=("Segoe UI", 14, "bold")).pack(side="left")
        self.clock = tk.StringVar()
        ttk.Label(header, textvariable=self.clock, style="IoT.TLabel",
                  font=("Consolas", 11), foreground="#647585").pack(side="right")
        capture_bar = ttk.Frame(body, style="IoT.TFrame")
        capture_bar.pack(fill="x", pady=(12, 18))
        self.capture_button = ttk.Button(capture_bar, text="Start capture", command=self.start_capture, style="Primary.TButton")
        self.capture_button.pack(side="left")
        self.stop_button = ttk.Button(capture_bar, text="Stop & save", command=self.stop, style="Marker.TButton")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.settings_button = ttk.Button(capture_bar, text="Settings", command=self.capture_settings, style="Marker.TButton")
        self.settings_button.pack(side="left", padx=8)
        self.capture_text = tk.StringVar(value="Idle · Auto IP")
        ttk.Label(capture_bar, textvariable=self.capture_text, style="IoT.TLabel", font=("Segoe UI", 10)).pack(side="left", padx=6)
        choices = ttk.Frame(body, style="IoT.TFrame")
        choices.pack(fill="x")
        for col, weight in ((0, 1), (1, 3), (2, 1)):
            choices.columnconfigure(col, weight=weight)
        for col, title in enumerate(("Platform", "Device", "Action")):
            ttk.Label(choices, text=title, style="IoT.TLabel").grid(row=0, column=col, sticky="w", padx=(0 if col == 0 else 12, 0))
        self.catalog = self.session.catalog()
        self.platforms = {t["platform_label"]: t["platform"] for t in self.catalog}
        self.platform, self.device, self.action = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self.platform_input = ttk.Combobox(choices, textvariable=self.platform, values=tuple(self.platforms),
                                          state="readonly", width=15, style="IoT.TCombobox")
        self.device_input = ttk.Combobox(choices, textvariable=self.device, state="readonly", width=31, style="IoT.TCombobox")
        self.action_input = ttk.Combobox(choices, textvariable=self.action, state="readonly", width=18, style="IoT.TCombobox")
        for col, widget in enumerate((self.platform_input, self.device_input, self.action_input)):
            widget.grid(row=1, column=col, sticky="ew", padx=(0 if col == 0 else 12, 0), pady=(6, 18))
        self.platform_input.bind("<<ComboboxSelected>>", self.select_platform)
        self.device_input.bind("<<ComboboxSelected>>", self.select_device)
        self.action_input.bind("<<ComboboxSelected>>", self.select_action)
        capture_bar.pack_forget()
        capture_bar.pack(fill='x', pady=(0, 16))
        steps = ttk.Frame(body, style="IoT.TFrame")
        steps.pack(fill="x", pady=(0, 14))
        self.step_labels = []
        for title in ("1  Prepare", "2  Send", "3  Confirm", "4  Wait"):
            label = ttk.Label(steps, text=title, style="IoT.TLabel", font=("Segoe UI", 10, "bold"))
            label.pack(side="left", expand=True, anchor="w")
            self.step_labels.append(label)
        card = ttk.Frame(body, padding=18, style="IoT.White.TFrame")
        card.pack(fill="x")
        self.phase_text, self.guide, self.timing_text = tk.StringVar(), tk.StringVar(), tk.StringVar()
        ttk.Label(card, textvariable=self.phase_text, style="IoT.White.TLabel",
                  font=("Segoe UI", 18, "bold"), foreground="#243746").pack(anchor="w")
        ttk.Label(card, textvariable=self.guide, wraplength=850, style="IoT.White.TLabel").pack(fill="x", pady=(10, 8))
        self.mark_button = tk.Button(card, command=self.primary, font=("Segoe UI", 12, "bold"),
                                     bg="#087b78", fg="white", activebackground="#076661", activeforeground="white",
                                     relief="flat", bd=0, pady=10, cursor="hand2", disabledforeground="#8997a2")
        self.mark_button.pack(fill="x")
        self.result_area = ttk.Frame(card, style="IoT.White.TFrame")
        self.note = tk.StringVar()
        outcomes = ttk.Frame(self.result_area, style="IoT.White.TFrame")
        outcomes.pack(fill="x")
        self.result_buttons = []
        for title, outcome, color in (("Success", "success", "#087b78"),
                                       ("Failed", "failed", "#a53f36"), ("Unsure", "uncertain", "#647585")):
            button = tk.Button(outcomes, text=title, command=lambda value=outcome: self.confirm(value),
                               font=("Segoe UI", 12, "bold"), bg=color, fg="white",
                               activebackground=color, activeforeground="white", relief="flat", bd=0, pady=10)
            button.pack(side="left", fill="x", expand=True, padx=(0, 8))
            self.result_buttons.append(button)
        ttk.Label(self.result_area, text="Note (optional)",
                  style="IoT.White.TLabel", font=("Segoe UI", 9), foreground="#647585").pack(anchor="w", pady=(10, 3))
        ttk.Entry(self.result_area, textvariable=self.note, font=("Segoe UI", 10)).pack(fill="x")
        self.status = tk.StringVar(value="")
        ttk.Label(body, textvariable=self.status, wraplength=900, style="IoT.TLabel",
                  font=("Segoe UI", 10), foreground="#647585").pack(anchor="w", pady=(10, 12))
        controls = ttk.Frame(body, style="IoT.TFrame")
        controls.pack(fill="x", pady=(0, 15))
        self.undo_button = ttk.Button(controls, text="Discard last", command=self.undo, style="Marker.TButton")
        self.undo_button.pack(side="left")
        self.files_button = ttk.Button(controls, text="Open records", command=self.open_records, style="Marker.TButton")
        self.files_button.pack(side="right")
        ttk.Label(body, text="History", style="IoT.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 6))
        self.table = ttk.Treeview(body, columns=("sent", "confirmed", "device", "action", "result"),
                                  show="headings", height=4, style="IoT.Treeview")
        for key, title, width in (("sent", "Sent", 112), ("confirmed", "Confirmed", 112),
                                   ("device", "Device", 240), ("action", "Action", 135), ("result", "Result", 110)):
            self.table.heading(key, text=title)
            self.table.column(key, width=width, minwidth=80)
        self.table.pack(fill="both", expand=True)
        if not self.platforms:
            self.phase_text.set("No IoT actions configured")
            self.guide.set("Add an IoT task with an action breakdown to collection_tasks.json and reopen the tool.")
            for button in (self.capture_button, self.stop_button, self.mark_button):
                button.configure(state="disabled")
            return
        self.platform.set("Apple Home" if "Apple Home" in self.platforms else next(iter(self.platforms)))
        self.select_platform()
        key_tag = f"IoTMarkerSpace{id(self)}"
        root.bind_class(key_tag, "<KeyPress-space>", self.press_space)
        root.bind_class(key_tag, "<KeyRelease-space>", self.release_space)
        def bind(widget):
            widget.bindtags((key_tag,) + widget.bindtags())
            for child in widget.winfo_children():
                bind(child)
        bind(root)
        root.bind("<FocusOut>", lambda _e: setattr(self, "space_down", False))
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()
        root.after(100, self.tick)

    def select_platform(self, _event=None):
        platform = self.platforms[self.platform.get()]
        self.tasks = {t["name"]: t for t in self.catalog
                      if t["platform"] == platform and t["platform_label"] == self.platform.get()}
        self.device_input.configure(values=tuple(self.tasks))
        self.device.set(next(iter(self.tasks)))
        self.select_device()

    def select_device(self, _event=None):
        self.capture_options['phone_ip'] = ''
        task = self.tasks[self.device.get()]
        self.actions = {self.ACTION_LABELS.get(r["key"], r["key"].replace("_", " ").capitalize()): r["key"] for r in task["actions"]}
        self.action_input.configure(values=tuple(self.actions))
        self.action.set(next(iter(self.actions)))
        self.select_action()

    def select_action(self, _event=None):
        from .manual_marker import marker_protocol
        task, action = self.tasks[self.device.get()], self.actions[self.action.get()]
        self.protocol = marker_protocol(task, action)
        self.preparation = {"power_on": "Make sure the device is off.", "power_off": "Make sure the device is on.",
                            "change_color": "Turn the light on and keep its current color.",
                            "brightness_up": "Turn the light on below maximum brightness.",
                            "brightness_down": "Turn the light on above minimum brightness.",
                            "curtain_open": "Close the curtain.", "curtain_close": "Open the curtain.",
                            "unlock": "Make sure the door is locked.", "lock": "Make sure the door is unlocked.",
                            "play": "Pause playback.", "pause": "Start playback.",
                            "live_view_start": "Close live view.", "live_view_stop": "Open live view.",
                            "doorbell_press": "Make sure the doorbell is ready to ring.",
                            "motion_detected": "Leave the sensor area and wait for the sensor to reset.",
                            "motion_cleared": "Enter the sensor area to trigger it."}.get(action, "Prepare the device for this action.")
        self.operation = {"doorbell_press": "Press the physical doorbell", "motion_detected": "Enter the sensor area",
                          "motion_cleared": "Leave the sensor area"}.get(action, f"Use {self.platform.get()} to {self.action.get().lower()}")
        self.phase = "prepare"
        if hasattr(self, "status"):
            self.refresh()
        self.root.focus_set()

    def primary(self):
        if self.busy:
            return
        if self.pending:
            self.mark()
        elif self.pending_result:
            self.confirm(self.pending_result[1])
        elif self.phase == "prepare":
            self.start()
        elif self.phase == "ready":
            self.mark()
        elif self.phase in {"next", "saved"}:
            self.phase, self.active_event = "prepare", None
            self.note.set("")
            self.refresh()

    def capture_settings(self):
        if self.busy or self.session.manifest['status'] == 'recording':
            return
        dialog = tk.Toplevel(self.root)
        dialog.title('Capture settings')
        dialog.transient(self.root.winfo_toplevel())
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill='both', expand=True)
        fields = {}
        for row, (key, label) in enumerate((('host', 'Router'),
                ('interface', 'Interface'), ('user', 'SSH user'), ('identity_file', 'SSH key'))):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', pady=7, padx=(0, 16))
            fields[key] = tk.StringVar(value=self.capture_options[key] or '')
            ttk.Entry(frame, textvariable=fields[key], width=52).grid(row=row, column=1, sticky='ew')
        ttk.Label(frame, text='Capture scope').grid(row=4, column=0, sticky='w', pady=7)
        scope = tk.StringVar(value=CAPTURE_SCOPES[self.capture_scope])
        ttk.Combobox(frame, textvariable=scope, values=tuple(CAPTURE_SCOPES.values()),
                     state='readonly', width=40).grid(row=4, column=1, sticky='ew')
        ttk.Label(frame, text='Whole network includes other devices; router SSH traffic is excluded. Diagnostic use only.',
                  wraplength=510).grid(row=5, column=0, columnspan=2, sticky='w', pady=8)
        ttk.Label(frame, text='Save to: ' + str(self.session.parent), wraplength=510).grid(row=6, column=0, columnspan=2, sticky='w')
        external = tk.BooleanVar(value=self.external_capture.get())
        ttk.Checkbutton(frame, text='Use an existing capture (marks only)', variable=external).grid(row=7, column=0, columnspan=2, sticky='w', pady=12)
        def save():
            options = {'phone_ip': '', **{key: value.get().strip() for key, value in fields.items()}}
            self.capture_options = options
            self.external_capture.set(external.get())
            self.capture_scope = next(key for key, label in CAPTURE_SCOPES.items() if label == scope.get())
            self.session.router = RouterCaptureConfig(**options)
            dialog.destroy()
            self.refresh()
        ttk.Button(frame, text='Save', command=save).grid(row=8, column=1, sticky='e')

    def start_capture(self):
        if self.busy or self.session.manifest['status'] == 'recording':
            return
        task_id = self.tasks[self.device.get()]['id']
        def ready(_result):
            self.phase = 'prepare'
        self.worker(lambda: self.session.start_capture(task_id, RouterCaptureConfig(**self.capture_options),
                                                      capture_scope=self.capture_scope),
                    'Detecting device address and starting capture…', ready)

    def render_phase(self):
        pre, post, cooldown = (self.protocol[k] for k in ("pre_seconds", "post_seconds", "cooldown_seconds"))
        step = {"prepare": 0, "baseline": 0, "ready": 1, "confirm": 2, "blank": 3, "next": 3, "saved": 3}[self.phase]
        for i, label in enumerate(self.step_labels):
            label.configure(foreground="#087b78" if i == step else "#8a98a4")
        now = time.perf_counter()
        if self.phase == "prepare":
            title, detail = "Prepare", self.preparation
            timing, button = "", f"Ready — start {pre:g}s wait"
        elif self.phase == "baseline":
            remaining = max(0, math.ceil(self.baseline_started + pre - now))
            title, detail = f"Wait {remaining}s", "Leave the device untouched until the beep."
            timing, button = "", "Waiting…"
        elif self.phase == "ready":
            title, detail = "Send command", f"{self.operation} and press Space at the same time."
            timing, button = "", "Command sent [Space]"
        elif self.phase == "confirm":
            title, detail = "Confirm result", "Choose the result you observe on the device."
            timing, button = "", ""
        elif self.phase == "blank":
            remaining = max(0, math.ceil(self.wait_until - now))
            title, detail = f"Wait {remaining}s", "Leave the device untouched before the next trial."
            timing = f"Quiet period after the result: {post:g}s" + (f" + {cooldown:g}s cooldown." if cooldown else ".")
            button = "Waiting…"
        elif self.phase == "next":
            title, detail = "Trial complete", "Repeat, change the action, or finish."
            timing, button = "", "Next trial"
        else:
            title, detail = "Saved", "Open records or start a new session."
            timing, button = "", "New session"
        self.phase_text.set(title)
        self.guide.set(detail)
        self.timing_text.set(timing)
        if self.phase == "confirm" and not self.pending_result:
            self.mark_button.pack_forget()
            self.result_area.pack(fill="x")
        else:
            self.result_area.pack_forget()
            self.mark_button.pack(fill="x")
        self.mark_button.configure(text="Retry saving command" if self.pending else "Retry saving result" if self.pending_result else button,
                                   state="normal" if not self.busy and (self.pending or self.pending_result or self.phase in {"prepare", "ready", "next", "saved"}) else "disabled")
        if not self.external_capture.get() and not self.session.capture_status()['recording'] and not self.pending and not self.pending_result:
            self.mark_button.configure(state='disabled')
        self.mark_button.configure(bg='#e8edf1' if str(self.mark_button['state']) == 'disabled' else '#087b78')
        for button in self.result_buttons:
            button.configure(state="disabled" if self.busy else "normal")

    def refresh(self):
        active, rows = self.session.manifest["status"] == "recording", self.session.rows()
        unlocked = not self.busy and not self.pending and not self.pending_result and self.phase in {"prepare", "next", "saved"}
        for widget in (self.platform_input, self.device_input, self.action_input):
            widget.configure(state="readonly" if unlocked else "disabled")
        if active and self.session.manifest.get('capture_owned'):
            self.platform_input.configure(state='disabled')
            self.device_input.configure(state='disabled')
        self.capture_button.configure(state='disabled' if active or self.busy or self.external_capture.get() else 'normal')
        self.settings_button.configure(state='disabled' if active or self.busy else 'normal')
        self.stop_button.configure(state="normal" if active and not self.busy and not self.pending and not self.pending_result else "disabled")
        self.undo_button.configure(state="normal" if active and not self.busy and not self.pending and not self.pending_result and any(not r["voided"] for r in rows) else "disabled")
        self.files_button.configure(state="normal" if self.session.root and not self.busy else "disabled")
        self.table.delete(*self.table.get_children())
        def clock(value):
            return datetime.fromtimestamp(value).strftime("%H:%M:%S.%f")[:-3] if value is not None else "—"
        for row in reversed(rows[-50:]):
            outcome = {"success": "Success", "failed": "Failed", "uncertain": "Uncertain", "unconfirmed": "Not confirmed"}[row["outcome"]]
            if row["voided"]:
                outcome = "Discarded"
            elif not row["clock_alignment_valid"] or row.get("outcome_clock_alignment_valid") is False:
                outcome += " · clock!"
            self.table.insert("", "end", values=(clock(row["pc_epoch"]), clock(row.get("confirmed_pc_epoch")),
                              row["device_name"], self.ACTION_LABELS.get(row["action"], row["action"]), outcome))
        self.render_phase()

    def worker(self, action, message, success=None):
        if self.busy:
            return
        self.busy = True
        self.status.set(message)
        self.refresh()
        def run():
            try:
                self.messages.put((action(), None, success))
            except Exception as exc:
                import traceback
                traceback.print_exc()
                self.messages.put((None, str(exc), None))
        threading.Thread(target=run, daemon=False).start()

    def begin_baseline(self, _result=None):
        self.baseline_started, self.phase = time.perf_counter(), "baseline"
        self.note.set("")
        return "Session running. Follow the highlighted step."

    def start(self):
        if not self.external_capture.get() and not self.session.capture_status()['recording']:
            self.status.set('Start capture first.')
            return
        if self.session.manifest["status"] == "recording":
            self.status.set(self.begin_baseline())
            self.refresh()
        else:
            self.worker(self.session.start, "Starting session and synchronizing the clock…", self.begin_baseline)

    def mark(self, *, at=None, source="button"):
        if self.busy or self.session.manifest["status"] != "recording" or (not self.pending and self.phase != "ready"):
            return
        at = at or timestamp()
        if not self.pending and at["monotonic"] - self.last_mark_mono < .35:
            return
        self.last_mark_mono = at["monotonic"]
        if not self.pending:
            self.pending = ({"request_id": str(uuid.uuid4()), "task_id": self.tasks[self.device.get()]["id"],
                             "action": self.actions[self.action.get()], "input_source": source, "requires_outcome": True,
                             **{k: self.protocol[k] for k in ("pre_seconds", "post_seconds", "cooldown_seconds")},
                             "baseline_start_monotonic": self.baseline_started,
                             "baseline_ready": at["monotonic"] >= self.baseline_started + self.protocol["pre_seconds"],
                             "timing_protocol_source": self.protocol["source"]}, at)
        payload, recorded_at = self.pending
        def saved(row):
            self.pending = None
            self.active_event, self.phase = row["event_id"], "confirm"
            timeline_event(self, 'command', payload['action'], recorded_at, reference=row['event_id'])
            return "Command time saved. Observe the device and record the result."
        self.worker(lambda: self.session.mark(payload, at=recorded_at), "Saving command time…", saved)

    def confirm(self, outcome):
        if self.busy or self.phase != "confirm":
            return
        if not self.pending_result:
            self.pending_result = (self.active_event, outcome, self.note.get(), timestamp())
        event_id, outcome, note, at = self.pending_result
        def saved(row):
            self.pending_result = None
            command = next(e for e in self.session.events if e.get('event_id') == event_id and e['event'] == 'event_mark')
            timeline_event(self, 'result', command['action'], at, reference=event_id, outcome=outcome)
            self.phase = "blank"
            self.wait_until = row["monotonic"] + self.protocol["post_seconds"] + self.protocol["cooldown_seconds"]
            return "Result saved. Wait before preparing or issuing another command."
        self.worker(lambda: self.session.confirm(event_id, outcome, note=note, at=at), "Saving result time…", saved)

    def press_space(self, event):
        if str(event.widget.winfo_class()) in {"Entry", "TEntry", "Text", "TCombobox"} or event.state & (0x1 | 0x4 | 0x8):
            return
        if not self.space_down:
            self.space_down = True
            if self.phase == "ready":
                self.mark(at=timestamp(), source="keyboard_space")
        return "break"

    def release_space(self, _event):
        self.space_down = False
        return "break"

    def undo(self):
        row = next(r for r in reversed(self.session.rows()) if not r["voided"])
        def saved(_result):
            timeline_event(self, 'void', row['action'], self.session.events[-1], reference=row['event_id'])
            self.active_event, self.phase = None, "blank"
            self.wait_until = time.perf_counter() + self.protocol["post_seconds"] + self.protocol["cooldown_seconds"]
            return "Trial discarded; raw history retained. Wait in case the physical action occurred."
        self.worker(lambda: self.session.undo(row["event_id"]), "Discarding trial…", saved)

    def stop(self):
        timeline_finish(self, 'capture_stopped')
        def saved(_result):
            self.phase = "saved"
            unresolved = sum(not r["voided"] and r["outcome"] == "unconfirmed" for r in self.session.rows())
            return "Session saved." + (f" {unresolved} trial(s) have no confirmed result." if unresolved else "") + (
                " Capture needs review." if self.session.manifest.get('capture_owned') and not self.session.manifest.get('capture_collection_ready') else "") + (
                " Final clock check needs review." if self.session.manifest.get("clock_end_error") else "") + (
                " Final quiet period was incomplete." if any(r.get("post_window_complete") is False for r in self.session.rows()) else "")
        self.worker(self.session.stop, "Saving session and checking the clock…", saved)

    def open_records(self):
        if self.session.root:
            os.startfile(self.session.root)

    def close(self):
        self.closing = True
        self.advance_close()

    def advance_close(self):
        if self.busy:
            self.status.set("Saving before closing…")
        elif self.pending:
            self.mark()
        elif self.pending_result:
            self.confirm(self.pending_result[1])
        elif self.session.manifest["status"] == "recording":
            self.stop()
        else:
            self.closed = True
            self.root.destroy()

    def tick(self):
        if self.closed:
            return
        self.clock.set(datetime.now().astimezone().strftime("%H:%M:%S"))
        try:
            result, error, success = self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            message = success(result) if success and not error else ""
            self.status.set("Operation failed: " + error if error else message if self.phase == "saved" else "")
            self.refresh()
            if self.closing:
                if error:
                    self.closing = False
                    if messagebox.askyesno("Save incomplete", "Raw records are retained, but saving could not finish.\nClose anyway?\n\n" + error, parent=self.root):
                        self.closed = True
                        self.root.destroy()
                        return
                else:
                    self.advance_close()
                    if self.closed:
                        return
            self.root.focus_set()
        if not self.busy:
            capture = self.session.capture_status()
            diagnostic = self.session.manifest.get('traffic_scope') == 'lan_diagnostic'
            self.capture_text.set((f"{'Whole network · Target' if diagnostic else 'Capturing ·'} {capture['ip']} · {capture['bytes'] / 1048576:.1f} MB" if capture['recording'] else
                                  'Capture error · see status' if capture.get('error') else
                                  'Marks only · external capture' if self.external_capture.get() else
                                  'Idle · Whole network (diagnostic)' if self.capture_scope == 'lan_diagnostic' else
                                  'Idle · Auto IP'))
            if capture.get('error') and self.session.manifest['status'] == 'recording' and self.session.manifest.get('capture_owned'):
                self.session.manifest['capture_error'] = capture['error']
                self.stop()
            now = time.perf_counter()
            if self.phase == "baseline" and now >= self.baseline_started + self.protocol["pre_seconds"]:
                self.phase = "ready"
                self.root.bell()
                self.refresh()
            elif self.phase == "blank" and now >= self.wait_until:
                self.phase = "next"
                self.root.bell()
                self.refresh()
            else:
                self.render_phase()
        self.root.after(100, self.tick)


class ModePanel(tk.Frame):
    """Embed an existing controller without taking ownership of another mode."""
    def __init__(self, shell):
        super().__init__(shell.root)
        self.shell = shell
        self.window_size = '960x730'
        self.minimum_size = (900, 690)

    def title(self, _title):
        self.shell.root.title('Screen Time · Collection Tool')

    def geometry(self, size):
        self.window_size = size

    def minsize(self, width, height):
        self.minimum_size = (width, height)

    def protocol(self, _name, _callback):
        # The shell delegates close to the currently visible controller.
        pass

    def destroy(self):
        if self.shell.destroying:
            super().destroy()
        else:
            self.shell.destroying = True
            self.shell.root.destroy()


class CollectionToolWindow:
    """One visible mode; keep each existing controller and its records intact."""
    def __init__(self, root, args):
        self.root, self.args = root, args
        self.destroying = False
        self.controllers = {}
        self.current_mode = None
        bar = ttk.Frame(root, padding=(26, 10))
        bar.pack(fill='x')
        collection_theme(root)
        ttk.Label(bar, text='Collection', font=('Segoe UI', 17, 'bold')).pack(side='left', padx=(0, 24))
        self.mode = tk.StringVar(value='IoT Events' if getattr(args, 'marker_only', False) else 'Screen Time')
        self.selector = ttk.Combobox(bar, textvariable=self.mode,
                                    values=('Screen Time', 'IoT Events'), state='readonly', width=20)
        self.mode_buttons = {}
        for label in ('Screen Time', 'IoT Events'):
            def choose(value=label):
                self.mode.set(value)
                self.select_mode()
            button = ttk.Button(bar, text=label, command=choose, width=13)
            button.pack(side='left', padx=(0, 4))
            self.mode_buttons[label] = button
        self.hint = tk.StringVar()
        ttk.Label(bar, textvariable=self.hint).pack(side='left', padx=16)
        self.wall_clock = tk.StringVar()
        ttk.Label(bar, textvariable=self.wall_clock, font=('Consolas', 11), foreground='#71818d').pack(side='right')
        self.selector.bind('<<ComboboxSelected>>', self.select_mode)
        from .manual_timeline_ui import TimelinePanel
        self.schedule = TimelinePanel(self)
        self.select_mode()
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(150, self.tick)

    def locked(self):
        schedule = getattr(self, 'schedule', None)
        if schedule and schedule.run and not schedule.run.stopped:
            return True
        for _panel, controller in self.controllers.values():
            if controller.busy or getattr(controller, 'pending', None) or getattr(controller, 'pending_result', None):
                return True
            session = controller.session
            if session and (getattr(session, 'state', None) in ('starting', 'recording', 'stopping')
                            or getattr(session, 'manifest', {}).get('status') == 'recording'):
                return True
            review = getattr(controller, 'review_window', None)
            if review and review.root.winfo_exists():
                return True
        return False

    def select_mode(self, _event=None):
        target = self.mode.get()
        if target == self.current_mode:
            return
        if self.locked():
            self.mode.set(self.current_mode)
            return
        if target not in self.controllers:
            panel = ModePanel(self)
            controller = (IoTMarkerWindow if target == 'IoT Events' else ManualGroundTruthWindow)(panel, self.args)
            self.controllers[target] = (panel, controller)
        if self.current_mode:
            self.controllers[self.current_mode][0].pack_forget()
        self.current_mode = target
        for name, button in self.mode_buttons.items():
            button.configure(style='Primary.TButton' if name == target else 'TButton')
        panel, _controller = self.controllers[target]
        panel.pack(fill='both', expand=True)
        width, height = map(int, panel.window_size.split('x'))
        self.root.geometry(f'{width}x{height + 95}')
        self.root.minsize(*panel.minimum_size)
        panel.focus_set()

    def close(self):
        self.schedule.finish('window_closed')
        self.controllers[self.current_mode][1].close()

    def tick(self):
        if self.destroying:
            return
        locked = self.locked()
        self.selector.configure(state='disabled' if locked else 'readonly')
        for button in self.mode_buttons.values():
            button.configure(state='disabled' if locked else 'normal')
        self.hint.set('Session active' if locked else '')
        self.wall_clock.set(datetime.now().strftime('%H:%M:%S'))
        try:
            self.schedule.update()
        except (ValueError, OSError) as exc:
            self.schedule.error = 'Timeline error: ' + str(exc)
        self.root.after(150, self.tick)


def open_manual_window(args) -> int:
    root = tk.Tk()
    window = CollectionToolWindow(root, args)
    if getattr(args, 'timeline', None):
        root.after(100, lambda: window.schedule.import_plan(args.timeline))
    root.mainloop()
    return 0

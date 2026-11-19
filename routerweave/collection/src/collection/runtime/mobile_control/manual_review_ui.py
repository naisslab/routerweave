"""Review missing behavior intervals and export portable data; no model runtime."""
from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .manual_annotations import bounds, export_snapshot, load_timeline, revise_interval


class ManualReviewWindow:
    def __init__(self, parent, run):
        self.run = Path(run).resolve()
        self.start, self.end, self.manifest = bounds(self.run)
        self.iot = bool(self.manifest.get('manual_protocol'))
        self.rows = load_timeline(self.run)
        self.root = tk.Toplevel(parent)
        self.root.title('Screen Time · Review and export')
        self.root.geometry('1100x700')
        self.root.minsize(950, 620)
        self.busy = False
        self.selected = None
        self.messages = queue.Queue()
        self.result_dir = None
        body = ttk.Frame(self.root, padding=24)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text=self.run.name, font=('Microsoft YaHei UI', 17, 'bold')).pack(anchor='w')
        self.status = tk.StringVar()
        ttk.Label(body, textvariable=self.status, wraplength=1010).pack(anchor='w', pady=12)
        table_box = ttk.Frame(body)
        table_box.pack(fill='both', expand=True)
        self.table = ttk.Treeview(table_box, columns=('start','end','label','app','status'), show='headings', height=8)
        for key,title,width in [('start','Start',180),('end','End',180),('label','Activity',180),('app','App',160),('status','Label status',130)]:
            self.table.heading(key,text=title)
            self.table.column(key,width=width)
        self.table.pack(side='left',fill='both',expand=True)
        scroll = ttk.Scrollbar(table_box,command=self.table.yview)
        scroll.pack(side='right',fill='y')
        self.table.configure(yscrollcommand=scroll.set)
        self.table.bind('<<TreeviewSelect>>',self.select_row)
        form = ttk.Frame(body)
        form.pack(fill='x',pady=18)
        from .manual_ui import LABELS
        self.a,self.b,self.label,self.app,self.reason = (tk.StringVar() for _ in range(5))
        self.exclude = tk.BooleanVar(value=False)
        self.controls=[]
        for i,(title,variable) in enumerate([('Start offset (s)',self.a),('End offset (s)',self.b),('Task label',self.label),('App (optional)',self.app)]):
            ttk.Label(form,text=title).grid(row=0,column=i,sticky='w')
            field = (ttk.Combobox(form,textvariable=variable,values=LABELS,width=20) if variable==self.label
                     else ttk.Entry(form,textvariable=variable,width=18))
            field.grid(row=1,column=i,sticky='ew',padx=(0,10),pady=(6,14))
            form.columnconfigure(i,weight=1)
            self.controls.append(field)
        ttk.Label(form,text='Reason for annotation or revision').grid(row=2,column=0,sticky='w')
        reason=ttk.Entry(form,textvariable=self.reason)
        reason.grid(row=3,column=0,columnspan=3,sticky='ew',padx=(0,10),pady=6)
        exclude=ttk.Checkbutton(form,text='Uncertain: exclude interval',variable=self.exclude)
        exclude.grid(row=2,column=3,sticky='w')
        self.save_button=ttk.Button(form,text='Save annotation',command=self.save_review)
        self.save_button.grid(row=3,column=3,sticky='ew')
        self.controls.extend([reason,exclude,self.save_button])
        if self.iot:
            form.pack_forget()
            self.table.heading('start', text='Manual event time')
            self.table.heading('end', text='Post-window end')
            self.table.heading('app', text='Pre / post window')
        ttk.Label(body,text=('Events retain their original marker times. Events with incomplete windows remain in the export but are excluded from inputs. Raw traffic is retained.' if self.iot else
                            'No-task intervals are excluded automatically. Correct any missing or incorrect task labels. Offsets are in seconds from the start of the run.'),
                  wraplength=1010).pack(anchor='w')
        actions=ttk.Frame(body)
        actions.pack(fill='x',pady=(20,0))
        self.export_button=ttk.Button(actions,text='Verify and export',command=self.export)
        self.export_button.pack(side='right')
        self.open_button=ttk.Button(actions,text='Open export folder',command=self.open_result,state='disabled')
        self.open_button.pack(side='right',padx=10)
        self.controls.append(self.export_button)
        self.root.protocol('WM_DELETE_WINDOW',self.close)
        self.refresh()
        self.root.after(150,self.tick)

    def refresh(self):
        self.rows=load_timeline(self.run)
        self.table.delete(*self.table.get_children())
        if self.iot:
            from .manual_ground_truth import event_windows, read_events
            points = event_windows(read_events(self.run), self.manifest)
            for i, point in enumerate(points):
                local = lambda key: datetime.fromtimestamp(point[key]).strftime('%H:%M:%S.%f')[:-3]
                self.table.insert('', 'end', iid=str(i), values=(local('pc_event_epoch'), local('pc_end_epoch'),
                    point['label'], f"{point['pre_seconds']}s / {point['post_seconds']}s",
                    'Complete' if point['input_eligible'] else 'Incomplete window'))
            self.status.set(f"Manual events: {len(points)}. Complete windows: {sum(p['input_eligible'] for p in points)}. Sensor states were not verified automatically."
                            if self.manifest['manual_protocol']['mode'] == 'event_markers' else
                            f"Observed routine traffic for {self.end-self.start:.1f} s without state labels.")
            return
        names=dict(pending='Pending',recorded='Recorded',confirmed='Revised',excluded='Excluded')
        for i,row in enumerate(self.rows):
            local=lambda key:datetime.fromtimestamp(row[key]).strftime('%H:%M:%S.%f')[:-3]
            self.table.insert('','end',iid=str(i),values=(local('pc_start_epoch'),local('pc_end_epoch'),
                              'No task' if row['label']=='no_task' else row['label'],row['app'],names[row['review_status']]))
        pending=sum(r['pc_end_epoch']-r['pc_start_epoch'] for r in self.rows if r['review_status']=='pending')
        excluded=sum(r['pc_end_epoch']-r['pc_start_epoch'] for r in self.rows if r['review_status']=='excluded')
        task_seconds=sum(r['pc_end_epoch']-r['pc_start_epoch'] for r in self.rows if r['review_status'] in {'recorded','confirmed'})
        self.status.set(f'Task: {task_seconds:.1f} s · Excluded: {excluded:.1f} s · Pending: {pending:.1f} s.')

    def select_row(self,_event=None):
        if self.iot or self.busy or not self.table.selection():
            return
        self.selected=self.rows[int(self.table.selection()[0])]
        self.initial_a=f"{self.selected['pc_start_epoch']-self.start:.6f}"
        self.initial_b=f"{self.selected['pc_end_epoch']-self.start:.6f}"
        self.a.set(self.initial_a)
        self.b.set(self.initial_b)
        self.label.set(self.selected['label'])
        self.app.set(self.selected['app'])
        self.reason.set('')
        self.exclude.set(self.selected['review_status']=='excluded')

    def save_review(self):
        if self.iot or self.busy:
            return
        try:
            if not self.selected:
                raise ValueError('Select an interval to annotate or revise.')
            a=self.selected['pc_start_epoch'] if self.a.get()==self.initial_a else self.start+float(self.a.get())
            b=self.selected['pc_end_epoch'] if self.b.get()==self.initial_b else self.start+float(self.b.get())
            revise_interval(self.run,start=a,end=b,label=self.label.get(),app=self.app.get(),
                            screen_state=self.selected['screen_state'],reason=self.reason.get(),exclude=self.exclude.get())
            self.selected=None
            self.refresh()
        except Exception as exc:
            messagebox.showerror('Label not saved',str(exc),parent=self.root)

    def new_output(self):
        return self.run.parent.parent/'manual-screen-time-exports'/self.run.name/datetime.now().strftime('%Y%m%d-%H%M%S-%f')

    def export(self):
        if self.busy:
            return
        self.busy=True
        for widget in self.controls:
            widget.configure(state='disabled')
        out=self.new_output()
        self.status.set('Checking timestamps, capture integrity, and labels, and copying the data for export…')
        def work():
            try:
                value=export_snapshot(self.run,out)
                self.messages.put((out,value,None))
            except Exception as exc:
                self.messages.put((None,None,str(exc)))
        threading.Thread(target=work,daemon=False).start()

    def tick(self):
        try:
            out,value,error=self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy=False
            for widget in self.controls:
                widget.configure(state='normal')
            if error:
                self.status.set('Export incomplete: '+error)
            else:
                self.result_dir=out
                self.open_button.configure(state='normal')
                if not value['capture_ready']:
                    result='Capture check failed: '+'; '.join(value['errors'])
                elif self.iot:
                    result = f"Traffic and events exported. Complete event windows: {sum(p['input_eligible'] for p in value['event_windows'])}."
                elif value['task_data_ready']:
                    result=f"Verified the continuous PCAP. No-task intervals total {value['no_task_seconds']:.1f} s and have input_eligible=False."
                else:
                    result=f"Verified. Pending: {value['review_seconds']['pending']:.1f} s. Excluded: {value['review_seconds']['excluded']:.1f} s. Labeled intervals are usable separately."
                self.status.set(result+' Export folder: '+str(out))
        self.root.after(150,self.tick)

    def open_result(self):
        if self.result_dir:
            os.startfile(self.result_dir)

    def close(self):
        if self.busy:
            self.status.set('Export in progress. Wait for completion before closing.')
        else:
            self.root.destroy()

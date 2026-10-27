"""Windows-first Tk/ttk application. tkinterdnd2 is an optional drag/drop enhancement."""
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .catalog import METHODS, METHOD_BY_CODE, MODERN, HISTORICAL
from .engine import Options, encrypt, decrypt, inspect_file

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None

BG = '#0b1220'
PANEL = '#142036'
CARD = '#1b2b43'
TEXT = '#eaf1fd'
MUTED = '#9eafc9'
ACCENT = '#62b1ff'
ORANGE = '#ffc177'
RED = '#ff8a8a'


def _display_size(number):
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if number < 1024 or unit == 'TiB':
            return f'{number:,.1f} {unit}' if unit != 'B' else f'{number:,} B'
        number /= 1024


class CipherApp:
    def __init__(self):
        self.root = TkinterDnD.Tk() if TkinterDnD else tk.Tk()
        self.root.title(f'CASSipher  ·  {__version__}')
        self.root.geometry('1170x790')
        self.root.minsize(930, 660)
        self.root.configure(bg=BG)
        self.cancel_flag = threading.Event()
        self.messages = queue.Queue()
        self.active = False
        self.inputs = []
        self.method_code = 'aes256'
        self._output_auto = True
        self._build_style()
        self._build()
        self.root.after(75, self._poll)

    def _build_style(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', background=BG, foreground=TEXT, font=('Segoe UI', 10))
        style.configure('TFrame', background=BG)
        style.configure('Panel.TFrame', background=PANEL)
        style.configure('TLabel', background=BG, foreground=TEXT)
        style.configure('Muted.TLabel', foreground=MUTED)
        style.configure('Panel.TLabel', background=PANEL, foreground=TEXT)
        style.configure('PanelMuted.TLabel', background=PANEL, foreground=MUTED)
        style.configure('TButton', background=CARD, foreground=TEXT, padding=(12, 8), borderwidth=0)
        style.map('TButton', background=[('active', '#284566'), ('disabled', PANEL)], foreground=[('disabled', MUTED)])
        style.configure('Accent.TButton', background='#2461aa', foreground='white', padding=(18, 10), font=('Segoe UI Semibold', 10))
        style.map('Accent.TButton', background=[('active','#3276cc'), ('disabled',PANEL)])
        style.configure('TEntry', fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT, padding=7)
        style.configure('TCombobox', fieldbackground=CARD, background=CARD, foreground=TEXT, arrowcolor=TEXT, padding=5)
        style.map('TCombobox', fieldbackground=[('readonly',CARD)], foreground=[('readonly',TEXT)])
        style.configure('TNotebook', background=BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=PANEL, foreground=MUTED, padding=(22,12), borderwidth=0, font=('Segoe UI Semibold', 11))
        style.map('TNotebook.Tab', background=[('selected','#223955')], foreground=[('selected',TEXT)])
        style.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=32, borderwidth=0)
        style.map('Treeview', background=[('selected','#23588d')], foreground=[('selected','white')])
        style.configure('Treeview.Heading', background=CARD, foreground=MUTED, padding=8, font=('Segoe UI Semibold', 9))
        style.configure('TProgressbar', background=ACCENT, troughcolor=PANEL)
        style.configure('TCheckbutton', background=BG, foreground=TEXT)
        style.map('TCheckbutton', background=[('active', BG)], foreground=[('active',TEXT)])

    def _text(self, parent, text, muted=False, size=None, bold=False, **pack):
        font=('Segoe UI Semibold' if bold else 'Segoe UI', size or 10)
        widget=tk.Label(parent, text=text, bg=parent.cget('bg') if isinstance(parent, (tk.Frame, tk.LabelFrame)) else BG,
                        fg=MUTED if muted else TEXT, font=font, anchor='w', justify='left')
        widget.pack(**pack)
        return widget

    def _field(self, parent, label, variable, width=None, show=None):
        r = ttk.Frame(parent)
        r.pack(fill='x', pady=(0,9))
        ttk.Label(r, text=label, style='Muted.TLabel').pack(anchor='w', pady=(0,3))
        entry = ttk.Entry(r, textvariable=variable, width=width, show=show)
        entry.pack(fill='x')
        return entry

    def _build(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill='x', padx=26, pady=(19,15))
        tk.Label(header, text='◆', font=('Segoe UI Symbol',27), bg=BG, fg=ACCENT).pack(side='left', padx=(0,10))
        names = tk.Frame(header, bg=BG)
        names.pack(side='left')
        self._text(names, 'CASSipher', size=19, bold=True, anchor='w')
        self._text(names, 'Offline encryption  •  file protection  •  historical cryptography', muted=True, size=10, anchor='w')
        tk.Label(header, text=f'RESEARCH BUILD  •  v{__version__}', bg=CARD, fg=ORANGE, padx=12, pady=7,
                 font=('Segoe UI Semibold',9)).pack(side='right', pady=8)

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill='both', expand=True, padx=22, pady=(0,12))
        self.enc_tab=ttk.Frame(self.tabs)
        self.dec_tab=ttk.Frame(self.tabs)
        self.lib_tab=ttk.Frame(self.tabs)
        self.tabs.add(self.enc_tab, text='  01  ENCRYPT  ')
        self.tabs.add(self.dec_tab, text='  02  DECRYPT  ')
        self.tabs.add(self.lib_tab, text='  03  METHODS LIBRARY  ')
        self._build_encrypt()
        self._build_decrypt()
        self._build_library()

        footer=ttk.Frame(self.root)
        footer.pack(side='bottom', fill='x', padx=26, pady=(0,17), before=self.tabs)
        self.status=ttk.Label(footer, text='Ready • No file data leaves this computer.', style='Muted.TLabel')
        self.status.pack(side='left')
        self.progress=ttk.Progressbar(footer, orient='horizontal', maximum=100, length=220)
        self.progress.pack(side='right', padx=(12,0))
        self.stop_button=ttk.Button(footer, text='Cancel', command=self.cancel_flag.set, state='disabled')
        self.stop_button.pack(side='right', padx=(12,0))

    def _filtered(self, query, family, security, ordering):
        pool=[m for m in METHODS if (not query or query.casefold() in (m.name+' '+m.summary).casefold())
              and (family=='All families' or m.family==family)
              and (security=='All statuses' or m.security==security)]
        if ordering=='Year / oldest':
            pool.sort(key=lambda m:(0 if m.year=='Antiquity' else 1 if m.year in ('Classical',) else 2, m.year))
        elif ordering=='Year / newest':
            pool.reverse()  # preliminary; sorted deterministically next
            pool.sort(key=lambda m: (int(m.year[:4]) if m.year[:4].isdigit() else 0), reverse=True)
        elif ordering=='Category':
            pool.sort(key=lambda m:(m.family, m.name))
        elif ordering=='Security status':
            priority={'Recommended':0,'Special requirements':1,'Research':2,'Broken':3}
            pool.sort(key=lambda m:(priority.get(m.security,5),m.name))
        else:
            pool.sort(key=lambda m:m.name)
        return pool

    def _create_method_tree(self, parent, is_library=False):
        block=ttk.Frame(parent)
        block.pack(fill='both', expand=True)
        filterrow=ttk.Frame(block)
        filterrow.pack(fill='x', pady=(0,8))
        q=tk.StringVar()
        search=ttk.Entry(filterrow, textvariable=q)
        search.pack(fill='x')
        combos=ttk.Frame(block)
        combos.pack(fill='x', pady=(0,8))
        fam=tk.StringVar(value='All families')
        security=tk.StringVar(value='All statuses')
        order=tk.StringVar(value='Security status')
        for variable,choices,w in [
            (fam, ['All families','Modern','Historical','Experimental','Post-quantum'],17),
            (security,['All statuses','Recommended','Special requirements','Broken','Research'],19),
            (order,['Security status','Alphabetical','Category','Year / oldest','Year / newest'],18)]:
            box=ttk.Combobox(combos,textvariable=variable,values=choices,state='readonly',width=w)
            box.pack(side='left', fill='x', expand=True, padx=(0,3))
        cols=('name','status')
        tree=ttk.Treeview(block,columns=cols,show='headings',height=9,selectmode='browse')
        tree.heading('name',text='METHOD')
        tree.heading('status',text='STATUS')
        tree.column('name',width=230,minwidth=145,stretch=True)
        tree.column('status',width=125,minwidth=100,stretch=False)
        sb=ttk.Scrollbar(block, orient='vertical',command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side='left',fill='both',expand=True)
        sb.pack(side='left',fill='y')
        def refresh(*_):
            remembered=tree.selection()[0] if tree.selection() else None
            tree.delete(*tree.get_children())
            for m in self._filtered(q.get(),fam.get(),security.get(),order.get()):
                tree.insert('','end',iid=m.code,values=(m.name,'Available' if m.implemented else 'Planned'))
            if remembered in tree.get_children():
                tree.selection_set(remembered)
        q.trace_add('write',refresh)
        fam.trace_add('write',refresh)
        security.trace_add('write',refresh)
        order.trace_add('write',refresh)
        refresh()
        return tree

    def _build_encrypt(self):
        wrapper=ttk.Frame(self.enc_tab)
        wrapper.pack(fill='both',expand=True,padx=12,pady=16)
        left=ttk.Frame(wrapper,width=400)
        left.pack(side='left', fill='both', expand=True,padx=(0,12))
        right=ttk.Frame(wrapper,width=530)
        right.pack(side='left',fill='both',expand=True,padx=(12,0))
        ttk.Label(left,text='1  CHOOSE AN ENCRYPTION METHOD',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,9))
        self.enc_tree=self._create_method_tree(left)
        self.enc_tree.bind('<<TreeviewSelect>>',self._select_method)
        self.enc_tree.selection_set('aes256')
        self.enc_tree.see('aes256')
        self.selected_desc=tk.StringVar(value='AES-256-GCM  •  Modern authenticated encryption')
        self.desc_label=ttk.Label(left,textvariable=self.selected_desc,style='Muted.TLabel',wraplength=350)
        self.desc_label.pack(anchor='w',pady=(8,4))
        ttk.Label(right,text='2  SELECT INPUTS & DESTINATION',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,9))
        listframe=ttk.Frame(right)
        listframe.pack(fill='x')
        self.file_list=tk.Listbox(listframe,height=4,selectmode='extended',background=PANEL,foreground=TEXT,
                                  selectbackground='#23588d',font=('Segoe UI',10),relief='flat',borderwidth=0)
        self.file_list.pack(fill='x',expand=True)
        brow=ttk.Frame(right)
        brow.pack(fill='x',pady=(6,13))
        ttk.Button(brow,text='Add files…',command=self._add_files).pack(side='left',padx=(0,6))
        ttk.Button(brow,text='Add folder…',command=self._add_folder).pack(side='left',padx=(0,6))
        ttk.Button(brow,text='Remove',command=self._remove_file).pack(side='left')
        self._register_drop(self.file_list, self._on_drop_encrypt)
        self.output=tk.StringVar()
        ttk.Label(right,text='Encrypted output file',style='Muted.TLabel').pack(anchor='w')
        orow=ttk.Frame(right); orow.pack(fill='x',pady=(4,10))
        ttk.Entry(orow,textvariable=self.output).pack(side='left',expand=True,fill='x',padx=(0,6))
        ttk.Button(orow,text='Browse…',command=self._pick_output).pack(side='right')
        formats=ttk.Frame(right); formats.pack(fill='x',pady=(0,10))
        ttk.Label(formats,text='File extension:',style='Muted.TLabel').pack(side='left')
        self.extension=tk.StringVar(value='Unified .cwbox')
        ext=ttk.Combobox(formats,textvariable=self.extension,values=['Unified .cwbox','Keep original extension','Custom'],state='readonly',width=23)
        ext.pack(side='left',padx=8)
        ext.bind('<<ComboboxSelected>>',lambda _:self._derive_output())
        self.custom_extension=tk.StringVar(value='.encrypted')
        ttk.Entry(formats,textvariable=self.custom_extension,width=14).pack(side='left')
        comp_row=ttk.Frame(right);comp_row.pack(fill='x',pady=(0,12))
        ttk.Label(comp_row,text='Compression:',style='Muted.TLabel').pack(side='left')
        self.comp=tk.StringVar(value='zlib')
        ttk.Combobox(comp_row,textvariable=self.comp,values=['zlib','auto','lzma','bz2','none','zstd'],state='readonly',width=15).pack(side='left',padx=8)
        ttk.Label(comp_row,text='Compresses BEFORE encryption',style='Muted.TLabel').pack(side='left')
        ttk.Label(right,text='3  METHOD SETTINGS',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,8))
        self.key_frame=ttk.Frame(right)
        self.key_frame.pack(fill='x')
        self.enc_password=tk.StringVar()
        self.enc_confirm=tk.StringVar()
        self.enc_key=tk.StringVar()
        self.pad_path=tk.StringVar()
        self.generate_pad=tk.BooleanVar(value=True)
        self._show_key_fields()
        ttk.Label(right,text='Modern ciphers are authenticated. Historical ciphers are intentionally insecure.',
                  style='Muted.TLabel',wraplength=500).pack(anchor='w',pady=(7,9))
        self.enc_btn=ttk.Button(right,text='Encrypt selected files  →',style='Accent.TButton',command=self._start_encrypt)
        self.enc_btn.pack(fill='x')

    def _select_method(self, _=None):
        sel=self.enc_tree.selection()
        if not sel:return
        self.method_code=sel[0]
        method=METHOD_BY_CODE[self.method_code]
        self.selected_desc.set(f'{method.name}  •  {method.security}  •  {method.summary}')
        self._show_key_fields()

    def _show_key_fields(self):
        if not hasattr(self,'key_frame'):return
        for child in self.key_frame.winfo_children():child.destroy()
        code=self.method_code
        if code in MODERN:
            row=ttk.Frame(self.key_frame);row.pack(fill='x',pady=(0,7))
            ttk.Label(row,text='Password',width=18).pack(side='left')
            ttk.Entry(row,textvariable=self.enc_password,show='•').pack(side='left',fill='x',expand=True)
            row2=ttk.Frame(self.key_frame);row2.pack(fill='x')
            ttk.Label(row2,text='Confirm password',width=18).pack(side='left')
            ttk.Entry(row2,textvariable=self.enc_confirm,show='•').pack(side='left',fill='x',expand=True)
        elif code=='otp':
            row=ttk.Frame(self.key_frame);row.pack(fill='x')
            ttk.Entry(row,textvariable=self.pad_path).pack(side='left',fill='x',expand=True,padx=(0,5))
            ttk.Button(row,text='Pad file…',command=self._select_pad_enc).pack(side='left')
            ttk.Checkbutton(self.key_frame,text='Generate new random pad (never reuse)',variable=self.generate_pad).pack(anchor='w',pady=(8,2))
            ttk.Label(self.key_frame,text='Store the pad separately from ciphertext. Losing it means losing the data.',
                      foreground=ORANGE,wraplength=470).pack(anchor='w')
        elif code in HISTORICAL:
            ttk.Label(self.key_frame,text='Historical key: Caesar 0–255 · Affine a,b · Rail fence 2–20 · Vigenère text',
                      style='Muted.TLabel',wraplength=470).pack(anchor='w',pady=(0,4))
            ttk.Entry(self.key_frame,textvariable=self.enc_key).pack(fill='x')
        else:
            ttk.Label(self.key_frame,text='Planned, not available in this release.',foreground=ORANGE).pack(anchor='w')

    def _add_files(self):
        files=filedialog.askopenfilenames(title='Add files')
        self._add_input_paths(files)

    def _add_folder(self):
        folder=filedialog.askdirectory(title='Add folder')
        if folder:self._add_input_paths([folder])

    def _add_input_paths(self,paths):
        for p in paths:
            path=str(Path(p).expanduser().resolve())
            if os.path.exists(path) and path not in self.inputs:
                self.inputs.append(path)
                self.file_list.insert(tk.END,path)
        self._derive_output()

    def _remove_file(self):
        for i in reversed(self.file_list.curselection()):
            self.file_list.delete(i)
            self.inputs.pop(i)
        self._derive_output()

    def _derive_output(self):
        if not self.inputs:return
        first=Path(self.inputs[0])
        stem=first.name
        ext_choice=self.extension.get()
        ext='.cwbox' if ext_choice=='Unified .cwbox' else (first.suffix or '.bin') if ext_choice=='Keep original extension' else ('.'+self.custom_extension.get().lstrip('.'))
        self.output.set(str(first.parent / (stem+ext)))

    def _pick_output(self):
        result=filedialog.asksaveasfilename(title='Save encrypted container',initialfile=Path(self.output.get()).name if self.output.get() else 'encrypted.cwbox',defaultextension='.cwbox')
        if result:self.output.set(result)

    def _select_pad_enc(self):
        if self.generate_pad.get():
            path=filedialog.asksaveasfilename(title='Save NEW secret pad (separate location)',defaultextension='.otpkey')
        else:
            path=filedialog.askopenfilename(title='Choose existing UNUSED pad')
        if path:self.pad_path.set(path)

    def _register_drop(self,widget,handler):
        if DND_FILES and hasattr(widget,'drop_target_register'):
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind('<<Drop>>',lambda e:handler(self.root.tk.splitlist(e.data)))

    def _on_drop_encrypt(self,files):
        self._add_input_paths(files)

    def _build_decrypt(self):
        outer=ttk.Frame(self.dec_tab)
        outer.pack(fill='both',expand=True,padx=32,pady=12)
        ttk.Label(outer,text='RESTORE ENCRYPTED FILES',font=('Segoe UI Semibold',17)).pack(anchor='w',pady=(0,5))
        ttk.Label(outer,text='Choose a .cwbox container (or custom extension); the method is detected automatically.',style='Muted.TLabel').pack(anchor='w',pady=(0,8))
        ttk.Label(outer,text='1  ENCRYPTED FILE',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,8))
        self.dec_source=tk.StringVar()
        r=ttk.Frame(outer);r.pack(fill='x',pady=(0,8))
        inp=ttk.Entry(r,textvariable=self.dec_source)
        inp.pack(side='left',fill='x',expand=True,padx=(0,8))
        ttk.Button(r,text='Browse…',command=self._pick_decrypt).pack(side='left')
        ttk.Button(r,text='Inspect',command=self._inspect).pack(side='left',padx=(8,0))
        self._register_drop(inp,lambda fs:self._on_drop_decrypt(fs))
        self.detected=tk.StringVar(value='No container inspected yet.')
        ttk.Label(outer,textvariable=self.detected,style='Muted.TLabel',wraplength=850).pack(anchor='w',pady=(0,8))
        ttk.Label(outer,text='2  CREDENTIALS',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,6))
        self.dec_password=tk.StringVar()
        self.dec_key=tk.StringVar()
        self.dec_pad=tk.StringVar()
        creds=ttk.Frame(outer);creds.pack(fill='x',pady=(0,8))
        self._dec_credential_frame=creds
        self._credential_input('Password (modern ciphers)',self.dec_password,True)
        self._credential_input('Historical key',self.dec_key,False)
        self._credential_input('OTP pad path',self.dec_pad,False,browse=True)
        ttk.Label(outer,text='3  RESTORE DESTINATION',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(4,6))
        self.dec_target=tk.StringVar(value=str(Path.home()/'Downloads'))
        r=ttk.Frame(outer);r.pack(fill='x',pady=(0,6))
        ttk.Entry(r,textvariable=self.dec_target).pack(side='left',fill='x',expand=True,padx=(0,8))
        ttk.Button(r,text='Choose folder…',command=self._choose_dec_folder).pack(side='left')
        ttk.Label(outer,text='Restored files never overwrite existing names. All authenticated data is checked before publication.',
                  foreground=MUTED,wraplength=850).pack(anchor='w',pady=(0,6))
        self.dec_btn=ttk.Button(outer,text='Authenticate & decrypt  →',style='Accent.TButton',command=self._start_decrypt)
        self.dec_btn.pack(anchor='w',fill='x',ipady=2)

    def _credential_input(self,label,variable,secret,browse=False):
        r=ttk.Frame(self._dec_credential_frame)
        r.pack(fill='x',pady=2)
        ttk.Label(r,text=label,width=28).pack(side='left')
        ttk.Entry(r,textvariable=variable,show='•' if secret else '').pack(side='left',fill='x',expand=True,padx=(0,7))
        if browse:
            ttk.Button(r,text='Pad file…',command=self._pick_dec_pad).pack(side='left')

    def _pick_decrypt(self):
        p=filedialog.askopenfilename(title='Open encrypted container')
        if p:
            self.dec_source.set(p)
            self._inspect()

    def _on_drop_decrypt(self,files):
        if files:
            self.dec_source.set(files[0]);self._inspect()

    def _choose_dec_folder(self):
        p=filedialog.askdirectory(title='Restore into folder')
        if p:self.dec_target.set(p)

    def _pick_dec_pad(self):
        p=filedialog.askopenfilename(title='Choose OTP pad')
        if p:self.dec_pad.set(p)

    def _inspect(self):
        try:
            h=inspect_file(self.dec_source.get())
            m=METHOD_BY_CODE[h['method']]
            self.detected.set(f'Detected: {m.name}  |  Compression: {h["compression"]}  |  Encrypted payload: {_display_size(h["packed_size"])}  |  Security: {m.security}')
            self._update_status('Container recognized. Enter the appropriate credentials.')
        except Exception as exc:
            self.detected.set(f'Not recognized: {exc}')

    def _build_library(self):
        outer=ttk.Frame(self.lib_tab);outer.pack(fill='both',expand=True,padx=12,pady=16)
        left=ttk.Frame(outer,width=405)
        left.pack(side='left',fill='both',expand=True,padx=(0,12))
        right=ttk.Frame(outer,width=540)
        right.pack(side='left',fill='both',expand=True,padx=(12,0))
        ttk.Label(left,text='EXPLORE THE CRYPTOGRAPHY CATALOG',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,8))
        self.lib_tree=self._create_method_tree(left,True)
        self.lib_tree.bind('<<TreeviewSelect>>',self._lib_selection)
        self.lib_tree.selection_set('aes256')
        ttk.Label(right,text='METHOD DETAILS & MATHEMATICS',font=('Segoe UI Semibold',11)).pack(anchor='w',pady=(0,8))
        textframe=ttk.Frame(right);textframe.pack(fill='both',expand=True)
        self.lib_details=tk.Text(textframe,bg=PANEL,fg=TEXT,insertbackground=TEXT,relief='flat',wrap='word',padx=17,pady=14,
                                 font=('Segoe UI',10),spacing2=4,spacing3=7)
        self.lib_details.pack(side='left',expand=True,fill='both')
        scroll=ttk.Scrollbar(textframe,orient='vertical',command=self.lib_details.yview)
        scroll.pack(side='right',fill='y')
        self.lib_details.configure(yscrollcommand=scroll.set)
        self.lib_details.tag_configure('heading',foreground=ACCENT,font=('Segoe UI Semibold',16),spacing3=12)
        self.lib_details.tag_configure('section',foreground=ACCENT,font=('Segoe UI Semibold',11),spacing1=12,spacing3=5)
        self.lib_details.tag_configure('subtle',foreground=MUTED)
        self._lib_selection()

    def _lib_selection(self,_=None):
        selected=self.lib_tree.selection()
        if not selected:return
        m=METHOD_BY_CODE[selected[0]]
        box=self.lib_details
        box.configure(state='normal')
        box.delete('1.0',tk.END)
        box.insert(tk.END,m.name+'\n','heading')
        box.insert(tk.END,f'{m.family}   •   {m.year}   •   {m.security}   •   {"IMPLEMENTED" if m.implemented else "PLANNED"}\n','subtle')
        for title,value in [('Overview',m.summary),('Mathematics / construction',m.mathematics),('Advantages',m.pros),('Disadvantages & security limitations',m.cons),('Key material',m.key),('Performance category (qualitative only)',m.speed)]:
            box.insert(tk.END,'\n'+title+'\n','section')
            box.insert(tk.END,value+'\n')
        if not m.implemented:
            box.insert(tk.END,'\nNot available for encryption in this release.\n','subtle')
        box.configure(state='disabled')

    def _update_status(self,text):
        self.status.config(text=text)

    def _begin_worker(self,func,success):
        if self.active:return
        self.active=True
        self.cancel_flag.clear()
        self.enc_btn.configure(state='disabled')
        self.dec_btn.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress.configure(value=0)
        def report(stage,value):
            self.messages.put(('progress',stage,value))
        def run():
            try:
                result=func(report,self.cancel_flag.is_set)
                self.messages.put(('ok',success(result)))
            except InterruptedError:
                self.messages.put(('cancelled','Cancelled. No incomplete output was published.'))
            except Exception as exc:
                self.messages.put(('error',str(exc)))
        threading.Thread(target=run,daemon=True).start()

    def _poll(self):
        try:
            while True:
                msg=self.messages.get_nowait()
                if msg[0]=='progress':
                    self._update_status(msg[1]+f'  •  {msg[2]*100:.0f}%')
                    self.progress.configure(value=msg[2]*100)
                else:
                    self.active=False
                    self.enc_btn.configure(state='normal')
                    self.dec_btn.configure(state='normal')
                    self.stop_button.configure(state='disabled')
                    if msg[0]=='ok':
                        self.progress.configure(value=100)
                        self._update_status('Operation completed.')
                        messagebox.showinfo('Success',msg[1],parent=self.root)
                    elif msg[0]=='cancelled':
                        self._update_status(msg[1])
                    else:
                        self._update_status('Operation failed: '+msg[1])
                        messagebox.showerror('Operation failed',msg[1],parent=self.root)
        except queue.Empty:
            pass
        self.root.after(90,self._poll)

    def _start_encrypt(self):
        try:
            if not self.inputs:raise ValueError('Choose at least one input file or folder.')
            if not self.output.get().strip():raise ValueError('Choose the encrypted output path.')
            method=METHOD_BY_CODE[self.method_code]
            if not method.implemented:raise ValueError('This method is planned and not implemented.')
            if self.method_code in MODERN:
                if self.enc_password.get()!=self.enc_confirm.get():
                    raise ValueError('The two passwords do not match.')
            if self.method_code not in MODERN and not messagebox.askyesno('Research / education only',
                    'This method is NOT recommended for protecting sensitive information. Continue?',parent=self.root):
                return
            options=Options(method=self.method_code,compression=self.comp.get(),password=self.enc_password.get(),
                            key=self.enc_key.get(),pad_path=self.pad_path.get(),generate_pad=self.generate_pad.get())
            paths=list(self.inputs)
            target=self.output.get()
            self._begin_worker(lambda report,cancelled:encrypt(paths,target,options,report,cancelled),
                               lambda result:'Encrypted file saved:\n'+result['output'] +
                               ('\n\nSecret pad saved separately:\n'+result['pad'] if result['pad'] else '')+
                               f'\n\nPacked: {_display_size(result["compressed_bytes"])}; final: {_display_size(result["output_bytes"])}')
        except Exception as exc:
            messagebox.showwarning('Check encryption settings',str(exc),parent=self.root)

    def _start_decrypt(self):
        try:
            source=self.dec_source.get().strip()
            if not source:raise ValueError('Choose an encrypted file.')
            method=inspect_file(source)['method']
            if method not in MODERN and not messagebox.askyesno('Historical / OTP handling',
                    'This file does not use modern authenticated password encryption. Continue?',parent=self.root):
                return
            dest=self.dec_target.get()
            password,key,pad=self.dec_password.get(),self.dec_key.get(),self.dec_pad.get()
            self._begin_worker(lambda report,cancelled:decrypt(source,dest,password=password,key=key,pad_path=pad,progress=report,cancelled=cancelled),
                               lambda result:'Restored successfully to:\n'+'\n'.join(result['outputs']))
        except Exception as exc:
            messagebox.showwarning('Check decryption settings',str(exc),parent=self.root)

    def run(self):
        self.root.mainloop()


def main():
    CipherApp().run()

if __name__ == '__main__':
    main()

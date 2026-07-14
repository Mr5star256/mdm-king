#!/usr/bin/env python3
"""
MDM KING — Admin Panel v3 (Modern UI)
Synchronised with mdm_king.py via config.json + license_data/
"""
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json, os, sys, datetime, threading, urllib.request, base64, uuid, hashlib
from cloudflare import CLOUDFLARE_API_URL, fetch_config, update_config

try:
    import ctypes
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except: pass

HERE = os.path.dirname(os.path.dirname(sys.executable)) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
CFG_PATH = os.path.join(HERE, 'config.json')
LICENSE_DATA = os.path.join(HERE, 'license_data')
LICENSES_PATH = os.path.join(LICENSE_DATA, 'licenses.json')
BLOCKLIST_PATH = os.path.join(LICENSE_DATA, 'blocklist.json')
PRIV_PATH = os.path.join(LICENSE_DATA, 'private.pem')
PUB_PATH = os.path.join(LICENSE_DATA, 'public.pem')

def _load_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
            if path.endswith('licenses.json') and not isinstance(data, dict):
                return {}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {} if 'licenses' in path else []
    except Exception:
        return {} if 'licenses' in path else []

def _save_json(path, data):
    with open(path, 'w', encoding='utf-8') as f: json.dump(data, f, indent=2)

def load_cfg():
    try:
        with open(CFG_PATH, encoding='utf-8') as f: return json.load(f)
    except: return {}

_sync_lock = threading.Lock()

def save_cfg(cfg):
    try:
        with open(CFG_PATH, 'w', encoding='utf-8') as f: json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f'save_cfg error: {e}')

def sync_download():
    if not _sync_lock.acquire(blocking=False):
        print('Sync already in progress')
        return False
    try:
        remote = fetch_config()
        if not remote:
            return False
        local = load_cfg()
        deleted = set(local.get('deleted_users', []))
        for u, d in remote.get('users', {}).items():
            if u in deleted: continue
            local.setdefault('users', {})
            if u not in local['users']:
                local['users'][u] = d
            else:
                for k, v in d.items():
                    if k not in ('password',):
                        local['users'][u][k] = v
        for key in ('admin', 'blocklist', 'features', 'options', 'smtp'):
            if key in remote:
                local[key] = remote[key]
        save_cfg(local)
        return True
    except Exception as e:
        import traceback
        print(f'Sync download failed: {e}')
        traceback.print_exc()
        return False
    finally:
        _sync_lock.release()

def sync_upload():
    if not _sync_lock.acquire(blocking=False):
        print('Sync upload already in progress')
        return False
    try:
        cfg = load_cfg()
        ok = update_config(cfg)
        return ok is not None
    except Exception as e:
        print(f'Sync upload failed: {e}')
        return False
    finally:
        _sync_lock.release()

# ── Cyberpunk Neon Theme ──
BG = '#0d001a'
SURFACE = '#1a0033'
CARD = '#150030'
DARK = '#060010'
BORDER = '#3a006a'
FG = '#e0e0ff'
MUTED = '#6a4a8a'
ACCENT = '#00ffff'
ACCENT2 = '#ff00ff'
GREEN = '#00ff88'
RED = '#ff004d'
ORANGE = '#ff6600'
CYAN = '#00ccff'
PINK = '#ff0088'
YELLOW = '#ffcc00'
TAB_INACTIVE = '#1a0033'

DURATIONS = {
    'Rent (4 hours)': ('rent', 4/24),
    '3 Months': ('month3', 90),
    '6 Months': ('month6', 180),
    '12 Months': ('month12', 365),
}

class AdminPanel:
    def __init__(self, root):
        self.root = root
        root.title('MDM KING — Admin Panel')
        root.configure(bg=BG)
        sw = root.winfo_screenwidth(); sh = root.winfo_screenheight()
        root.geometry(f'1050x680+{(sw-1050)//2}+{(sh-680)//2}')
        root.minsize(900, 580)
        try:
            ico = os.path.join(HERE, 'tools', 'mdm_king_logo_circular.ico')
            if os.path.isfile(ico): root.iconbitmap(ico)
            png32 = os.path.join(HERE, 'tools', 'mdm_king_logo_circular_32.png')
            if os.path.isfile(png32):
                try:
                    from PIL import ImageTk
                    root._taskbar_icon = ImageTk.PhotoImage(file=png32)
                    root.iconphoto(True, root._taskbar_icon)
                except:
                    root._taskbar_icon = tk.PhotoImage(file=png32)
                    root.iconphoto(True, root._taskbar_icon)
        except: pass

        self._current_tab = 0
        self._tab_frames = []
        self._tab_btns = []
        self._selected_user = ''
        self._selected_lic_id = ''
        self._selected_lic = ''

        # ── Header ──
        header = tk.Frame(root, bg=DARK, height=52)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text='MDM KING', font=('Segoe UI', 14, 'bold'),
                 fg=ACCENT, bg=DARK).pack(side=tk.LEFT, padx=20, pady=10)
        self._sync_indicator = tk.Label(header, text='●', font=('Segoe UI', 8),
                                        fg=GREEN, bg=DARK)
        self._sync_indicator.pack(side=tk.RIGHT, padx=(0, 10), pady=10)
        tk.Label(header, text='Gist Sync Active', font=('Segoe UI', 8),
                 fg=MUTED, bg=DARK).pack(side=tk.RIGHT, padx=(0, 2), pady=10)

        # ── Tab bar ──
        tab_bar = tk.Frame(root, bg=BG, height=42)
        tab_bar.pack(fill=tk.X)
        tab_bar.pack_propagate(False)
        self._tab_bar = tab_bar

        tab_labels = ['Users', 'Licenses', 'Blocklist', 'Sync & Settings']
        tab_icons = ['👥', '🔑', '🚫', '⚙️']
        for i, (label, icon) in enumerate(zip(tab_labels, tab_icons)):
            btn = tk.Label(tab_bar, text=f'  {icon}  {label}  ',
                           font=('Segoe UI', 10),
                           bg=ACCENT if i == 0 else TAB_INACTIVE,
                           fg='#1e1e2e' if i == 0 else MUTED,
                           padx=16, pady=6, cursor='hand2')
            btn.pack(side=tk.LEFT, padx=(0, 3), pady=5)
            btn.bind('<Button-1>', lambda e, idx=i: self._switch_tab(idx))
            btn.bind('<Enter>', lambda e, b=btn, i=i: self._tab_hover(b, i))
            btn.bind('<Leave>', lambda e, b=btn, i=i: self._tab_leave(b, i))
            self._tab_btns.append(btn)

        # ── Main content area ──
        self._content = tk.Frame(root, bg=BG)
        self._content.pack(fill=tk.BOTH, expand=True, padx=14, pady=(6, 10))

        self._build_users_tab()
        self._build_licenses_tab()
        self._build_blocklist_tab()
        self._build_sync_tab()

        # ── Footer status bar ──
        footer = tk.Frame(root, bg=DARK, height=26)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        self.footer_text = tk.Label(footer, text='Ready', font=('Segoe UI', 8),
                                    fg=MUTED, bg=DARK)
        self.footer_text.pack(side=tk.LEFT, padx=14, pady=2)
        self.footer_right = tk.Label(footer, text='', font=('Segoe UI', 8),
                                     fg=MUTED, bg=DARK)
        self.footer_right.pack(side=tk.RIGHT, padx=14, pady=2)

        self._switch_tab(0)
        threading.Thread(target=self._sync_down, daemon=True).start()

    # ── Tab system ──
    def _switch_tab(self, idx):
        for i, f in enumerate(self._tab_frames):
            f.pack_forget() if f else None
        self._tab_frames[idx].pack(fill=tk.BOTH, expand=True)
        for i, btn in enumerate(self._tab_btns):
            btn.configure(bg=ACCENT if i == idx else TAB_INACTIVE,
                          fg='#1e1e2e' if i == idx else MUTED)
        self._current_tab = idx
        if idx == 0: self.refresh_users()
        elif idx == 1: self.refresh_licenses()
        elif idx == 2: self.refresh_blocklist()

    def _tab_hover(self, btn, idx):
        if idx != self._current_tab:
            btn.configure(bg=SURFACE, fg=ACCENT)

    def _tab_leave(self, btn, idx):
        if idx != self._current_tab:
            btn.configure(bg=TAB_INACTIVE, fg=MUTED)

    # ── Helpers ──
    def _card(self, parent, title=None):
        f = tk.Frame(parent, bg=CARD, bd=0, highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=BORDER)
        f.pack(fill=tk.BOTH, expand=True, pady=(4, 6))
        if title:
            hdr = tk.Frame(f, bg=CARD)
            hdr.pack(fill=tk.X, padx=16, pady=(12, 4))
            tk.Label(hdr, text=title, font=('Segoe UI', 12, 'bold'),
                     fg=ACCENT, bg=CARD).pack(side=tk.LEFT)
            sep = tk.Frame(f, bg=BORDER, height=1)
            sep.pack(fill=tk.X, padx=16, pady=(2, 0))
        inner = tk.Frame(f, bg=CARD)
        inner.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)
        return inner, f

    def _section(self, parent, title):
        f = tk.Frame(parent, bg=CARD, bd=0, highlightthickness=1,
                     highlightbackground=BORDER, highlightcolor=BORDER)
        f.pack(fill=tk.X, pady=3)
        hdr = tk.Frame(f, bg=CARD)
        hdr.pack(fill=tk.X, padx=12, pady=(6, 2))
        tk.Label(hdr, text=title, font=('Segoe UI', 9, 'bold'),
                 fg=ACCENT2, bg=CARD).pack(side=tk.LEFT)
        inner = tk.Frame(f, bg=CARD)
        inner.pack(fill=tk.X, padx=12, pady=(0, 8))
        return inner

    def _tree(self, parent, cols, height=14):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Modern.Treeview', background=CARD, foreground=FG,
                        fieldbackground=CARD, rowheight=32, borderwidth=0,
                        font=('Segoe UI', 9))
        style.map('Modern.Treeview', background=[('selected', ACCENT)],
                  foreground=[('selected', '#1e1e2e')])
        style.configure('Modern.Treeview.Heading', background=SURFACE, foreground=ACCENT,
                        font=('Segoe UI', 9, 'bold'), borderwidth=0)
        style.map('Modern.Treeview.Heading', background=[('active', '#1a1a40')])
        style.layout('Modern.Treeview', [('Modern.Treeview.treearea', {'sticky': 'nswe'})])
        style.configure('Vertical.TScrollbar', background=SURFACE, troughcolor=BG,
                        bordercolor=SURFACE, arrowcolor=ACCENT)

        tree = ttk.Treeview(parent, columns=cols, show='headings', height=height,
                            selectmode='browse', style='Modern.Treeview')
        for c in cols:
            tree.heading(c, text=c.replace('_', ' ').title())
            tree.column(c, width=120, anchor='center')
        vsb = ttk.Scrollbar(parent, orient='vertical', command=tree.yview,
                           style='Vertical.TScrollbar')
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        return tree

    def _btn(self, parent, text, cmd, color=ACCENT, width=None):
        bg_color = color
        fg_color = '#1e1e2e'
        for c in [RED, ORANGE, PINK]:
            if color == c: fg_color = FG; break
        btn = tk.Button(parent, text=text, font=('Segoe UI', 9, 'bold'),
                        bg=bg_color, fg=fg_color, bd=0, padx=16, pady=6,
                        cursor='hand2', command=cmd, relief='flat',
                        activebackground=bg_color, activeforeground=fg_color)
        if width: btn.config(width=width)
        btn.pack(side=tk.LEFT, padx=4)
        hover_map = {ACCENT: '#7c6ff0', GREEN: '#40e06a', RED: '#e04444',
                     ORANGE: '#e0a060', CYAN: '#70d0c0', YELLOW: '#e0d080',
                     SURFACE: '#1a1a40'}
        hv = hover_map.get(color, '#3a3a5a')
        btn.bind('<Enter>', lambda e, b=btn, h=hv: b.configure(bg=h))
        btn.bind('<Leave>', lambda e, b=btn, c=color: b.configure(bg=c))
        return btn

    def _small_btn(self, parent, text, cmd, color=ACCENT):
        bg_color = color
        fg_color = '#1e1e2e'
        for c in [RED, ORANGE, PINK]:
            if color == c: fg_color = FG; break
        btn = tk.Button(parent, text=text, font=('Segoe UI', 8, 'bold'),
                        bg=bg_color, fg=fg_color, bd=0, padx=10, pady=3,
                        cursor='hand2', command=cmd, relief='flat')
        btn.pack(side=tk.LEFT, padx=2)
        return btn

    def _status(self, parent):
        lbl = tk.Label(parent, text='', font=('Segoe UI', 8), fg=MUTED, bg=BG)
        lbl.pack(pady=2)
        return lbl

    # ═══════════════ TAB 1: USERS ═══════════════
    def _build_users_tab(self):
        f = tk.Frame(self._content, bg=BG)
        self._tab_frames.append(f)

        inner, card = self._card(f, 'Registered Users')
        self.users_tree = self._tree(inner, ['Email', 'Status', 'HWID', 'License', 'Expires', 'Lic_ID'], height=14)
        self.users_tree.column('Email', width=200)
        self.users_tree.column('Status', width=80)
        self.users_tree.column('HWID', width=140)
        self.users_tree.column('License', width=80)
        self.users_tree.column('Expires', width=150)
        self.users_tree.column('Lic_ID', width=120)
        self.users_tree.bind('<<TreeviewSelect>>', self._on_user_select)

        btnf = tk.Frame(f, bg=BG)
        btnf.pack(pady=4)
        self._btn(btnf, 'Add User', self._add_user, ACCENT, 14)
        self._btn(btnf, 'View Details', self._view_user, CYAN, 14)
        self._btn(btnf, 'Activate + License', self._activate_user, GREEN, 18)
        self._btn(btnf, 'Deactivate', self._deactivate_user, ORANGE)
        self._btn(btnf, 'Block User', self._block_user, RED)
        self._btn(btnf, 'Copy Lic Key', self._copy_lic_key, YELLOW)
        self._btn(btnf, 'Delete', self._delete_user, RED)
        self._btn(btnf, 'Refresh', self.refresh_users, SURFACE)
        self.user_status = self._status(f)

    def _on_user_select(self, e):
        sel = self.users_tree.selection()
        self._selected_user = ''
        self._selected_lic_id = ''
        if sel:
            vals = self.users_tree.item(sel[0], 'values')
            if vals:
                self._selected_user = vals[0]
                self._selected_lic_id = vals[5] if len(vals) > 5 else ''

    def _view_user(self):
        email = getattr(self, '_selected_user', '')
        if not email:
            messagebox.showwarning('No User', 'Select a user first'); return
        cfg = load_cfg()
        data = cfg.get('users', {}).get(email, {})
        if not isinstance(data, dict):
            messagebox.showwarning('No Data', 'No user data found'); return
        win = tk.Toplevel(self.root)
        win.withdraw()
        win.title(f'User: {email}')
        win.configure(bg=BG)
        try:
            ico = os.path.join(HERE, 'tools', 'mdm_king_logo_circular.ico')
            if os.path.isfile(ico): win.iconbitmap(ico)
        except: pass
        self.root.update_idletasks()
        px, py, pw, ph = self.root.winfo_x(), self.root.winfo_y(), self.root.winfo_width(), self.root.winfo_height()
        win.geometry(f'420x380+{px + pw//2 - 210}+{py + ph//2 - 190}')
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        tk.Label(win, text='User Details', font=('Segoe UI', 13, 'bold'),
                 fg=ACCENT, bg=BG).pack(pady=(16, 10))

        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        blocked_ids = [b.get('lic_id', '') for b in blocklist if isinstance(b, dict)]
        blocked_hwids = [b.get('hwid', '') for b in blocklist if isinstance(b, dict)]
        mid = data.get('machine_id', '') or ''
        lid = data.get('license_id', '') or ''
        if mid in blocked_hwids or lid in blocked_ids:
            status = 'BLOCKED'
            status_color = RED
        elif data.get('activated', False):
            status = 'ACTIVE'
            status_color = GREEN
        else:
            status = 'PENDING'
            status_color = ORANGE

        fields = [
            ('Email', email, FG),
            ('Status', status, status_color),
            ('Machine ID', mid, FG),
            ('HWID', data.get('hwid', '—'), FG),
            ('License Type', data.get('license_type', '—'), FG),
            ('License ID', lid, FG),
            ('Expiry', data.get('expiry', '—'), FG),
            ('Created', data.get('created', '—'), MUTED),
        ]
        for label, val, color in fields:
            row = tk.Frame(win, bg=BG)
            row.pack(fill=tk.X, padx=30, pady=2)
            tk.Label(row, text=label + ':', font=('Segoe UI', 9, 'bold'),
                     fg=MUTED, bg=BG, width=14, anchor='w').pack(side=tk.LEFT)
            tk.Label(row, text=val or '—', font=('Segoe UI', 9),
                     fg=color, bg=BG, anchor='w').pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(win, text='Close', font=('Segoe UI', 9),
                  bg=SURFACE, fg=FG, bd=0, padx=24, pady=5, cursor='hand2',
                  command=win.destroy).pack(pady=14)
        win.deiconify()

    def _add_user(self):
        win = tk.Toplevel(self.root)
        win.withdraw()
        win.title('Add User')
        win.configure(bg=BG)
        try:
            ico = os.path.join(HERE, 'tools', 'mdm_king_logo_circular.ico')
            if os.path.isfile(ico): win.iconbitmap(ico)
        except: pass
        self.root.update_idletasks()
        px, py, pw, ph = self.root.winfo_x(), self.root.winfo_y(), self.root.winfo_width(), self.root.winfo_height()
        win.geometry(f'380x240+{px + pw//2 - 190}+{py + ph//2 - 120}')
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        win.deiconify()
        tk.Label(win, text='Add New User', font=('Segoe UI', 13, 'bold'),
                 fg=ACCENT, bg=BG).pack(pady=(18, 12))

        f1 = tk.Frame(win, bg=BG)
        f1.pack(pady=4)
        tk.Label(f1, text='Email:', font=('Segoe UI', 10), fg=FG, bg=BG, width=8, anchor='w').pack(side=tk.LEFT)
        email_entry = tk.Entry(f1, font=('Segoe UI', 10), bg=SURFACE, fg=FG, bd=0,
                               highlightthickness=1, highlightcolor=ACCENT,
                               highlightbackground=BORDER, insertbackground=FG, relief='flat', width=28)
        email_entry.pack(side=tk.LEFT, padx=4)

        f2 = tk.Frame(win, bg=BG)
        f2.pack(pady=4)
        tk.Label(f2, text='Password:', font=('Segoe UI', 10), fg=FG, bg=BG, width=8, anchor='w').pack(side=tk.LEFT)
        pass_entry = tk.Entry(f2, font=('Segoe UI', 10), bg=SURFACE, fg=FG, bd=0,
                              highlightthickness=1, highlightcolor=ACCENT,
                              highlightbackground=BORDER, insertbackground=FG, relief='flat',
                              show='*', width=28)
        pass_entry.pack(side=tk.LEFT, padx=4)

        def do_add():
            email = email_entry.get().strip()
            pwd = pass_entry.get().strip()
            if not email or not pwd:
                messagebox.showwarning('Missing Fields', 'Enter both email and password'); return
            cfg = load_cfg()
            users = cfg.setdefault('users', {})
            if email in users:
                messagebox.showwarning('Exists', f'User {email} already exists'); return
            users[email] = {
                'password': pwd,
                'activated': False,
                'machine_id': '',
                'created': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            }
            admins = cfg.setdefault('admin', {})
            admins[email] = {
                'password': pwd,
                'is_admin': True,
                'activated': False,
            }
            save_cfg(cfg)
            win.destroy()
            self.refresh_users()

        btnf = tk.Frame(win, bg=BG)
        btnf.pack(pady=16)
        tk.Button(btnf, text='Add User', font=('Segoe UI', 10, 'bold'),
                  bg=GREEN, fg='#1e1e2e', bd=0, padx=20, pady=6, cursor='hand2',
                  command=do_add).pack(side=tk.LEFT, padx=4)
        tk.Button(btnf, text='Cancel', font=('Segoe UI', 9),
                  bg=SURFACE, fg=FG, bd=0, padx=20, pady=6, cursor='hand2',
                  command=win.destroy).pack(side=tk.LEFT, padx=4)

    def _activate_user(self):
        if not getattr(self, '_selected_user', ''):
            messagebox.showwarning('No User', 'Select a user first'); return
        if not os.path.isfile(PRIV_PATH):
            messagebox.showerror('No Keypair', 'Go to Settings tab and generate a keypair first')
            return
        dur_win = tk.Toplevel(self.root)
        dur_win.withdraw()
        dur_win.title('Select License Duration')
        dur_win.configure(bg=BG)
        try:
            ico = os.path.join(HERE, 'tools', 'mdm_king_logo_circular.ico')
            if os.path.isfile(ico): dur_win.iconbitmap(ico)
        except: pass
        self.root.update_idletasks()
        px, py, pw, ph = self.root.winfo_x(), self.root.winfo_y(), self.root.winfo_width(), self.root.winfo_height()
        dur_win.geometry(f'340x300+{px + pw//2 - 170}+{py + ph//2 - 150}')
        dur_win.resizable(False, False)
        dur_win.transient(self.root)
        dur_win.grab_set()
        dur_win.deiconify()
        tk.Label(dur_win, text='Select License Duration', font=('Segoe UI', 13, 'bold'),
                 fg=ACCENT, bg=BG).pack(pady=(18, 10))
        var = tk.StringVar(value='3 Months')
        for label in DURATIONS:
            tk.Radiobutton(dur_win, text=label, variable=var, value=label,
                           font=('Segoe UI', 10), fg=FG, bg=BG,
                           selectcolor=CARD, activebackground=BG,
                           activeforeground=FG, padx=24, pady=3).pack(anchor='w', padx=36)

        def do_activate():
            dur_label = var.get()
            typ_key, days = DURATIONS[dur_label]
            email = self._selected_user
            cfg = load_cfg()
            section = 'admin' if email in cfg.get('admin', {}) else 'users'
            user_data = cfg.get(section, {}).get(email, {})
            if not isinstance(user_data, dict): user_data = {}
            hwid = user_data.get('machine_id', '')
            try:
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import padding
                from cryptography.hazmat.backends import default_backend
            except ImportError:
                messagebox.showerror('Missing Library', 'pip install cryptography')
                return
            os.makedirs(LICENSE_DATA, exist_ok=True)
            with open(PRIV_PATH, 'rb') as f:
                priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            now = datetime.datetime.utcnow()
            expires = now + datetime.timedelta(days=days)
            lic_id = 'LIC-' + uuid.uuid4().hex[:8].upper()
            payload = {
                'lic_id': lic_id, 'hwid': hwid, 'type': typ_key,
                'created': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'expires': expires.strftime('%Y-%m-%dT%H:%M:%SZ'),
            }
            canonical = json.dumps(payload, separators=(',', ':'), sort_keys=True)
            sig = priv.sign(canonical.encode(), padding.PKCS1v15(), hashes.SHA256())
            payload['signature'] = base64.b64encode(sig).decode()
            lic_key = base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()
            licenses = _load_json(LICENSES_PATH)
            licenses[lic_id] = {**payload, 'active': True}
            _save_json(LICENSES_PATH, licenses)
            user_data['activated'] = True
            user_data['license_key'] = lic_key
            user_data['license_id'] = lic_id
            user_data['license_type'] = typ_key
            user_data['expiry'] = expires.strftime('%Y-%m-%dT%H:%M:%SZ')
            cfg[section][email] = user_data
            save_cfg(cfg)
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(lic_key)
            except: pass
            dur_win.destroy()
            self.refresh_users()
            threading.Thread(target=sync_upload, daemon=True).start()

        btnf = tk.Frame(dur_win, bg=BG)
        btnf.pack(pady=14)
        tk.Button(btnf, text='ACTIVATE & GENERATE', font=('Segoe UI', 10, 'bold'),
                  bg=GREEN, fg='#1e1e2e', bd=0, padx=20, pady=6, cursor='hand2',
                  command=do_activate).pack(side=tk.LEFT, padx=4)
        tk.Button(btnf, text='Cancel', font=('Segoe UI', 9),
                  bg=SURFACE, fg=FG, bd=0, padx=20, pady=6, cursor='hand2',
                  command=dur_win.destroy).pack(side=tk.LEFT, padx=4)

    def _deactivate_user(self):
        if not getattr(self, '_selected_user', ''): return
        cfg = load_cfg()
        email = self._selected_user
        section = 'admin' if email in cfg.get('admin', {}) else 'users'
        users = cfg.get(section, {})
        if email in users and isinstance(users[email], dict):
            users[email]['activated'] = False
            save_cfg(cfg)
            self.refresh_users()
            threading.Thread(target=sync_upload, daemon=True).start()

    def _block_user(self):
        if not getattr(self, '_selected_user', ''): return
        if not messagebox.askyesno('Block User', 'Block this user\'s HWID and deactivate?'): return
        cfg = load_cfg()
        email = self._selected_user
        section = 'admin' if email in cfg.get('admin', {}) else 'users'
        users = cfg.get(section, {})
        user_data = users.get(email, {})
        if not isinstance(user_data, dict): return
        hwid = user_data.get('machine_id', '')
        lic_id = user_data.get('license_id', '')
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        if lic_id:
            for b in blocklist:
                if isinstance(b, dict) and b.get('lic_id') == lic_id: break
            else:
                blocklist.append({'lic_id': lic_id, 'blocked_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')})
        if hwid:
            for b in blocklist:
                if isinstance(b, dict) and b.get('hwid') == hwid: break
            else:
                blocklist.append({'hwid': hwid, 'blocked_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')})
        _save_json(BLOCKLIST_PATH, blocklist)
        user_data['activated'] = False
        users[email] = user_data
        save_cfg(cfg)
        if lic_id:
            licenses = _load_json(LICENSES_PATH)
            if lic_id in licenses:
                licenses[lic_id]['active'] = False
                _save_json(LICENSES_PATH, licenses)
        self.refresh_users()
        self.refresh_blocklist()
        threading.Thread(target=sync_upload, daemon=True).start()

    def _copy_lic_key(self):
        if not getattr(self, '_selected_user', ''): return
        cfg = load_cfg()
        email = self._selected_user
        section = 'admin' if email in cfg.get('admin', {}) else 'users'
        users = cfg.get(section, {})
        user_data = users.get(email, {})
        if isinstance(user_data, dict):
            key = user_data.get('license_key', '')
            if key:
                self.root.clipboard_clear()
                self.root.clipboard_append(key)

    def _delete_user(self):
        if not getattr(self, '_selected_user', ''): return
        if not messagebox.askyesno('Confirm Delete', f'Permanently delete {self._selected_user}?\n\nThis cannot be undone.'): return
        cfg = load_cfg()
        email = self._selected_user
        section = 'admin' if email in cfg.get('admin', {}) else 'users'
        users = cfg.get(section, {})
        user_data = users.get(email, {})
        if isinstance(user_data, dict):
            lic_id = user_data.get('license_id', '')
            if lic_id:
                licenses = _load_json(LICENSES_PATH)
                licenses.pop(lic_id, None)
                _save_json(LICENSES_PATH, licenses)
        users.pop(email, None)
        cfg.setdefault('deleted_users', []).append(email)
        save_cfg(cfg)
        self.refresh_users()
        threading.Thread(target=sync_upload, daemon=True).start()

    # ═══════════════ TAB 2: LICENSES ═══════════════
    def _build_licenses_tab(self):
        f = tk.Frame(self._content, bg=BG)
        self._tab_frames.append(f)

        inner, card = self._card(f, 'All Issued Licenses')
        self.lic_tree = self._tree(inner, ['Lic_ID', 'HWID', 'Type', 'Created', 'Expires', 'Status'], height=10)
        self.lic_tree.column('Lic_ID', width=120)
        self.lic_tree.column('HWID', width=150)
        self.lic_tree.column('Type', width=80)
        self.lic_tree.column('Created', width=150)
        self.lic_tree.column('Expires', width=150)
        self.lic_tree.column('Status', width=80)
        self.lic_tree.bind('<<TreeviewSelect>>', self._on_lic_select)

        cf = self._section(f, 'Create License (Manual)')
        r1 = tk.Frame(cf, bg=CARD)
        r1.pack(fill=tk.X, pady=2)
        tk.Label(r1, text='HWID:', font=('Segoe UI', 9), fg=FG, bg=CARD, width=6, anchor='w').pack(side=tk.LEFT)
        self.lic_hwid = tk.Entry(r1, font=('Consolas', 9), bg=SURFACE, fg=FG, bd=0,
                                 highlightthickness=1, highlightcolor=ACCENT,
                                 highlightbackground=BORDER, insertbackground=FG, relief='flat')
        self.lic_hwid.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        r2 = tk.Frame(cf, bg=CARD)
        r2.pack(fill=tk.X, pady=2)
        tk.Label(r2, text='Type:', font=('Segoe UI', 9), fg=FG, bg=CARD, width=6, anchor='w').pack(side=tk.LEFT)
        cb = ttk.Combobox(r2, values=['rent', 'month3', 'month6', 'month12'],
                          state='readonly', font=('Segoe UI', 9))
        cb.set('month3')
        cb.pack(side=tk.LEFT, padx=4)

        # Fix: store combobox reference properly
        style = ttk.Style()
        style.configure('Lic.TCombobox', fieldbackground=SURFACE, background=SURFACE,
                        foreground=FG, arrowcolor=FG, selectbackground=ACCENT, selectforeground='#1e1e2e')
        cb.configure(style='Lic.TCombobox')
        self.lic_type = cb

        r3 = tk.Frame(cf, bg=CARD)
        r3.pack(pady=4)
        self._btn(r3, 'Generate', self._manual_generate, ACCENT, 14)
        self._btn(r3, 'Copy Selected Key', self._copy_lic_key_from_tree, CYAN)
        self._btn(r3, 'Block', self._block_lic, RED)
        self._btn(r3, 'Unblock', self._unblock_lic, GREEN)
        self._btn(r3, 'Delete License', self._delete_license, RED)

        self.gen_out = tk.Text(cf, font=('Consolas', 8), bg=DARK, fg=GREEN, bd=0,
                               height=3, relief='flat', wrap='word',
                               highlightthickness=1, highlightbackground=BORDER)
        self.gen_out.pack(fill=tk.X, pady=4)

        self.lic_status = self._status(f)

    def _on_lic_select(self, e):
        sel = self.lic_tree.selection()
        self._selected_lic = ''
        if sel:
            vals = self.lic_tree.item(sel[0], 'values')
            self._selected_lic = vals[0] if vals else ''

    def _manual_generate(self):
        hwid = self.lic_hwid.get().strip()
        typ = self.lic_type.get()
        if not hwid: messagebox.showwarning('Missing HWID', 'Enter HWID'); return
        if not os.path.isfile(PRIV_PATH): messagebox.showerror('No Keypair', 'Generate keypair first'); return
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            messagebox.showerror('Missing Library', 'pip install cryptography'); return
        os.makedirs(LICENSE_DATA, exist_ok=True)
        with open(PRIV_PATH, 'rb') as f:
            priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        now = datetime.datetime.utcnow()
        delta_map = {'rent': 4/24, 'month3': 90, 'month6': 180, 'month12': 365}
        delta = datetime.timedelta(days=delta_map.get(typ, 90))
        expires = now + delta
        lic_id = 'LIC-' + uuid.uuid4().hex[:8].upper()
        payload = {
            'lic_id': lic_id, 'hwid': hwid, 'type': typ,
            'created': now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expires': expires.strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
        canonical = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        sig = priv.sign(canonical.encode(), padding.PKCS1v15(), hashes.SHA256())
        payload['signature'] = base64.b64encode(sig).decode()
        lic_key = base64.b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode()
        licenses = _load_json(LICENSES_PATH)
        licenses[lic_id] = {**payload, 'active': True}
        _save_json(LICENSES_PATH, licenses)
        self.gen_out.delete('1.0', tk.END)
        self.gen_out.insert('1.0', lic_key)
        self.root.clipboard_clear()
        self.root.clipboard_append(lic_key)
        self.refresh_licenses()

    def _copy_lic_key_from_tree(self):
        if not getattr(self, '_selected_lic', ''): return
        lid = self._selected_lic
        licenses = _load_json(LICENSES_PATH)
        if lid in licenses:
            payload = {k: v for k, v in licenses[lid].items() if k != 'active'}
            sig = payload.pop('signature', '')
            canonical = json.dumps(payload, separators=(',', ':'), sort_keys=True)
            payload['signature'] = sig
            lic_key = base64.b64encode(json.dumps({**payload}, separators=(',', ':')).encode()).decode()
            self.root.clipboard_clear()
            self.root.clipboard_append(lic_key)

    def _block_lic(self):
        if not getattr(self, '_selected_lic', ''): return
        lid = self._selected_lic
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        for b in blocklist:
            if isinstance(b, dict) and b.get('lic_id') == lid: return
        blocklist.append({'lic_id': lid, 'blocked_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')})
        _save_json(BLOCKLIST_PATH, blocklist)
        licenses = _load_json(LICENSES_PATH)
        if lid in licenses: licenses[lid]['active'] = False; _save_json(LICENSES_PATH, licenses)
        self.refresh_licenses()
        self.refresh_users()
        threading.Thread(target=sync_upload, daemon=True).start()

    def _unblock_lic(self):
        if not getattr(self, '_selected_lic', ''): return
        lid = self._selected_lic
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        blocklist = [b for b in blocklist if not (isinstance(b, dict) and b.get('lic_id') == lid)]
        _save_json(BLOCKLIST_PATH, blocklist)
        licenses = _load_json(LICENSES_PATH)
        if lid in licenses: licenses[lid]['active'] = True; _save_json(LICENSES_PATH, licenses)
        self.refresh_licenses()
        self.refresh_users()
        threading.Thread(target=sync_upload, daemon=True).start()

    def _delete_license(self):
        if not getattr(self, '_selected_lic', ''): return
        lid = self._selected_lic
        if not messagebox.askyesno('Confirm Delete', f'Permanently delete license {lid}?\n\nThis cannot be undone.'): return
        licenses = _load_json(LICENSES_PATH)
        licenses.pop(lid, None)
        _save_json(LICENSES_PATH, licenses)
        cfg = load_cfg()
        for section in ('users', 'admin'):
            for email, data in cfg.get(section, {}).items():
                if isinstance(data, dict) and data.get('license_id') == lid:
                    data.pop('license_id', None)
                    data.pop('license_key', None)
                    data.pop('license_type', None)
                    data.pop('expiry', None)
                    data['activated'] = False
        save_cfg(cfg)
        self.refresh_licenses()
        self.refresh_users()
        threading.Thread(target=sync_upload, daemon=True).start()

    # ═══════════════ TAB 3: BLOCKLIST ═══════════════
    def _build_blocklist_tab(self):
        f = tk.Frame(self._content, bg=BG)
        self._tab_frames.append(f)

        inner, card = self._card(f, 'Blocked Licenses & HWIDs')
        self.bl_tree = self._tree(inner, ['Type', 'Value', 'Blocked_At'], height=10)
        self.bl_tree.column('Type', width=100)
        self.bl_tree.column('Value', width=280)
        self.bl_tree.column('Blocked_At', width=200)
        self.bl_tree.bind('<<TreeviewSelect>>', self._on_bl_select)

        hf = self._section(f, 'Block HWID')
        hr = tk.Frame(hf, bg=CARD)
        hr.pack(fill=tk.X, pady=2)
        tk.Label(hr, text='HWID:', font=('Segoe UI', 9), fg=FG, bg=CARD, width=6, anchor='w').pack(side=tk.LEFT)
        self.bl_hwid_entry = tk.Entry(hr, font=('Consolas', 9), bg=SURFACE, fg=FG, bd=0,
                                      highlightthickness=1, highlightcolor=ACCENT,
                                      highlightbackground=BORDER, insertbackground=FG, relief='flat')
        self.bl_hwid_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        hb = tk.Frame(hf, bg=CARD)
        hb.pack(pady=4)
        self._btn(hb, 'Block HWID', self._block_hwid, RED)
        self._btn(hb, 'Unblock HWID', self._unblock_hwid, GREEN)
        self._btn(hb, 'Upload to Gist', self._upload_blocklist, ACCENT)
        self._btn(hb, 'Delete Selected', self._delete_block_entry, RED)

        self.bl_status = self._status(f)

    def _on_bl_select(self, e):
        sel = self.bl_tree.selection()
        self._selected_bl = ''
        if sel:
            vals = self.bl_tree.item(sel[0], 'values')
            self._selected_bl = vals[1] if vals else ''

    def _delete_block_entry(self):
        if not getattr(self, '_selected_bl', ''): return
        val = self._selected_bl
        if not messagebox.askyesno('Confirm Delete', f'Permanently remove {val} from blocklist?\n\nThis cannot be undone.'): return
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        blocklist = [b for b in blocklist if not (isinstance(b, dict) and (b.get('hwid') == val or b.get('lic_id') == val))]
        _save_json(BLOCKLIST_PATH, blocklist)
        self.refresh_blocklist()
        threading.Thread(target=sync_upload, daemon=True).start()

    def _block_hwid(self):
        hwid = self.bl_hwid_entry.get().strip()
        if not hwid: return
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        for b in blocklist:
            if isinstance(b, dict) and b.get('hwid') == hwid: return
        blocklist.append({'hwid': hwid, 'blocked_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')})
        _save_json(BLOCKLIST_PATH, blocklist)
        self.refresh_blocklist()
        threading.Thread(target=sync_upload, daemon=True).start()

    def _unblock_hwid(self):
        hwid = self.bl_hwid_entry.get().strip()
        if not hwid: return
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        blocklist = [b for b in blocklist if not (isinstance(b, dict) and b.get('hwid') == hwid)]
        _save_json(BLOCKLIST_PATH, blocklist)
        self.refresh_blocklist()
        threading.Thread(target=sync_upload, daemon=True).start()

    def _upload_blocklist(self):
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        cfg = load_cfg()
        cfg['blocklist'] = {'hwids': [b['hwid'] for b in blocklist if isinstance(b, dict) and 'hwid' in b],
                            'ids': [b['lic_id'] for b in blocklist if isinstance(b, dict) and 'lic_id' in b]}
        save_cfg(cfg)
        threading.Thread(target=sync_upload, daemon=True).start()

    # ═══════════════ TAB 4: SYNC & SETTINGS ═══════════════
    def _build_sync_tab(self):
        f = tk.Frame(self._content, bg=BG)
        self._tab_frames.append(f)

        inner, card = self._card(f, 'Sync & Settings')

        # Keypair
        kf = self._section(inner, 'License Keypair')
        has_priv = os.path.isfile(PRIV_PATH)
        has_pub = os.path.isfile(PUB_PATH)
        ready = has_priv and has_pub
        status_text = 'Ready ✓' if ready else 'Missing — generate one'
        color = GREEN if ready else RED
        tk.Label(kf, text=f'Status: {status_text}', font=('Segoe UI', 10, 'bold'),
                 fg=color, bg=CARD).pack(anchor='w', pady=2)
        btnf = tk.Frame(kf, bg=CARD)
        btnf.pack(anchor='w', pady=2)
        if not ready:
            self._btn(btnf, 'Generate Keypair', self._gen_keypair, ACCENT)
        else:
            self._btn(btnf, 'Re-generate', self._gen_keypair, ORANGE)
            self._btn(btnf, 'Copy PubKey', self._copy_pubkey, CYAN)

        # Machine HWID
        mf = self._section(inner, 'Machine Info')
        try:
            import subprocess
            r = subprocess.run(['wmic', 'csproduct', 'get', 'uuid'], capture_output=True, text=True, timeout=3)
            hwid = ''
            for line in r.stdout.split('\n'):
                line = line.strip()
                if line and 'UUID' not in line:
                    hwid = line; break
        except: hwid = 'unknown'
        tk.Label(mf, text=f'HWID (Machine UUID): {hwid}', font=('Segoe UI', 10, 'bold'),
                 fg=ACCENT, bg=CARD).pack(anchor='w', pady=2)

        # Cloudflare Sync
        gf = self._section(inner, f'Cloudflare Sync — {CLOUDFLARE_API_URL}')
        cf_status = 'Connected ✓' if sync_download() else 'Check connection'
        self.sf_label = tk.Label(gf, text=f'Status: {cf_status}', font=('Segoe UI', 10, 'bold'),
                 fg=GREEN if '✓' in cf_status else RED, bg=CARD)
        self.sf_label.pack(anchor='w', pady=2)
        tk.Label(gf, text='Config is stored in Cloudflare KV — globally synced',
                 font=('Segoe UI', 8), fg=MUTED, bg=CARD).pack(anchor='w')
        sync_btnf = tk.Frame(gf, bg=CARD)
        sync_btnf.pack(anchor='w', pady=4)
        self._btn(sync_btnf, 'Download from Cloudflare', self._sync_down, ACCENT, 24)
        self._btn(sync_btnf, 'Upload to Cloudflare', self._sync_up, GREEN, 24)

        self.sync_status = self._status(inner)
        tk.Label(inner, text='Changes are auto-uploaded when you Activate/Block users',
                 font=('Segoe UI', 8), fg=MUTED, bg=CARD).pack()

    def _gen_keypair(self):
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            messagebox.showerror('Missing', 'pip install cryptography'); return
        os.makedirs(LICENSE_DATA, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        with open(PRIV_PATH, 'wb') as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()))
        pub = key.public_key()
        with open(PUB_PATH, 'wb') as f:
            f.write(pub.public_bytes(encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo))
        self.sync_status.config(text='Keypair generated', fg=GREEN)
        self.footer_text.config(text='Keypair generated')
        self._rebuild_settings_tab()

    def _copy_pubkey(self):
        if not os.path.isfile(PUB_PATH): return
        with open(PUB_PATH, 'rb') as f:
            b64 = base64.b64encode(f.read()).decode()
        self.root.clipboard_clear()
        self.root.clipboard_append(b64)
        self.sync_status.config(text='PubKey base64 copied — paste into mdm_king.py', fg=GREEN)

    def _rebuild_settings_tab(self):
        for i, f in enumerate(self._tab_frames):
            f.destroy()
        self._tab_frames.clear()
        old_idx = self._current_tab
        self._build_users_tab()
        self._build_licenses_tab()
        self._build_blocklist_tab()
        self._build_sync_tab()
        self._switch_tab(old_idx if old_idx < len(self._tab_frames) else 0)

    def _sync_down(self):
        self.footer_text.config(text='Downloading from Cloudflare...')
        ok = sync_download()
        self.root.after(0, lambda: (
            self.sync_status.config(text='Downloaded from Cloudflare ✓' if ok else 'Download failed',
                                    fg=GREEN if ok else RED),
            self.footer_text.config(text='Downloaded ✓' if ok else 'Download failed'),
            self.refresh_all() if ok else None
        ))

    def _sync_up(self):
        self.footer_text.config(text='Uploading to Cloudflare...')
        ok = sync_upload()
        self.root.after(0, lambda: (
            self.sync_status.config(text='Uploaded to Cloudflare ✓' if ok else 'Upload failed',
                                    fg=GREEN if ok else RED),
            self.footer_text.config(text='Uploaded ✓' if ok else 'Upload failed')
        ))

    # ═══════════════ REFRESH ═══════════════
    def refresh_all(self):
        self.refresh_users()
        self.refresh_licenses()
        self.refresh_blocklist()

    def refresh_users(self):
        try:
            for i in self.users_tree.get_children(): self.users_tree.delete(i)
        except: return
        cfg = load_cfg()
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        blocked_ids = [b.get('lic_id', '') for b in blocklist if isinstance(b, dict)]
        blocked_hwids = [b.get('hwid', '') for b in blocklist if isinstance(b, dict)]
        users = {**cfg.get('users', {}), **cfg.get('admin', {})}
        for email, data in sorted(users.items()):
            if not isinstance(data, dict): continue
            activated = data.get('activated', False)
            mid = data.get('hwid', '—') or data.get('machine_id', '—') or '—'
            lic = data.get('license_type', '—') or '—'
            exp = data.get('expiry', '—') or '—'
            lid = data.get('license_id', '—') or '—'
            if mid in blocked_hwids or lid in blocked_ids:
                status = 'BLOCKED'
            elif activated:
                status = 'ACTIVE'
            else:
                status = 'PENDING'
            self.users_tree.insert('', tk.END, values=(email, status, mid, lic, exp, lid))
        self.user_status.config(text=f'{len(users)} users')

    def refresh_licenses(self):
        try:
            for i in self.lic_tree.get_children(): self.lic_tree.delete(i)
        except: return
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        blocked_ids = [b.get('lic_id', '') for b in blocklist if isinstance(b, dict)]
        licenses = _load_json(LICENSES_PATH)
        for lid, data in sorted(licenses.items()):
            status = 'BLOCKED' if lid in blocked_ids else ('ACTIVE' if data.get('active', True) else 'DISABLED')
            self.lic_tree.insert('', tk.END, values=(
                lid, data.get('hwid', '?'), data.get('type', '?'),
                data.get('created', '?'), data.get('expires', '?'), status
            ))
        self.lic_status.config(text=f'{len(licenses)} licenses')

    def refresh_blocklist(self):
        try:
            for i in self.bl_tree.get_children(): self.bl_tree.delete(i)
        except: return
        blocklist = _load_json(BLOCKLIST_PATH)
        if not isinstance(blocklist, list): blocklist = []
        for b in blocklist:
            if isinstance(b, dict):
                if 'lic_id' in b:
                    self.bl_tree.insert('', tk.END, values=('License ID', b['lic_id'], b.get('blocked_at', '')))
                if 'hwid' in b:
                    self.bl_tree.insert('', tk.END, values=('HWID', b['hwid'], b.get('blocked_at', '')))
        self.bl_status.config(text=f'{len(blocklist)} entries')

if __name__ == '__main__':
    root = tk.Tk()
    AdminPanel(root)
    root.mainloop()

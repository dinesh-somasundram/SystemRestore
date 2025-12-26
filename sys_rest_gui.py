# sys_rest_gui.py
"""
Minimal System Restore GUI (Tkinter, Windows).

Behavior:
- Auto-elevate on start (UAC prompt may appear).
- If System Restore is disabled: ask to enable; if yes, prompt for drive/max size and enable.
- Shows restore points in a table (Seq #, Date/Time, Description).
- Enforces 24h gating:
    - If latest restore point is < 24h old: Create is disabled and a message is shown.
    - Else: Create is enabled.
- Delete:
    - Button disabled unless a row is selected
    - Only deletes the selected row (no manual Seq entry)
    - If selected Seq no longer exists after refresh, shows "not found" and refreshes
- Shadow ID is never shown to user; used only for debug logging.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional

from system_restore import SystemRestore, check_admin, elevate

CREATE_BLOCK_MINUTES = 24 * 60


def ensure_admin_or_exit(root: tk.Tk) -> None:
    """Auto-elevate; exits this process if elevation succeeds or user cancels."""
    if check_admin():
        return
    if not elevate():
        messagebox.showerror("Administrator Required", "This app must be run as Administrator.")
        root.destroy()
        raise SystemExit(2)


class SystemRestoreApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("System Restore")
        self.geometry("980x520")
        self.minsize(860, 420)

        ensure_admin_or_exit(self)

        self.sr = SystemRestore(debug=False, dry_run=False)
        self.rows: List[Dict[str, Any]] = []

        self._build_ui()
        self._startup_flow()

    # ---------------- UI ----------------
    def _build_ui(self) -> None:
        self.status_var = tk.StringVar(value="")
        self.gating_var = tk.StringVar(value="")

        top = ttk.Frame(self, padding=10)
        top.pack(fill="both", expand=True)

        header = ttk.Frame(top)
        header.pack(fill="x")

        ttk.Label(header, text="System Restore", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Label(header, textvariable=self.status_var).pack(side="left", padx=12)

        gating = ttk.Label(top, textvariable=self.gating_var)
        gating.pack(fill="x", pady=(8, 6))

        table_frame = ttk.Frame(top)
        table_frame.pack(fill="both", expand=True)

        columns = ("seq", "time", "desc")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("seq", text="Seq #")
        self.tree.heading("time", text="Date/Time")
        self.tree.heading("desc", text="Description")

        self.tree.column("seq", width=90, anchor="e", stretch=False)
        self.tree.column("time", width=210, anchor="w", stretch=False)
        self.tree.column("desc", width=600, anchor="w", stretch=True)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        btns = ttk.Frame(top)
        btns.pack(fill="x", pady=(10, 0))

        self.btn_refresh = ttk.Button(btns, text="Refresh", command=self.on_refresh)
        self.btn_create = ttk.Button(btns, text="Create Restore Point", command=self.on_create)
        self.btn_delete = ttk.Button(btns, text="Delete Restore Point", command=self.on_delete)
        self.btn_exit = ttk.Button(btns, text="Exit", command=self.destroy)

        self.btn_refresh.pack(side="left")
        self.btn_create.pack(side="left", padx=(8, 0))

        self.btn_delete.state(["disabled"])  # disabled until a row is selected
        self.btn_delete.pack(side="left", padx=(8, 0))

        self.btn_exit.pack(side="right")

        self.bind("<F5>", lambda _e: self.on_refresh())

        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_delete_state())
        self.tree.bind("<Double-1>", lambda _e: self.on_delete())

    # ---------------- Logic ----------------
    def _startup_flow(self) -> None:
        if not self.sr.check_enabled():
            self.status_var.set("Status: Disabled")
            if not messagebox.askyesno("System Restore Disabled", "System Restore is disabled.\n\nEnable it now?"):
                self.destroy()
                return

            drive = simpledialog.askstring("Enable System Restore", 'Drive (default "C:"):', initialvalue="C:")
            if drive is None:
                self.destroy()
                return

            max_size = simpledialog.askstring(
                "Shadow Storage",
                'Max shadow storage (default "10%"):',
                initialvalue="10%",
            )
            if max_size is None:
                self.destroy()
                return

            res = self.sr.enable(drive=drive.strip() or "C:", max_size=max_size.strip() or "10%")
            if not res.get("success"):
                messagebox.showerror("Enable Failed", res.get("message", "Failed to enable System Restore."))
                self.destroy()
                return

        self.status_var.set("Status: Enabled")
        self.on_refresh()

    def _clear_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _populate_table(self, rows: List[Dict[str, Any]]) -> None:
        self._clear_table()
        for rp in rows:
            seq = str(rp.get("sequence", "") or "")
            dt = str(rp.get("time", "") or "")
            desc = str(rp.get("description", "") or "")
            self.tree.insert("", "end", values=(seq, dt, desc))

    def _sync_delete_state(self) -> None:
        if self.tree.selection():
            self.btn_delete.state(["!disabled"])
        else:
            self.btn_delete.state(["disabled"])

    def _seq_exists(self, seq: str) -> bool:
        s = (seq or "").strip()
        return any(str(r.get("sequence", "") or "").strip() == s for r in self.rows)

    def _get_selected_seq(self) -> Optional[str]:
        sel = self.tree.selection()
        if not sel:
            return None
        values = self.tree.item(sel[0], "values")
        if not values:
            return None
        seq = str(values[0]).strip()
        return seq or None

    def _apply_24h_gating(self) -> None:
        latest = self.sr.get_latest_restore_point(self.rows)
        minutes = latest.get("age_minutes") if latest else None
        can_create = minutes is None or int(minutes) >= CREATE_BLOCK_MINUTES if minutes is not None else True

        if not can_create and minutes is not None:
            age = (latest.get("age_human") if latest else None) or ""
            self.gating_var.set(
                f"A restore point was created {age} ago "
                f"(Restore point cannot be created within 24 hours.)"
            )
            self.btn_create.state(["disabled"])
        else:
            self.gating_var.set("")
            self.btn_create.state(["!disabled"])

    # ---------------- Handlers ----------------
    def on_refresh(self) -> None:
        try:
            self.rows = self.sr.list_restore_points(with_shadows=False)
            self._populate_table(self.rows)
            self._apply_24h_gating()
            self._sync_delete_state()
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to refresh restore points:\n\n{exc}")

    def on_create(self) -> None:
        if "disabled" in self.btn_create.state():
            return

        name = simpledialog.askstring("Create Restore Point", "Restore point name/description:")
        if not name or not name.strip():
            return

        res = self.sr.create_restore_point(description=name.strip(), restore_point_type="MODIFY_SETTINGS")
        if res.get("success"):
            messagebox.showinfo("Created", res.get("message", "Restore point created."))
        else:
            messagebox.showerror("Create Failed", res.get("message", "Failed to create restore point."))
        self.on_refresh()

    def on_delete(self) -> None:
        if "disabled" in self.btn_delete.state():
            return

        seq = self._get_selected_seq()
        if not seq:
            self._sync_delete_state()
            return

        if not seq.isdigit():
            messagebox.showwarning("Invalid Seq #", "Selected Seq # is not numeric.")
            return

        if not self._seq_exists(seq):
            messagebox.showinfo("Not Found", f"Seq # {seq} not found.")
            self.on_refresh()
            return

        if not messagebox.askyesno("Confirm Delete", f"⚠ Delete Seq # {seq}?\n\nThis cannot be undone."):
            return

        res = self.sr.delete_restore_point(seq)

        if res.get("success"):
            if self.sr.debug:
                self.sr.debug_log(
                    f"Deleted restore point: sequence={res.get('sequence')} shadow_id={res.get('shadow_id')}"
                )
            messagebox.showinfo("Deleted", res.get("message", "Restore point deleted."))
        else:
            details = res.get("message", "Failed to delete.")
            stderr = res.get("stderr", "")
            stdout = res.get("stdout", "")
            if stderr or stdout:
                details += "\n\n--- vssadmin output ---"
                if stdout:
                    details += f"\nstdout:\n{stdout}"
                if stderr:
                    details += f"\nstderr:\n{stderr}"
            messagebox.showerror("Delete Failed", details)

        self.on_refresh()


if __name__ == "__main__":
    if sys.platform != "win32":
        raise RuntimeError("Windows only")
    app = SystemRestoreApp()
    app.mainloop()

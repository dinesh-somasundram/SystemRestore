# sys_rest_cli.py
"""
Interactive System Restore CLI (Windows, single-key prompts, case-insensitive).
Rules:
- Auto-elevate on start (UAC prompt still appears if needed).
- If System Restore is disabled: ask to enable, then enable.
- Display restore points table.
- Menu options:
    - If latest restore point is < 24h old:
        offer (D)elete or (E)xit
    - Else:
        offer (C)reate (D)elete or (E)xit
"""

from __future__ import annotations
import msvcrt
import shutil
from typing import Any, Dict, List, Sequence
from system_restore import SystemRestore, check_admin, elevate

TABLE_STYLE = "double"
TABLE_WIDTH = 120        # max total table width (including borders)
SEQ_MIN_W = 5            # Seq starts at 5, grows if needed
DATE_W = 21              # fixed width for "%d-%b-%y %I:%M:%S %p" (21 chars)
DESC_MIN_W = 11          # at least len("Description")
CREATE_BLOCK_MINUTES = 24 * 60

def ensure_admin_or_relaunch() -> None:
    """Auto-elevate (no in-app prompt)."""
    if check_admin():
        return
    if not elevate():
        print("Administrator elevation is required. Exiting.")
        raise SystemExit(2)

def get_single_key(valid_keys: str, beep_on_invalid: bool = True) -> str:
    """
    Read a single keypress and validate against valid_keys (case-insensitive).
    Returns the key as UPPERCASE.
    """
    valid = set(valid_keys.upper())
    while True:
        ch = msvcrt.getch()

        if ch in (b"\x00", b"\xe0"):  # function/arrow keys
            msvcrt.getch()
            continue

        if ch == b"\x03":  # Ctrl+C
            raise KeyboardInterrupt

        if ch in (b"\r", b"\n"):  # Enter
            continue

        key = ch.decode("utf-8", errors="ignore").strip().upper()
        if not key:
            continue

        if key in valid:
            return key

        if beep_on_invalid:
            print("\a", end="", flush=True)

def prompt_choice(message: str, choices: str) -> str:
    print(f"➜  {message} ", end="", flush=True)
    key = get_single_key(choices)
    print(key)
    return key

def prompt_yes_no(message: str) -> bool:
    return prompt_choice(f"{message} (Y/N)", "YN") == "Y"

def ellipsize(s: Any, width: int) -> str:
    s = "" if s is None else str(s)
    if width <= 0:
        return ""
    if len(s) <= width:
        return s
    if width == 1:
        return "…"
    return s[: width - 1] + "…"

def print_table(rows: List[Dict[str, str]], style: str = "single", table_width: int = TABLE_WIDTH) -> None:
    if not rows:
        print("\nNo restore points found.\n")
        return

    # Avoid CMD wrapping: cap to terminal_cols - 1 (wrapping often happens at exact width)
    term_cols = shutil.get_terminal_size(fallback=(table_width, 30)).columns
    effective_width = min(int(table_width), max(60, term_cols - 1))
    table_width = effective_width

    if style == "double":
        tl, tr, bl, br, h, v = "╔", "╗", "╚", "╝", "═", "║"
        tm, bm, lm, rm, mm = "╦", "╩", "╠", "╣", "╬"
    else:
        tl, tr, bl, br, h, v = "┌", "┐", "└", "┘", "─", "│"
        tm, bm, lm, rm, mm = "┬", "┴", "├", "┤", "┼"

    headers = ["Seq #", "Date/Time", "Description"]

    overhead = 10  # Total printed width = sum(widths) + 10 (3 cols => padding+separators+borders)

    max_seq_len = 0
    for r in rows:
        s = "" if r.get("sequence") is None else str(r.get("sequence")).strip()
        max_seq_len = max(max_seq_len, len(s))

    min_desc = max(DESC_MIN_W, len(headers[2]))
    max_seq_allowed = max(SEQ_MIN_W, table_width - overhead - DATE_W - min_desc)

    seq_w = max(SEQ_MIN_W, max_seq_len)
    seq_w = min(seq_w, max_seq_allowed)

    desc_w = table_width - overhead - seq_w - DATE_W
    desc_w = max(min_desc, desc_w)

    if seq_w + DATE_W + desc_w + overhead > table_width:
        seq_w = max(SEQ_MIN_W, table_width - overhead - DATE_W - desc_w)

    def ellipsize_left(s: Any, width: int) -> str:
        s = "" if s is None else str(s)
        if width <= 0:
            return ""
        if len(s) <= width:
            return s
        if width == 1:
            return "…"
        return "…" + s[-(width - 1):]

    def fit_seq(seq: Any) -> str:
        s = "" if seq is None else str(seq).strip()
        s = ellipsize_left(s, seq_w)
        return s.rjust(seq_w)

    data: List[List[str]] = []
    for r in rows:
        data.append(
            [
                fit_seq(r.get("sequence", "")),
                ellipsize(r.get("time", "") or "", DATE_W),
                ellipsize(r.get("description", "") or "", desc_w),
            ]
        )

    widths = [
        max(seq_w, len(headers[0])),
        max(DATE_W, len(headers[1])),
        max(desc_w, len(headers[2])),
    ]

    def line(left: str, mid: str, right: str) -> str:
        return left + mid.join(h * (w + 2) for w in widths) + right

    def row_line(values: Sequence[Any]) -> str:
        a = ellipsize_left(str(values[0]), widths[0])
        b = ellipsize(str(values[1]), widths[1])
        c = ellipsize(str(values[2]), widths[2])
        return v + v.join(
            [
                f" {a:<{widths[0]}} ",
                f" {b:<{widths[1]}} ",
                f" {c:<{widths[2]}} ",
            ]
        ) + v

    print()
    print(line(tl, tm, tr))
    print(row_line(headers))
    print(line(lm, mm, rm))
    for r in data:
        print(row_line(r))
    print(line(bl, bm, br))
    print()

def refresh(sr: SystemRestore) -> List[Dict[str, str]]:
    rows = sr.list_restore_points(with_shadows=False)
    print_table(rows, style=TABLE_STYLE)
    return rows

def seq_exists(rows: List[Dict[str, str]], seq: str) -> bool:
    s = (seq or "").strip()
    return any((r.get("sequence") or "").strip() == s for r in rows)

def main() -> int:
    try:
        ensure_admin_or_relaunch()
        sr = SystemRestore(debug=False, dry_run=False)

        if not sr.check_enabled():
            print("System Restore is currently DISABLED.")
            if not prompt_yes_no("Enable System Restore now?"):
                print("Exiting.")
                return 0

            drive = input('Drive to enable (default "C:"): ').strip() or "C:"
            max_size = input('Max shadow storage (default "10%"): ').strip() or "10%"
            res = sr.enable(drive=drive, max_size=max_size)
            print(res.get("message", ""))
            if not res.get("success"):
                return 1

        print("System Restore is ENABLED.")
        rows = refresh(sr)

        while True:
            latest = sr.get_latest_restore_point(rows)
            minutes = latest["age_minutes"] if latest else None
            can_create = minutes is None or minutes >= CREATE_BLOCK_MINUTES

            if not can_create and minutes is not None:
                age = (latest.get("age_human") if latest else None) or ""
                print(
                    f"A restore point was created {age} ago "
                    f"(Restore point cannot be created within 24 hours.)"
                )
                key = prompt_choice("(D)elete restore point or (E)xit system restore?", "DE")
            else:
                key = prompt_choice("(C)reate, (D)elete restore point or (E)xit system restore?", "CDE")

            if key == "E":
                print("Exiting.")
                return 0

            if key == "C":
                name = input("Restore point name/description: ").strip()
                if not name:
                    print("Name cannot be empty.")
                    rows = refresh(sr)
                    continue

                res = sr.create_restore_point(description=name, restore_point_type="MODIFY_SETTINGS")
                print(res.get("message", ""))
                rows = refresh(sr)
                continue

            if key == "D":
                seq = input("Enter the Seq # to delete: ").strip()
                if not seq:
                    print("Seq # cannot be empty.")
                    rows = refresh(sr)
                    continue

                if not seq.isdigit():
                    print("Seq # must be numeric.")
                    rows = refresh(sr)
                    continue

                if not seq_exists(rows, seq):
                    print(f"Seq # {seq} not found.")
                    rows = refresh(sr)
                    continue

                if not prompt_yes_no(f"⚠ Delete Seq # {seq}? This cannot be undone."):
                    rows = refresh(sr)
                    continue

                res = sr.delete_restore_point(seq)  # numeric-only enforced in system_restore.py
                print(res.get("message", ""))

                if res.get("success"):
                    shadow_id = res.get("shadow_id", "")
                    if shadow_id:
                        print(f"Deleted Seq # {res.get('sequence')} (Shadow: {shadow_id})")

                rows = refresh(sr)
                continue

    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130

if __name__ == "__main__":
    raise SystemExit(main())

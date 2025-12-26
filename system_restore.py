# system_restore.py
"""
Windows System Restore library (Windows-only).

Provides:
- SystemRestore:
    - check_enabled()
    - enable(drive="C:", max_size="10%")
    - list_restore_points(with_shadows=False)  -> always includes age fields
    - get_latest_restore_point(restore_points=None) -> returns latest + age + shadow_id (best-effort)
    - create_restore_point(description, restore_point_type)
    - delete_restore_point(sequence) -> numeric-only full SequenceNumber; returns sequence+shadow_id on success
- check_admin(), elevate(): helpers for CLI/GUI layers

Notes on deletion:
Windows doesn't provide a clean public API to delete an individual restore point by SequenceNumber.
This implementation correlates restore points to VSS shadow copies by nearest timestamp within
DEFAULT_TOLERANCE_SECONDS (default 3600 seconds) and deletes the matched shadow copy via vssadmin.

Console window behavior:
All subprocesses are launched with CREATE_NO_WINDOW to prevent console popups when using pythonw.exe.
"""

from __future__ import annotations

import ctypes
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

if sys.platform != "win32":
    raise RuntimeError("Windows only")

try:
    import winreg  # type: ignore
except Exception as exc:  # pragma: no cover
    raise RuntimeError("winreg unavailable; this module is Windows-only") from exc


def check_admin() -> bool:
    """Return True if running elevated."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate(argv: Optional[List[str]] = None) -> bool:
    """
    Request admin elevation (UAC). Returns True if elevation was triggered.
    If triggered, the current process exits.

    Args:
        argv: override arguments used for relaunch (defaults to sys.argv).
    """
    args = argv or sys.argv
    try:
        params = " ".join(
            f'"{arg}"' if " " in arg and not arg.startswith('"') else arg for arg in args
        )
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        if rc <= 32:
            return False
        sys.exit(0)
    except Exception:
        return False


class SystemRestore:
    """
    Windows System Restore helper.

    DEFAULT_TOLERANCE_SECONDS controls the mapping window used when correlating:
      RestorePoint(CreationTime) -> ShadowCopy(InstallDate)
    """

    DEFAULT_TOLERANCE_SECONDS: int = 3600
    RP_TIME_FMT: str = "%d-%b-%y %I:%M:%S %p"

    def __init__(self, debug: bool = False, dry_run: bool = False):
        self.debug = debug
        self.dry_run = dry_run
        self.is_admin = check_admin()

        self.system_restore_enabled = False
        self.restore_point_created = False
        self.restore_point_deleted = False

        self._powershell_exe = self._detect_powershell()
        self._creationflags = self._compute_creationflags()

    def debug_log(self, msg: str) -> None:
        if self.debug:
            print(f"[debug] {msg}")

    @staticmethod
    def _detect_powershell() -> str:
        for exe in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"):
            if shutil.which(exe):
                return exe
        return "powershell"

    @staticmethod
    def _compute_creationflags() -> int:
        """
        Prevent console windows from popping up (especially when running under pythonw.exe).
        """
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)

    def _run_powershell(self, script: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                self._powershell_exe,
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=self._creationflags,
        )

    # -------------------------
    # Age helpers (used by CLI/GUI)
    # -------------------------
    @staticmethod
    def _human_age_from_minutes(minutes: int) -> str:
        if minutes < 60:
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        hours = minutes // 60
        mins = minutes % 60
        if mins == 0:
            return f"{hours} hour{'s' if hours != 1 else ''}"
        return f"{hours} hour{'s' if hours != 1 else ''} {mins} minute{'s' if mins != 1 else ''}"

    def get_restore_point_age(self, rp_time: str) -> Dict[str, Optional[Any]]:
        """
        Return both age in minutes + human-readable text for a restore point time string.

        Returns:
            {'age_minutes': Optional[int], 'age_human': Optional[str]}
        """
        if not rp_time:
            return {"age_minutes": None, "age_human": None}

        try:
            dt = datetime.strptime(str(rp_time).strip(), self.RP_TIME_FMT)
        except Exception:
            return {"age_minutes": None, "age_human": None}

        minutes = int((datetime.now() - dt).total_seconds() // 60)
        return {"age_minutes": minutes, "age_human": self._human_age_from_minutes(minutes)}

    # -------------------------
    # System Restore enabled / enable
    # -------------------------
    def check_enabled(self) -> bool:
        """Return True if System Restore appears enabled."""
        self._check_system_restore()
        return self.system_restore_enabled

    def _check_system_restore(self) -> None:
        """
        Check if System Restore is enabled.

        Strategy:
          1) Registry disable flags (strong indicator)
          2) Registry RPSessionInterval (weak indicator)
          3) PowerShell probe fallback (practical indicator)
        """
        self.system_restore_enabled = False
        reason = "unknown"

        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore",
            ) as key:

                def get_dword(name: str) -> Optional[int]:
                    try:
                        v, _ = winreg.QueryValueEx(key, name)
                        return int(v)
                    except FileNotFoundError:
                        return None
                    except Exception:
                        return None

                disable_sr = get_dword("DisableSR")
                disable_cfg = get_dword("DisableConfig")
                global_disable = get_dword("SRGlobalDisable")

                if disable_sr == 1 or disable_cfg == 1 or global_disable == 1:
                    self.system_restore_enabled = False
                    reason = "registry_disable_flag"
                else:
                    rpsi = get_dword("RPSessionInterval")
                    if rpsi is not None and rpsi >= 1:
                        self.system_restore_enabled = True
                        reason = "registry_rpsessioninterval"
                    else:
                        reason = "registry_inconclusive"

        except FileNotFoundError:
            self.system_restore_enabled = False
            reason = "registry_key_missing"
        except Exception:
            self.system_restore_enabled = False
            reason = "registry_error"

        if reason in ("registry_inconclusive", "registry_key_missing", "registry_error"):
            ps_cmd = r"""
            try {
                $null = Get-ComputerRestorePoint -ErrorAction Stop
                'OK'
            } catch {
                $m = $_.Exception.Message
                if ($m) { $m = $m.ToString() } else { $m = '' }
                'ERR|' + $m
            }
            """
            try:
                r = self._run_powershell(ps_cmd, timeout=10)
                out = (r.stdout or "").strip()
                if out == "OK":
                    self.system_restore_enabled = True
                    reason = "powershell_ok"
                elif out.startswith("ERR|"):
                    msg = out[4:].lower()
                    disabled_markers = [
                        "system restore is disabled",
                        "restore points are disabled",
                        "the system restore feature is not enabled",
                        "cannot create a system restore point",
                        "service cannot be started",
                    ]
                    self.system_restore_enabled = not any(m in msg for m in disabled_markers)
                    reason = (
                        "powershell_disabled"
                        if not self.system_restore_enabled
                        else "powershell_ok_heuristic"
                    )
                else:
                    self.system_restore_enabled = False
                    reason = "powershell_unexpected_output"
            except Exception:
                self.system_restore_enabled = False
                reason = "powershell_probe_failed"

        self.debug_log(f"System Restore enabled={self.system_restore_enabled} ({reason})")

    def enable(self, drive: str = "C:", max_size: Optional[str] = "10%") -> Dict[str, Any]:
        """
        Enable System Restore on a drive and optionally set shadow storage size.

        Args:
            drive: e.g. "C:" (or "C:\\")
            max_size: vssadmin MaxSize (e.g. "10%", "5GB"). None = skip resize step.
        """
        if not self.is_admin:
            return {"success": False, "code": "not_admin", "message": "Admin rights required."}

        norm_drive = drive.strip().rstrip("\\")
        ps_drive = (norm_drive + "\\") if len(norm_drive) == 2 and norm_drive[1] == ":" else norm_drive

        if self.dry_run:
            return {
                "success": True,
                "code": "dry_run",
                "message": f"[dry-run] Would enable System Restore on {ps_drive} and set MaxSize={max_size}.",
            }

        ps_cmd = rf"""
        try {{
            Enable-ComputerRestore -Drive "{ps_drive}" -ErrorAction Stop
            "OK|Enabled on {ps_drive}"
        }} catch {{
            "FAIL|" + $_.Exception.Message
        }}
        """
        try:
            r = self._run_powershell(ps_cmd, timeout=30)
            out = (r.stdout or "").strip()
            if not out:
                return {
                    "success": False,
                    "code": "no_output",
                    "message": "Enable-ComputerRestore returned no output.",
                }

            status, msg = (out.split("|", 1) + [""])[:2]
            status = status.strip().upper()
            msg = msg.strip()

            if status != "OK":
                return {
                    "success": False,
                    "code": "fail",
                    "message": msg or "Failed to enable System Restore.",
                }

            resize_msg = ""
            if max_size:
                try:
                    rr = subprocess.run(
                        [
                            "vssadmin",
                            "resize",
                            "shadowstorage",
                            f"/For={norm_drive}",
                            f"/On={norm_drive}",
                            f"/MaxSize={max_size}",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        creationflags=self._creationflags,
                    )
                    if rr.returncode == 0:
                        resize_msg = f" Shadow storage resized to {max_size}."
                    else:
                        resize_msg = " Shadow storage resize failed (continuing)."
                        self.debug_log((rr.stderr or "").strip())
                except Exception as exc:
                    resize_msg = f" Shadow storage resize exception: {exc}"

            self._check_system_restore()
            return {
                "success": True,
                "code": "ok",
                "message": f"Enabled on {ps_drive}.{resize_msg}".strip(),
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "code": "timeout", "message": "Timed out enabling System Restore."}
        except Exception as exc:
            return {"success": False, "code": "exception", "message": f"Exception enabling System Restore: {exc}"}

    # -------------------------
    # Listing / mapping
    # -------------------------
    def list_restore_points(self, with_shadows: bool = False) -> List[Dict[str, Any]]:
        """
        Return restore points (latest first).

        Always includes:
          - sequence (str)
          - description (str)
          - time (str)
          - age_minutes (Optional[int])
          - age_human (Optional[str])

        Optionally includes:
          - shadow_id (str) if with_shadows=True
        """
        ps_cmd = r"""
            try {
                Get-ComputerRestorePoint |
                Sort-Object CreationTime -Descending |
                ForEach-Object {
                    $dt   = [Management.ManagementDateTimeConverter]::ToDateTime($_.CreationTime)
                    $desc = ($_.Description -replace '\r|\n', ' ' -replace '\|', '-')
                    '{0}|{1}|{2}' -f $_.SequenceNumber,
                                      $desc,
                                      $dt.ToString('dd-MMM-yy hh:mm:ss tt')
                }
            } catch { '' }
        """
        try:
            result = self._run_powershell(ps_cmd, timeout=10)
            lines = [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]

            restore_points: List[Dict[str, Any]] = []
            for line in lines:
                parts = line.split("|", 2)
                if len(parts) != 3:
                    continue

                rp: Dict[str, Any] = {
                    "sequence": parts[0].strip(),
                    "description": parts[1].strip(),
                    "time": parts[2].strip(),
                    "shadow_id": "",
                }
                rp.update(self.get_restore_point_age(rp["time"]))
                restore_points.append(rp)

            if with_shadows and restore_points:
                self.attach_shadow_ids(restore_points)

            return restore_points
        except Exception:
            return []

    def get_shadow_copies(self) -> List[Dict[str, str]]:
        """
        Return VSS shadow copies as:
            { 'id': '{GUID}', 'time': 'dd-MMM-yy hh:mm:ss tt' }
        """
        ps_cmd = r"""
        try {
            $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
            if (-not $shadows) { return }
            foreach ($s in $shadows | Sort-Object InstallDate -Descending) {
                $dt = [Management.ManagementDateTimeConverter]::ToDateTime($s.InstallDate)
                '{0}|{1}' -f $s.ID, $dt.ToString('dd-MMM-yy hh:mm:ss tt')
            }
        } catch { '' }
        """
        try:
            result = self._run_powershell(ps_cmd, timeout=15)
            lines = [ln.strip() for ln in (result.stdout or "").splitlines() if ln.strip()]
            shadows: List[Dict[str, str]] = []
            for line in lines:
                parts = line.split("|", 1)
                if len(parts) != 2:
                    continue
                shadows.append({"id": parts[0].strip(), "time": parts[1].strip()})
            return shadows
        except Exception:
            return []

    def attach_shadow_ids(
        self,
        restore_points: List[Dict[str, Any]],
        tolerance_seconds: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Attach 'shadow_id' to each restore point using nearest timestamp match within tolerance.
        Modifies list in place and returns it.
        """
        tol = self.DEFAULT_TOLERANCE_SECONDS if tolerance_seconds is None else int(tolerance_seconds)

        for rp in restore_points:
            rp.setdefault("shadow_id", "")

        shadows = self.get_shadow_copies()
        if not shadows or not restore_points:
            return restore_points

        parsed_shadows: List[tuple[datetime, str]] = []
        for sh in shadows:
            try:
                parsed_shadows.append((datetime.strptime(sh["time"], self.RP_TIME_FMT), sh["id"]))
            except Exception:
                continue
        if not parsed_shadows:
            return restore_points

        for rp in restore_points:
            try:
                rp_dt = datetime.strptime(str(rp.get("time", "") or ""), self.RP_TIME_FMT)
            except Exception:
                continue

            closest_id = ""
            min_delta: Optional[float] = None
            for sh_dt, sh_id in parsed_shadows:
                delta = abs((sh_dt - rp_dt).total_seconds())
                if min_delta is None or delta < min_delta:
                    min_delta = delta
                    closest_id = sh_id

            if min_delta is not None and min_delta <= tol:
                rp["shadow_id"] = closest_id

        return restore_points

    def get_latest_restore_point(
        self, restore_points: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Return latest restore point including:
          - age_minutes (int|None)
          - age_human (str|None)
          - shadow_id (str; may be empty if not matched)

        If restore_points is provided, it should be the result of list_restore_points().
        """
        rps = restore_points if restore_points is not None else self.list_restore_points(with_shadows=False)
        if not rps:
            return None

        latest: Dict[str, Any] = dict(rps[0])
        latest.update(self.get_restore_point_age(latest.get("time", "") or ""))

        latest.setdefault("shadow_id", "")
        self.attach_shadow_ids([latest])
        latest.setdefault("shadow_id", "")

        return latest

    # -------------------------
    # Create
    # -------------------------
    @staticmethod
    def _sanitize_description(description: str) -> str:
        s = (description or "").strip()
        s = s.replace("\r", " ").replace("\n", " ").replace("|", "-")
        return s or "Manual Restore Point"

    def create_restore_point(
        self,
        description: str = "Manual Restore Point",
        restore_point_type: str = "MODIFY_SETTINGS",
    ) -> Dict[str, Any]:
        """Create a restore point using Checkpoint-Computer."""
        if not self.is_admin:
            return {"success": False, "code": "not_admin", "message": "Admin rights required."}

        desc = self._sanitize_description(description)

        if self.dry_run:
            return {"success": True, "code": "dry_run", "message": f"[dry-run] Would create: {desc!r}."}

        ps_cmd = (
            f"$msg = Checkpoint-Computer -Description {desc!r} "
            f"-RestorePointType {restore_point_type!r} -WarningAction Continue 3>&1 2>$null; "
            "$msgText = ($msg | Out-String).Trim(); "
            "if (-not $msgText) { 'OK|' } "
            "elseif ($msgText -match 'A new system restore point cannot be created' -or "
            "        $msgText -match 'cannot be created' -or "
            "        $msgText -match 'WARNING') { "
            "  $first = ($msgText -split '\\. ')[0]; "
            "  if ($msgText -match '\\.') { $first = $first + '.' }; "
            "  'FAIL|' + $first "
            "} else { 'OK|' }"
        )

        try:
            result = self._run_powershell(ps_cmd, timeout=120)
            output = (result.stdout or "").strip()
            self.debug_log(f"Create RP stdout: {output}")
            if (result.stderr or "").strip():
                self.debug_log(f"Create RP stderr: {(result.stderr or '').strip()}")

            if not output:
                return {"success": False, "code": "no_output", "message": "No output from Checkpoint-Computer."}

            status, msg = (output.split("|", 1) + [""])[:2]
            status = status.strip().upper()
            msg = msg.strip()

            if status == "FAIL":
                return {"success": False, "code": "fail", "message": msg or "Could not create a restore point."}

            self.restore_point_created = True
            return {"success": True, "code": "ok", "message": "Restore point created successfully."}
        except subprocess.TimeoutExpired:
            return {"success": False, "code": "timeout", "message": "Timed out while creating restore point."}
        except Exception as exc:
            return {"success": False, "code": "exception", "message": f"Exception creating restore point: {exc}"}

    # -------------------------
    # Delete
    # -------------------------
    @staticmethod
    def _parse_sequence(sequence: str) -> Optional[int]:
        """
        Validate and normalize SequenceNumber input.
        Only accepts digits-only full sequence.
        """
        if sequence is None:
            return None
        s = str(sequence).strip()
        if not s or not s.isdigit():
            return None
        try:
            return int(s)
        except Exception:
            return None

    def _delete_shadow(self, shadow_id: str) -> Dict[str, Any]:
        """
        Internal: delete by ShadowCopy ID (vssadmin).
        - On success: generic message (no shadow id in message)
        - On failure: surfaces stdout/stderr for troubleshooting
        """
        if not self.is_admin:
            return {"success": False, "code": "not_admin", "message": "Admin rights required."}
        if not shadow_id:
            return {"success": False, "code": "missing_id", "message": "No ShadowCopyID provided."}

        if self.dry_run:
            return {"success": True, "code": "dry_run", "message": f"[dry-run] Would delete shadow {shadow_id}."}

        try:
            result = subprocess.run(
                ["vssadmin", "delete", "shadows", f"/Shadow={shadow_id}", "/Quiet"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=60,
                creationflags=self._creationflags,
            )

            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()

            if result.returncode == 0:
                self.restore_point_deleted = True
                return {
                    "success": True,
                    "code": "ok",
                    "message": "Restore point deleted successfully.",
                }

            msg = "Failed to delete restore point."
            if stderr:
                msg += f" {stderr}"

            return {
                "success": False,
                "code": "fail",
                "message": msg,
                "returncode": result.returncode,
                "stdout": stdout,
                "stderr": stderr,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "code": "timeout",
                "message": "Timed out deleting restore point.",
                "stdout": "",
                "stderr": "",
            }
        except Exception as exc:
            return {
                "success": False,
                "code": "exception",
                "message": f"Exception deleting restore point: {exc}",
                "stdout": "",
                "stderr": "",
            }

    def delete_restore_point_by_sequence(self, sequence: str) -> Dict[str, Any]:
        """
        Delete a restore point by numeric SequenceNumber only.
        Internally maps to ShadowCopy ID using DEFAULT_TOLERANCE_SECONDS.

        On success, payload includes:
          - sequence (string)
          - shadow_id
        """
        seq_int = self._parse_sequence(sequence)
        if seq_int is None:
            return {
                "success": False,
                "code": "invalid_sequence",
                "message": "Sequence must be a numeric value (digits only).",
            }

        if not self.is_admin:
            return {"success": False, "code": "not_admin", "message": "Admin rights required."}

        rps = self.list_restore_points(with_shadows=True)
        if not rps:
            return {"success": False, "code": "no_restore_points", "message": "No restore points found."}

        target: Optional[Dict[str, Any]] = None
        for rp in rps:
            rp_seq = str(rp.get("sequence", "") or "").strip()
            if rp_seq.isdigit() and int(rp_seq) == seq_int:
                target = rp
                break

        if not target:
            return {"success": False, "code": "not_found", "message": f"Seq # {seq_int} not found."}

        shadow_id = str(target.get("shadow_id", "") or "").strip()
        if not shadow_id:
            return {
                "success": False,
                "code": "no_shadow_match",
                "message": (
                    f"Could not map Seq # {seq_int} to a ShadowCopy ID "
                    f"(tolerance={self.DEFAULT_TOLERANCE_SECONDS}s)."
                ),
            }

        res = self._delete_shadow(shadow_id)
        if res.get("success"):
            res["sequence"] = str(seq_int)
            res["shadow_id"] = shadow_id
        return res

    def delete_restore_point(self, sequence: str) -> Dict[str, Any]:
        """Alias for UI layers: delete by numeric SequenceNumber only."""
        return self.delete_restore_point_by_sequence(sequence)

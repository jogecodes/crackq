"""
Minimal Hashcat CLI wrapper to replace pyhashcat for CrackQ.
"""
import json
import os
import pty
import re
import select
import subprocess
import threading
import time

from crackq.logger import logger


_HASHMODE_RE = re.compile(r"^\s*(\d+)\s+\|\s+(.+?)\s+\|\s+(.+?)\s*$")
_HASHMODE_HEADER_RE = re.compile(r"^Hash mode #(\d+)\s*$")
_HASHMODE_NAME_RE = re.compile("^\\s*Name\\.+:\\s*(.+?)\\s*$")
_HASHMODE_CATEGORY_RE = re.compile("^\\s*Category\\.+:\\s*(.+?)\\s*$")
_STATUS_FIELD_RE = re.compile(r"^([A-Za-z0-9#\\.]+)\\.*:\\s*(.*)$")
_STATUS_MAP = {
    0: "Initializing",
    1: "Running",
    2: "Running",
    3: "Paused",
    4: "Exhausted",
    5: "Cracked",
    6: "Aborted",
}


class Hashcat:
    def __init__(self):
        self._bin = os.environ.get("HASHCAT_BIN", "hashcat")
        self._proc = None
        self._stdout_thread = None
        self._stderr_thread = None
        self._watch_thread = None
        self._last_status = None
        self._last_log = ""
        self._pty_master = None
        self._status_lock = threading.Lock()
        self._event_handlers = {}
        self._usage_output = None

        # options
        self.session = None
        self.hash = None
        self.hash_mode = None
        self.attack_mode = None
        self.rules = None
        self.rp_files_cnt = None
        self.dict1 = None
        self.dict2 = None
        self.mask = None
        self.show = False
        self.speed_only = False
        self.benchmark = False
        self.benchmark_all = False
        self.username = False
        self.potfile_disable = False
        self.potfile_path = None
        self.restore_disable = False
        self.restore_file_path = None
        self.skip = None
        self.quiet = False
        self.optimized_kernel_enable = False
        self.workload_profile = None
        self.increment = False
        self.increment_min = None
        self.increment_max = None
        self.brain_client = False
        self.brain_client_features = None
        self.brain_password = None
        self.brain_host = None
        self.markov_hcstat2 = None
        self.custom_charset_1 = None
        self.custom_charset_2 = None
        self.custom_charset_3 = None
        self.custom_charset_4 = None
        self.outfile = None
        self.hwmon_disable = False
        self.logfile_disable = False
        self.usage = False
        self.backend_info = False
        self.spin_damp = None
        self.left = None

    def event_connect(self, callback=None, signal=None):
        if not callback or not signal:
            return
        self._event_handlers.setdefault(signal, []).append(callback)

    def _emit(self, signal):
        callbacks = self._event_handlers.get(signal, [])
        for cb in callbacks:
            try:
                cb(self)
            except Exception as err:
                logger.debug("Event callback failed: %s", err)

    def _build_args(self):
        args = [self._bin]

        if self.session:
            args += ["--session", str(self.session)]
        if self.hash_mode is not None:
            args += ["-m", str(self.hash_mode)]
        if self.attack_mode is not None:
            args += ["-a", str(self.attack_mode)]

        if self.username:
            args.append("--username")
        if self.potfile_disable:
            args.append("--potfile-disable")
        if self.potfile_path:
            args += ["--potfile-path", str(self.potfile_path)]
        if self.restore_disable:
            args.append("--restore-disable")
        if self.restore_file_path:
            args += ["--restore-file-path", str(self.restore_file_path)]
        if self.skip is not None:
            args += ["--skip", str(self.skip)]
        if self.show:
            args.append("--show")
        if self.speed_only:
            args.append("--speed-only")
        if self.benchmark:
            args.append("-b")
            if self.benchmark_all:
                args.append("--benchmark-all")
        if self.quiet:
            args.append("--quiet")
        if self.optimized_kernel_enable:
            args.append("-O")
        if self.workload_profile is not None:
            args += ["-w", str(self.workload_profile)]
        if self.increment:
            args.append("--increment")
        if self.increment_min is not None:
            args += ["--increment-min", str(self.increment_min)]
        if self.increment_max is not None:
            args += ["--increment-max", str(self.increment_max)]

        if self.brain_client:
            args.append("--brain-client")
            if self.brain_client_features is not None:
                args += ["--brain-client-features", str(self.brain_client_features)]
            if self.brain_password:
                args += ["--brain-password", str(self.brain_password)]
            if self.brain_host:
                args += ["--brain-host", str(self.brain_host)]

        if self.markov_hcstat2:
            args += ["--markov-hcstat2", str(self.markov_hcstat2)]
        if self.attack_mode in [3, 6, 7]:
            if self.custom_charset_1:
                args += ["-1", str(self.custom_charset_1)]
            if self.custom_charset_2:
                args += ["-2", str(self.custom_charset_2)]
            if self.custom_charset_3:
                args += ["-3", str(self.custom_charset_3)]
            if self.custom_charset_4:
                args += ["-4", str(self.custom_charset_4)]
        if self.outfile:
            args += ["--outfile", str(self.outfile)]
        if self.hwmon_disable:
            args.append("--hwmon-disable")
        if self.logfile_disable:
            args.append("--logfile-disable")

        # status stream for parsing
        args += ["--status", "--status-json", "--status-timer", "10"]

        # rules
        if self.rules:
            if isinstance(self.rules, (list, tuple)):
                for rule in self.rules:
                    args += ["-r", str(rule)]
            else:
                args += ["-r", str(self.rules)]

        # input files/mask
        if self.hash:
            args.append(str(self.hash))
        if self.dict1:
            args.append(str(self.dict1))
        if self.dict2:
            args.append(str(self.dict2))
        if self.mask:
            args.append(str(self.mask))

        return args

    def _stdout_reader(self):
        # If using a PTY, stdout/stderr are merged and read via master fd.
        if self._pty_master is None:
            for line in self._proc.stdout:
                self._handle_output_line(line)
            logger.debug("hashcat stdout reader stopped")
            return
        buf = b""
        while True:
            if self._proc.poll() is not None:
                # Drain any remaining output
                rlist = [self._pty_master]
                timeout = 0
            else:
                rlist = [self._pty_master]
                timeout = 0.5
            ready, _, _ = select.select(rlist, [], [], timeout)
            if ready:
                try:
                    data = os.read(self._pty_master, 1024)
                except OSError:
                    break
                if not data:
                    break
                buf += data
                # split on CR or LF to get status lines
                while True:
                    m = re.search(br"[\r\n]", buf)
                    if not m:
                        break
                    line = buf[:m.start()].decode(errors="ignore")
                    buf = buf[m.end():]
                    self._handle_output_line(line)
            if self._proc.poll() is not None and not ready:
                break
        if buf:
            self._handle_output_line(buf.decode(errors="ignore"))
        logger.debug("hashcat stdout reader stopped")

    def _stderr_reader(self):
        if self._pty_master is not None:
            return
        for line in self._proc.stderr:
            self._handle_output_line(line)
        logger.debug("hashcat stderr reader stopped")

    def _handle_output_line(self, line):
        if line is None:
            return
        if not isinstance(line, str):
            line = line.decode(errors="ignore")
        line = line.replace("\r", "").rstrip("\n")
        if not line:
            return
        with self._status_lock:
            self._last_log = line
        uline = line.upper()
        if "WARNING" in uline:
            self._emit("EVENT_LOG_WARNING")
        if "ERROR" in uline:
            self._emit("EVENT_LOG_ERROR")
        # JSON status lines (if enabled)
        if line.startswith("{") and line.endswith("}"):
            try:
                status = json.loads(line)
                with self._status_lock:
                    self._last_status = status
            except json.JSONDecodeError:
                pass
            return
        self._parse_text_status(line)

    def _parse_text_status(self, line):
        if not line:
            return
        # Skip the prompt/status control line.
        if line.startswith("[s]tatus"):
            return
        match = _STATUS_FIELD_RE.match(line)
        if not match:
            return
        key = match.group(1)
        val = match.group(2).strip()
        with self._status_lock:
            status = dict(self._last_status or {})
        # Map key fields used by CrackQ
        if key == "Status":
            status["status_name"] = val
            status["status"] = val
        elif key.startswith("Speed.#"):
            speed_hps = self._parse_speed(val)
            if speed_hps is not None:
                status.setdefault("speed", [])
                status["speed"].append({"speed": speed_hps})
        elif key == "Recovered":
            # Example: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
            m = re.search(r"(\\d+)\\/(\\d+)", val)
            if m:
                status["recovered_hashes"] = [int(m.group(1)), int(m.group(2))]
        elif key == "Progress":
            m = re.search(r"(\\d+)\\/(\\d+)", val)
            if m:
                status["progress"] = [int(m.group(1)), int(m.group(2))]
        elif key == "Salts":
            try:
                status["salts"] = int(val.split()[0])
            except (ValueError, IndexError):
                pass
        with self._status_lock:
            self._last_status = status

    def _parse_speed(self, val):
        # Example: "56725.3 MH/s (2.22ms) @ Accel:36 ..."
        parts = val.split()
        if len(parts) < 2:
            return None
        try:
            num = float(parts[0])
        except ValueError:
            return None
        unit = parts[1]
        mult = 1.0
        if unit.startswith("kH/"):
            mult = 1e3
        elif unit.startswith("MH/"):
            mult = 1e6
        elif unit.startswith("GH/"):
            mult = 1e9
        elif unit.startswith("TH/"):
            mult = 1e12
        return num * mult

    def _watcher(self):
        rc = self._proc.wait()
        with self._status_lock:
            last_status = self._last_status or {}
        status_str = last_status.get("status")
        if self.show:
            self._emit("EVENT_POTFILE_HASH_SHOW")
        if status_str == "Cracked":
            self._emit("EVENT_CRACKER_HASH_CRACKED")
        if rc == 0:
            self._emit("EVENT_CRACKER_FINISHED")
            self._emit("EVENT_OUTERLOOP_FINISHED")
        else:
            self._emit("EVENT_LOG_ERROR")

    def hashcat_session_execute(self):
        if self.usage:
            try:
                self._usage_output = subprocess.check_output(
                    [self._bin, "--help"],
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                return 0
            except subprocess.CalledProcessError as err:
                self._usage_output = err.output
                return -1

        args = self._build_args()
        logger.debug("Executing hashcat: %s", " ".join(args))
        # Use a PTY so hashcat emits status output (it often suppresses
        # periodic status updates when stdout is not a TTY).
        self._pty_master, pty_slave = pty.openpty()
        self._proc = subprocess.Popen(
            args,
            stdin=pty_slave,
            stdout=pty_slave,
            stderr=pty_slave,
            close_fds=True,
        )
        try:
            os.close(pty_slave)
        except OSError:
            pass
        self._stdout_thread = threading.Thread(target=self._stdout_reader, daemon=True)
        self._watch_thread = threading.Thread(target=self._watcher, daemon=True)
        self._stdout_thread.start()
        self._watch_thread.start()
        return 0

    def _send_control(self, ch):
        if not self._proc or self._proc.poll() is not None:
            return
        try:
            self._proc.stdin.write(ch)
            self._proc.stdin.flush()
        except Exception:
            pass

    def hashcat_session_quit(self):
        self._send_control("q")
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def hashcat_session_pause(self):
        self._send_control("p")

    def hashcat_session_resume(self):
        self._send_control("r")

    def hashcat_status_get_status(self):
        with self._status_lock:
            status = self._last_status
        if not status:
            return -1
        return self._normalize_status(status)

    def status_get_status_string(self):
        with self._status_lock:
            status = self._last_status
        if self.speed_only and status:
            return "Bypass"
        if status and "status" in status:
            # Hashcat JSON may provide numeric status plus status_name.
            stat_val = status.get("status")
            if isinstance(stat_val, int):
                if "status_name" in status:
                    return status["status_name"]
                return _STATUS_MAP.get(stat_val, str(stat_val))
            return status["status"]
        if self._proc and self._proc.poll() is None:
            return "Initializing"
        if self._proc and self._proc.poll() == 0:
            return "Exhausted"
        if self._proc and self._proc.poll() is not None:
            return "Aborted"
        return None

    def status_get_hashes_msec_all(self):
        with self._status_lock:
            status = self._last_status or {}
        speed_hps = self._get_speed_hps(status)
        return speed_hps / 1000.0

    def status_get_salts_cnt(self):
        with self._status_lock:
            status = self._last_status or {}
        return int(status.get("salts", 0))

    def status_get_digests_done(self):
        with self._status_lock:
            status = self._last_status or {}
        recovered = status.get("recovered_hashes")
        if isinstance(recovered, (list, tuple)) and recovered:
            return int(recovered[0])
        return int(status.get("digests_done", 0))

    def status_get_digests_cnt(self):
        with self._status_lock:
            status = self._last_status or {}
        recovered = status.get("recovered_hashes")
        if isinstance(recovered, (list, tuple)) and len(recovered) > 1:
            return int(recovered[1])
        progress = status.get("progress")
        if isinstance(progress, (list, tuple)) and len(progress) > 1:
            return int(progress[1])
        return int(status.get("digests_cnt", 0))

    def hashcat_status_get_log(self):
        with self._status_lock:
            return self._last_log or ""

    def status_reset(self):
        with self._status_lock:
            self._last_status = None

    def reset(self):
        self.hashcat_session_quit()
        self.status_reset()

    def hashcat_list_hashmodes(self):
        output = ""
        tmp_path = "/tmp/hashcat_example_hashes.txt"
        try:
            with open(tmp_path, "w") as fh_out:
                subprocess.run(
                    [self._bin, "--example-hashes"],
                    stdout=fh_out,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
            with open(tmp_path, "r") as fh_in:
                output = fh_in.read()
        except Exception as err:
            logger.debug("Failed to capture example hashes output: %s", err)

        modes = {}
        current_id = None
        current_name = None
        current_category = None
        for line in output.splitlines():
            header = _HASHMODE_HEADER_RE.match(line)
            if header:
                if current_id and current_name and current_category:
                    modes[current_id] = [current_name, current_category, 0.0]
                current_id = header.group(1)
                current_name = None
                current_category = None
                continue
            if current_id:
                name_match = _HASHMODE_NAME_RE.match(line)
                if name_match:
                    current_name = name_match.group(1).strip()
                    continue
                cat_match = _HASHMODE_CATEGORY_RE.match(line)
                if cat_match:
                    current_category = cat_match.group(1).strip()
                    continue
        if current_id and current_name and current_category:
            modes[current_id] = [current_name, current_category, 0.0]
        return modes

    def _normalize_status(self, status):
        speed_hps = self._get_speed_hps(status)
        progress = status.get("progress")
        progress_pct = 0
        if isinstance(progress, (list, tuple)) and len(progress) > 1 and progress[1]:
            try:
                progress_pct = int((progress[0] / progress[1]) * 100)
            except Exception:
                progress_pct = 0
        norm = {
            "Speed Raw": int(speed_hps),
            "Speed All": "{} H/s".format(int(speed_hps)),
            "Restore Point": int(status.get("restore_point", 0)),
            "Progress": progress_pct,
        }
        return norm

    def _get_speed_hps(self, status):
        speed = status.get("speed")
        if isinstance(speed, (int, float)):
            return float(speed)
        total = 0.0
        if isinstance(speed, list):
            for item in speed:
                if isinstance(item, dict) and "speed" in item:
                    try:
                        total += float(item["speed"])
                    except Exception:
                        continue
                elif isinstance(item, (list, tuple)) and item:
                    try:
                        total += float(item[0])
                    except Exception:
                        continue
        return total

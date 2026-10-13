"""Android Emulator and ADB Execution Runner for SpyAware-Analyzer.

Safely manages headless emulator lifecycle, boot synchronization, APK installation,
activity launching, logcat dumping, and cleanup using argument arrays and timeouts.
"""

import fcntl
import logging
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

BOOT_TIMEOUT_SECONDS = 90
INSTALL_TIMEOUT_SECONDS = 30
EXECUTION_TIMEOUT_SECONDS = 60
CLEANUP_TIMEOUT_SECONDS = 30

EMULATOR_MIN_PORT = 5554
EMULATOR_MAX_PORT = 5584

_PORT_RESERVATIONS_LOCK = threading.RLock()
_ACTIVE_PORT_RESERVATIONS: Set[int] = set()

_AVD_LOCKS_LOCK = threading.RLock()
_ACTIVE_AVD_RUNS: Set[str] = set()


class AVDLock:
    """Manages cross-thread and cross-process locking for Android Virtual Device instances."""

    def __init__(self, avd_name: str):
        self.avd_name = avd_name
        self._file_fd = None
        self._acquired = False

    def acquire(self, timeout: float = 0.0) -> bool:
        start_time = time.time()
        while True:
            acquired = False
            with _AVD_LOCKS_LOCK:
                if self.avd_name not in _ACTIVE_AVD_RUNS:
                    _ACTIVE_AVD_RUNS.add(self.avd_name)
                    acquired = True

            if acquired:
                try:
                    lock_path = Path(tempfile.gettempdir()) / f"spyaware_avd_{self.avd_name}.lock"
                    self._file_fd = open(lock_path, "w")
                    fcntl.flock(self._file_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._acquired = True
                    return True
                except (BlockingIOError, OSError):
                    with _AVD_LOCKS_LOCK:
                        _ACTIVE_AVD_RUNS.discard(self.avd_name)
                    if self._file_fd:
                        try:
                            self._file_fd.close()
                        except Exception:
                            pass
                        self._file_fd = None

            if timeout <= 0 or (time.time() - start_time) >= timeout:
                return False
            time.sleep(0.05)

    def release(self) -> None:
        if self._file_fd:
            try:
                fcntl.flock(self._file_fd, fcntl.LOCK_UN)
                self._file_fd.close()
            except Exception:
                pass
            self._file_fd = None
        with _AVD_LOCKS_LOCK:
            _ACTIVE_AVD_RUNS.discard(self.avd_name)
        self._acquired = False

    @property
    def acquired(self) -> bool:
        return self._acquired

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


class DynamicRunner:
    """Controls adb operations and Android emulator execution safely."""

    def __init__(
        self,
        boot_timeout: Optional[int] = None,
        install_timeout: int = INSTALL_TIMEOUT_SECONDS,
        execution_timeout: int = EXECUTION_TIMEOUT_SECONDS,
        cleanup_timeout: int = CLEANUP_TIMEOUT_SECONDS,
    ):
        if boot_timeout is None:
            env_val = os.environ.get("SPYAWARE_BOOT_TIMEOUT")
            self.boot_timeout = int(env_val) if env_val else BOOT_TIMEOUT_SECONDS
        else:
            self.boot_timeout = boot_timeout
        self.install_timeout = install_timeout
        self.execution_timeout = execution_timeout
        self.cleanup_timeout = cleanup_timeout

    @staticmethod
    def is_port_in_use(port: int) -> bool:
        """Checks whether a TCP port is currently occupied or bound on localhost."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return False
        except OSError:
            return True

    def get_device_states(self, adb_path: str) -> Dict[str, str]:
        """Returns mapping of device serial to ADB status (e.g. 'device', 'offline', 'unauthorized')."""
        if not adb_path:
            return {}
        states: Dict[str, str] = {}
        try:
            res = subprocess.run(
                [adb_path, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("List of devices"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    states[parts[0]] = parts[1]
                elif len(parts) == 1:
                    states[parts[0]] = "unknown"
        except (subprocess.SubprocessError, OSError):
            pass
        return states

    def get_device_state(self, adb_path: str, device_id: str) -> Optional[str]:
        """Returns the specific ADB state of a device serial ('device', 'offline', 'unauthorized', or None)."""
        states = self.get_device_states(adb_path)
        return states.get(device_id)

    def get_device_avd_name(self, adb_path: str, device_id: str) -> Optional[str]:
        """Queries the AVD name of an active emulator serial."""
        if not device_id or not device_id.startswith("emulator-"):
            return None

        # 1. Primary: adb emu avd name
        try:
            res = subprocess.run(
                [adb_path, "-s", device_id, "emu", "avd", "name"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                for line in res.stdout.splitlines():
                    cleaned = line.strip()
                    if cleaned and cleaned != "OK" and not cleaned.startswith("Android Console:"):
                        return cleaned
        except (subprocess.SubprocessError, OSError):
            pass

        # 2. Secondary: getprop ro.boot.qemu.avd_name
        try:
            res = subprocess.run(
                [adb_path, "-s", device_id, "shell", "getprop", "ro.boot.qemu.avd_name"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            pass

        # 3. Tertiary: getprop ro.kernel.qemu.avd_name
        try:
            res = subprocess.run(
                [adb_path, "-s", device_id, "shell", "getprop", "ro.kernel.qemu.avd_name"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except (subprocess.SubprocessError, OSError):
            pass

        # 4. Direct console socket query fallback (useful if device is offline in adb)
        try:
            port_str = device_id.split("-")[1]
            port = int(port_str)
            token = None
            token_path = Path.home() / ".emulator_console_auth_token"
            if token_path.exists():
                token = token_path.read_text(encoding="utf-8").strip()

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(("127.0.0.1", port))
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                if "Authentication required" in banner and token:
                    s.sendall(f"auth {token}\n".encode("utf-8"))
                    _ = s.recv(1024).decode("utf-8", errors="ignore")
                s.sendall(b"avd name\nquit\n")
                resp = b""
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
                resp_text = resp.decode("utf-8", errors="ignore")
                for line in resp_text.splitlines():
                    cleaned = line.strip()
                    if cleaned and cleaned != "OK" and not cleaned.startswith("Android Console:") and not cleaned.startswith("auth "):
                        return cleaned
        except Exception:
            pass

        return None

    def find_running_avd(self, adb_path: str, avd_name: str) -> Optional[str]:
        """Finds any connected emulator currently running the specified AVD name."""
        if not avd_name:
            return None
        serials = self.get_all_device_serials(adb_path)
        for serial in serials:
            if serial.startswith("emulator-"):
                running_avd = self.get_device_avd_name(adb_path, serial)
                if running_avd == avd_name:
                    return serial
        return None

    def is_device_booted(self, adb_path: str, device_id: str) -> bool:
        """Verifies if a specific device has completed Android OS boot and package manager is responsive."""
        base_cmd = [adb_path, "-s", device_id]
        try:
            res = subprocess.run(
                base_cmd + ["shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip() == "1":
                pm_res = subprocess.run(
                    base_cmd + ["shell", "pm", "path", "android"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                return pm_res.returncode == 0 and "package:" in pm_res.stdout
        except (subprocess.SubprocessError, OSError):
            pass
        return False

    def get_online_devices(self, adb_path: str) -> List[str]:
        """Returns all currently online device serials (in 'device' state)."""
        devices: List[str] = []
        try:
            res = subprocess.run(
                [adb_path, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "device":
                    devices.append(parts[0])
        except (subprocess.SubprocessError, OSError):
            pass
        return devices

    def get_all_device_serials(self, adb_path: str) -> List[str]:
        """Returns all device serials reported by adb devices regardless of state."""
        serials: List[str] = []
        try:
            res = subprocess.run(
                [adb_path, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith("List of devices"):
                    continue
                parts = line.split()
                if parts:
                    serials.append(parts[0])
        except (subprocess.SubprocessError, OSError):
            pass
        return serials

    def get_first_online_device(self, adb_path: str, prefer_emulator: bool = True) -> Optional[str]:
        """Finds an already booted and available device/emulator, prioritizing emulators."""
        devices = self.get_online_devices(adb_path)
        if not devices:
            return None
        if prefer_emulator:
            for d in devices:
                if d.startswith("emulator-"):
                    return d
        return devices[0]

    def reserve_emulator_port(self, adb_path: str) -> int:
        """Allocates and reserves an available emulator console port (even number between 5554 and 5584)."""
        with _PORT_RESERVATIONS_LOCK:
            adb_serials = set(self.get_all_device_serials(adb_path))
            for port in range(EMULATOR_MIN_PORT, EMULATOR_MAX_PORT + 2, 2):
                if port in _ACTIVE_PORT_RESERVATIONS:
                    continue
                if f"emulator-{port}" in adb_serials:
                    continue
                # Check both console port and adb port (port + 1)
                if self.is_port_in_use(port) or self.is_port_in_use(port + 1):
                    continue
                _ACTIVE_PORT_RESERVATIONS.add(port)
                return port
            raise RuntimeError(f"No available emulator ports in range {EMULATOR_MIN_PORT}-{EMULATOR_MAX_PORT}")

    def release_port_reservation(self, port: int) -> None:
        """Releases a reserved emulator console port."""
        with _PORT_RESERVATIONS_LOCK:
            _ACTIVE_PORT_RESERVATIONS.discard(port)

    def get_next_available_emulator_port(self, adb_path: str) -> int:
        """Convenience alias for reserve_emulator_port."""
        return self.reserve_emulator_port(adb_path)

    def get_device_supported_abis(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> List[str]:
        """Queries supported ABIs of connected device/emulator via getprop."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        abis: List[str] = []
        try:
            # 1. Primary: ro.product.cpu.abilist (comma-separated list)
            res = subprocess.run(
                base_cmd + ["shell", "getprop", "ro.product.cpu.abilist"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                for item in res.stdout.strip().split(","):
                    abi = item.strip()
                    if abi and abi not in abis:
                        abis.append(abi)

            # 2. Check 64-bit and 32-bit abilists if still empty
            if not abis:
                for prop in ["ro.product.cpu.abilist64", "ro.product.cpu.abilist32", "ro.system.product.cpu.abilist"]:
                    r = subprocess.run(
                        base_cmd + ["shell", "getprop", prop],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if r.returncode == 0 and r.stdout.strip():
                        for item in r.stdout.strip().split(","):
                            abi = item.strip()
                            if abi and abi not in abis:
                                abis.append(abi)

            # 3. Fallback: ro.product.cpu.abi and abi2
            if not abis:
                for prop in ["ro.product.cpu.abi", "ro.product.cpu.abi2"]:
                    r = subprocess.run(
                        base_cmd + ["shell", "getprop", prop],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if r.returncode == 0 and r.stdout.strip():
                        abi = r.stdout.strip()
                        if abi and abi not in abis:
                            abis.append(abi)
        except (subprocess.SubprocessError, OSError):
            pass

        return abis

    def get_device_sdk_version(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> Optional[int]:
        """Queries the Android API level (ro.build.version.sdk) of connected device/emulator."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])
        try:
            res = subprocess.run(
                base_cmd + ["shell", "getprop", "ro.build.version.sdk"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip().isdigit():
                return int(res.stdout.strip())
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def start_emulator(
        self,
        emulator_path: str,
        avd_name: str,
        port: Optional[int] = None,
    ) -> subprocess.Popen:
        """Launches the configured AVD in headless mode without UI or audio."""
        cmd = [
            emulator_path,
            "-avd",
            avd_name,
        ]
        if port is not None:
            cmd.extend(["-port", str(port)])
        cmd.extend([
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-no-snapshot-load",
            "-gpu",
            "swiftshader_indirect",
            "-accel",
            "on",
            "-netdelay",
            "none",
            "-netspeed",
            "full",
        ])
        # Start detached in background
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
        )
        return proc

    def wait_for_boot(
        self,
        adb_path: str,
        device_id: Optional[str] = None,
        emulator_proc: Optional[subprocess.Popen] = None,
        timeout: Optional[int] = None,
    ) -> bool:
        """Polls adb until Android OS signals boot completion and package manager is active."""
        boot_timeout = timeout if timeout is not None else self.boot_timeout
        start_time = time.time()
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        last_state = "unknown"
        last_log_time = 0.0

        while time.time() - start_time < boot_timeout:
            elapsed = round(time.time() - start_time, 1)

            # Abort early if the spawned emulator process exited prematurely
            if emulator_proc is not None and isinstance(emulator_proc.poll(), int):
                logger.warning(
                    "Emulator process for %s exited prematurely with return code %s after %.1fs (last state: %s)",
                    device_id or "default",
                    emulator_proc.poll(),
                    elapsed,
                    last_state,
                )
                return False

            try:
                # 1. Check getprop sys.boot_completed
                res = subprocess.run(
                    base_cmd + ["shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )

                err_text = (res.stderr or "").strip().lower()
                out_text = (res.stdout or "").strip()

                if "device not found" in err_text:
                    current_state = "not_found"
                elif "offline" in err_text:
                    current_state = "offline"
                elif "unauthorized" in err_text:
                    current_state = "unauthorized"
                elif res.returncode == 0:
                    current_state = "device"
                else:
                    current_state = "unknown"

                if current_state != last_state or (time.time() - last_log_time) >= 15.0:
                    logger.info(
                        "Polling boot on %s: state=%s, elapsed=%.1fs / %ss",
                        device_id or "default",
                        current_state,
                        elapsed,
                        boot_timeout,
                    )
                    last_state = current_state
                    last_log_time = time.time()

                if current_state == "device" and out_text == "1":
                    # 2. Check if Package Manager service is responsive
                    pm_res = subprocess.run(
                        base_cmd + ["shell", "pm", "path", "android"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if pm_res.returncode == 0 and "package:" in pm_res.stdout:
                        logger.info(
                            "Device %s boot completed successfully in %.1fs (state=%s)",
                            device_id or "default",
                            elapsed,
                            current_state,
                        )
                        return True
            except (subprocess.SubprocessError, OSError) as e:
                logger.debug("Exception while polling boot on %s: %s", device_id, e)

            time.sleep(2)

        elapsed = round(time.time() - start_time, 1)
        logger.warning(
            "Boot timeout exceeded for device %s after %.1fs (timeout=%ss). Last observed device state: %s",
            device_id or "default",
            elapsed,
            boot_timeout,
            last_state,
        )
        return False

    def clear_logcat(self, adb_path: str, device_id: Optional[str] = None) -> None:
        """Clears existing logcat buffer prior to test execution."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])
        try:
            subprocess.run(
                base_cmd + ["logcat", "-c"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            pass

    def install_apk(
        self, adb_path: str, apk_path: str, device_id: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Installs the APK granting runtime permissions (-g flag)."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        cmd = base_cmd + ["install", "-r", "-g", apk_path]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.install_timeout,
                check=False,
            )
            output = res.stdout + res.stderr
            success = "Success" in output
            if not success and "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in output:
                # Android 14+ emulators require bypass flag for legacy targetSdk APKs
                bypass_cmd = base_cmd + ["install", "--bypass-low-target-sdk-block", "-r", "-g", apk_path]
                res_bypass = subprocess.run(
                    bypass_cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.install_timeout,
                    check=False,
                )
                output_bypass = res_bypass.stdout + res_bypass.stderr
                if "Success" in output_bypass:
                    return True, output_bypass.strip()
                return False, output_bypass.strip()
            return success, output.strip()
        except subprocess.TimeoutExpired:
            return False, f"APK installation timed out after {self.install_timeout}s"
        except (subprocess.SubprocessError, OSError) as e:
            return False, str(e)

    def launch_activity(
        self,
        adb_path: str,
        package_name: str,
        activity_name: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Dispatches an am start or monkey launch command to start the application."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        if activity_name:
            # Form activity component name: if activity does not start with '.', handle prefix
            comp = activity_name if "/" in activity_name else f"{package_name}/{activity_name}"
            cmd = base_cmd + ["shell", "am", "start", "-n", comp]
        else:
            # Launch via monkey tool targeting launcher category
            cmd = base_cmd + [
                "shell",
                "monkey",
                "-p",
                package_name,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            output = res.stdout + res.stderr
            # Check for error signals
            failed = "Error:" in output or "does not exist" in output or "No activities found" in output
            return not failed, output.strip()
        except (subprocess.SubprocessError, OSError) as e:
            return False, str(e)

    def dump_logcat(
        self, adb_path: str, device_id: Optional[str] = None, max_lines: int = 1500
    ) -> Optional[str]:
        """Captures recent logcat entries."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["logcat", "-d", "-v", "time"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res.returncode != 0:
                return None
            lines = res.stdout.splitlines()
            if len(lines) > max_lines:
                return "\n".join(lines[-max_lines:])
            return res.stdout
        except (subprocess.SubprocessError, OSError):
            return None

    def dump_services(
        self, adb_path: str, package_name: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Inspects dumpsys activity services for the package."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "activity", "services", package_name],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode != 0:
                return None
            return res.stdout
        except (subprocess.SubprocessError, OSError):
            return None

    def dump_processes(
        self, adb_path: str, package_name: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Captures running process listings."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "ps", "-A"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode != 0:
                return None
            return "\n".join([l for l in res.stdout.splitlines() if package_name in l])
        except (subprocess.SubprocessError, OSError):
            return None

    def get_package_pids(
        self, adb_path: str, package_name: str, device_id: Optional[str] = None
    ) -> List[str]:
        """Queries running process IDs belonging to the specified package."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        pids: List[str] = []
        try:
            # 1. Try pidof
            res = subprocess.run(
                base_cmd + ["shell", "pidof", package_name],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                for p in res.stdout.strip().split():
                    if p.isdigit():
                        pids.append(p)
                if pids:
                    return pids

            # 2. Fallback to parsing ps -A
            ps_text = self.dump_processes(adb_path, package_name, device_id)
            if ps_text:
                for line in ps_text.splitlines():
                    if package_name in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            pids.append(parts[1])
            return pids
        except (subprocess.SubprocessError, OSError):
            return []

    def dump_camera_service(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Inspects dumpsys media.camera / camera for active camera clients."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "media.camera"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            # Fallback to dumpsys camera
            res_cam = subprocess.run(
                base_cmd + ["shell", "dumpsys", "camera"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res_cam.returncode == 0:
                return res_cam.stdout
            return None
        except (subprocess.SubprocessError, OSError):
            return None

    def dump_audio_service(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Inspects dumpsys audio for active recording clients or players."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "audio"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except (subprocess.SubprocessError, OSError):
            return None

    def dump_location_service(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Inspects dumpsys location for active requests and provider registrations."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "location"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except (subprocess.SubprocessError, OSError):
            return None

    def dump_accessibility_service(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Inspects dumpsys accessibility for enabled and bound services."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "accessibility"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except (subprocess.SubprocessError, OSError):
            return None

    def dump_media_projection_service(
        self, adb_path: str, device_id: Optional[str] = None
    ) -> Optional[str]:
        """Inspects dumpsys media_projection for active projection sessions."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            res = subprocess.run(
                base_cmd + ["shell", "dumpsys", "media_projection"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout
            return None
        except (subprocess.SubprocessError, OSError):
            return None

    def force_stop(
        self, adb_path: str, package_name: str, device_id: Optional[str] = None
    ) -> None:
        """Stops the target app process."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            subprocess.run(
                base_cmd + ["shell", "am", "force-stop", package_name],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            pass

    def uninstall_apk(
        self, adb_path: str, package_name: str, device_id: Optional[str] = None
    ) -> None:
        """Removes the package from the device."""
        base_cmd = [adb_path]
        if device_id:
            base_cmd.extend(["-s", device_id])

        try:
            subprocess.run(
                base_cmd + ["uninstall", package_name],
                capture_output=True,
                timeout=self.cleanup_timeout,
                check=False,
            )
        except (subprocess.SubprocessError, OSError):
            pass

    def stop_emulator(
        self,
        emulator_proc: Optional[subprocess.Popen] = None,
        adb_path: Optional[str] = None,
        device_id: Optional[str] = None,
        port: Optional[int] = None,
    ) -> None:
        """Safely stops an emulator process if it was started by this analysis."""
        if port is None and device_id and device_id.startswith("emulator-"):
            try:
                port = int(device_id.split("-")[1])
            except (IndexError, ValueError):
                pass

        if adb_path and device_id and device_id.startswith("emulator-"):
            try:
                subprocess.run(
                    [adb_path, "-s", device_id, "emu", "kill"],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            except (subprocess.SubprocessError, OSError):
                pass

        if emulator_proc and emulator_proc.poll() is None:
            try:
                emulator_proc.terminate()
                emulator_proc.wait(timeout=5)
            except Exception:
                try:
                    emulator_proc.kill()
                    emulator_proc.wait(timeout=5)
                except Exception:
                    pass

        if port is not None:
            self.release_port_reservation(port)

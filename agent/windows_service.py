"""Native Windows Service host for the ULPF Agent.

Dependency-free: uses only Python's standard library and the Windows Service
Control Manager API through ctypes. This keeps the agent fully offline and
avoids requiring pywin32 on the target machine.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import os
import sys
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import Agent, load_config  # noqa: E402

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_START_PENDING = 0x00000002
SERVICE_RUNNING = 0x00000004
SERVICE_STOP_PENDING = 0x00000003
SERVICE_STOPPED = 0x00000001
SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004
NO_ERROR = 0
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063

SERVICE_NAME = "ULPFAgent"

class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]

ADVAPI32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
KERNEL32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)

SERVICE_STATUS_HANDLE = wintypes.HANDLE
HANDLER_FUNCTION_EX = ctypes.WINFUNCTYPE(
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID
)
SERVICE_MAIN_FUNCTION = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))

ADVAPI32.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, HANDLER_FUNCTION_EX, wintypes.LPVOID]
ADVAPI32.RegisterServiceCtrlHandlerExW.restype = SERVICE_STATUS_HANDLE
ADVAPI32.SetServiceStatus.argtypes = [SERVICE_STATUS_HANDLE, ctypes.POINTER(SERVICE_STATUS)]
ADVAPI32.SetServiceStatus.restype = wintypes.BOOL
ADVAPI32.StartServiceCtrlDispatcherW.argtypes = [ctypes.c_void_p]
ADVAPI32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL

# SERVICE_TABLE_ENTRYW is declared here after SERVICE_MAIN_FUNCTION.
class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN_FUNCTION)]

stop_event = threading.Event()
service_status_handle = None
agent_instance = None


def set_status(state, exit_code=NO_ERROR, wait_hint=0):
    if not service_status_handle:
        return
    accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if state == SERVICE_RUNNING else 0
    status = SERVICE_STATUS(
        SERVICE_WIN32_OWN_PROCESS,
        state,
        accepted,
        exit_code,
        0,
        0,
        wait_hint,
    )
    ADVAPI32.SetServiceStatus(service_status_handle, ctypes.byref(status))


@HANDLER_FUNCTION_EX
def service_handler(control, event_type, event_data, context):
    if control in (0x00000001, 0x00000005):  # STOP / SHUTDOWN
        stop_event.set()
        if agent_instance is not None:
            agent_instance.stop.set()
        return NO_ERROR
    return NO_ERROR


@SERVICE_MAIN_FUNCTION
def service_main(argc, argv):
    global service_status_handle, agent_instance
    service_status_handle = ADVAPI32.RegisterServiceCtrlHandlerExW(
        SERVICE_NAME, service_handler, None
    )
    if not service_status_handle:
        return

    set_status(SERVICE_START_PENDING, wait_hint=10000)
    config_path = os.environ.get("ULPF_AGENT_CONFIG", str(Path(r"C:\ProgramData\ULPF-Agent\agent.yaml")))

    try:
        cfg = load_config(config_path)
        agent_instance = Agent(cfg)
        set_status(SERVICE_RUNNING)
        # Agent.run() owns the worker threads and blocks until interrupted.
        # For SCM stop, the handler sets Agent.stop; we wait here and then
        # allow worker threads to finish and close the spool cleanly.
        agent_instance.register()
        threads = [
            threading.Thread(target=agent_instance.file_loop, daemon=True),
            threading.Thread(target=agent_instance.journal_loop, daemon=True),
            threading.Thread(target=agent_instance.windows_loop, daemon=True),
            threading.Thread(target=agent_instance.send_loop, daemon=True),
            threading.Thread(target=agent_instance.heartbeat_loop, daemon=True),
        ]
        for thread in threads:
            thread.start()
        while not stop_event.wait(1.0):
            pass
        agent_instance.stop.set()
        set_status(SERVICE_STOP_PENDING, wait_hint=5000)
        agent_instance.save_offsets()
        agent_instance.spool.close()
        set_status(SERVICE_STOPPED)
    except Exception:
        try:
            traceback.print_exc()
            set_status(SERVICE_STOPPED, exit_code=1)
        except Exception:
            pass


def run_console(config_path):
    cfg = load_config(config_path)
    Agent(cfg).run()


def main():
    parser = argparse.ArgumentParser(description="ULPF native Windows Service host")
    parser.add_argument("--config", default=os.environ.get("ULPF_AGENT_CONFIG", r"C:\ProgramData\ULPF-Agent\agent.yaml"))
    parser.add_argument("--console", action="store_true", help="run without Windows Service Control Manager")
    args = parser.parse_args()

    if args.console:
        run_console(args.config)
        return 0

    service_main_proc = SERVICE_MAIN_FUNCTION(service_main)
    table = (SERVICE_TABLE_ENTRY * 2)()
    table[0].lpServiceName = SERVICE_NAME
    table[0].lpServiceProc = service_main_proc
    table[1].lpServiceName = None
    table[1].lpServiceProc = SERVICE_MAIN_FUNCTION()

    ok = ADVAPI32.StartServiceCtrlDispatcherW(ctypes.byref(table))
    if not ok:
        error = ctypes.get_last_error()
        if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            print("ULPF Agent is not running under the Windows Service Control Manager.")
            print("Use --console for a manual test.")
            return 2
        raise ctypes.WinError(error)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

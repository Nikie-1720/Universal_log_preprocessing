import os
import sys
import threading
import traceback

import win32event
import win32service
import win32serviceutil
import servicemanager


CONFIG_PATH = r"C:\ProgramData\ULPF-Agent\agent.yaml"


class ULPFWindowsService(win32serviceutil.ServiceFramework):

    _svc_name_ = "ULPFAgent"
    _svc_display_name_ = "ULPF Collector Agent"
    _svc_description_ = "Universal Log Pre-processing Framework Collector Agent"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)

        self.stop_event = win32event.CreateEvent(
            None,
            0,
            0,
            None
        )

        self.worker = None
        self.running = False

    def SvcStop(self):

        servicemanager.LogInfoMsg(
            "ULPF Agent stop requested."
        )

        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING
        )

        self.running = False

        win32event.SetEvent(
            self.stop_event
        )

    def SvcDoRun(self):

        servicemanager.LogInfoMsg(
            "ULPF Agent service starting."
        )

        # IMPORTANT:
        # Set this before starting the worker.
        self.running = True

        self.ReportServiceStatus(
            win32service.SERVICE_RUNNING
        )

        self.worker = threading.Thread(
            target=self.run_agent,
            name="ULPF-Agent-Worker",
            daemon=True
        )

        self.worker.start()

        while self.running:

            result = win32event.WaitForSingleObject(
                self.stop_event,
                1000
            )

            if result == win32event.WAIT_OBJECT_0:
                break

        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING
        )

        if self.worker and self.worker.is_alive():

            self.worker.join(
                timeout=10
            )

        servicemanager.LogInfoMsg(
            "ULPF Agent service stopped."
        )

    def run_agent(self):

        try:

            # Project root:
            # C:\Program Files\ULPF-Agent
            project_root = os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )

            if project_root not in sys.path:
                sys.path.insert(
                    0,
                    project_root
                )

            from agent.agent import Agent, load_config

            servicemanager.LogInfoMsg(
                "Loading ULPF Agent configuration: "
                + CONFIG_PATH
            )

            if not os.path.exists(CONFIG_PATH):

                raise FileNotFoundError(
                    "ULPF configuration not found: "
                    + CONFIG_PATH
                )

            # Agent expects a CONFIG DICTIONARY,
            # not the config file path.
            cfg = load_config(CONFIG_PATH)

            servicemanager.LogInfoMsg(
                "ULPF configuration loaded successfully."
            )

            agent = Agent(cfg)

            servicemanager.LogInfoMsg(
                "ULPF Agent initialized successfully."
            )

            agent.run()

        except Exception as exc:

            self.running = False

            error_text = (
                "ULPF Agent crashed: "
                + repr(exc)
                + "\n"
                + traceback.format_exc()
            )

            servicemanager.LogErrorMsg(
                error_text
            )

    if __name__ == "__main__":
        pass


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(
        ULPFWindowsService
    )
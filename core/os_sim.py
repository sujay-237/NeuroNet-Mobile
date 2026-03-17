import threading
import time

class Sandbox:
    def __init__(self):
        self.lock = threading.Lock()

    def run_in_sandbox(self, payload):
        """
        Spawns a new thread to process the request, simulating
        OS process isolation to prevent main thread blocking.
        """
        t = threading.Thread(target=self._process_safe, args=(payload,))
        t.start()
        # We don't join() here to show asynchronous handling capability

    def _process_safe(self, payload):
        with self.lock:
            # Simulate checking file permissions
            # If the attacker tries to use "cat /etc/passwd", we trap it here.
            if "/etc/passwd" in payload or "cmd.exe" in payload:
                print(f"[OS KERNEL] BLOCKED: Malicious syscall detected in payload.")
            else:
                # Simulate processing time
                time.sleep(0.1)
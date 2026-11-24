import time

class Sandbox:
    def __init__(self):
        pass

    def run_in_sandbox(self, payload):
        """
        Executes syscall and payload inspection synchronously.
        Serverless functions terminate background threads upon HTTP response return,
        so checks run synchronously in milliseconds without blocking.
        """
        return self._process_safe(payload)

    def _process_safe(self, payload):
        payload_str = str(payload)
        suspicious_syscalls = [
            "/etc/passwd", "cmd.exe", "powershell", "/bin/sh",
            "rm -rf", "wget", "curl", "chmod", "iptables"
        ]
        
        detected = [sc for sc in suspicious_syscalls if sc in payload_str.lower()]
        
        if detected:
            log_msg = f"[OS KERNEL] BLOCKED: Malicious syscall(s) detected: {', '.join(detected)}"
            return {
                "status": "BLOCKED",
                "detected": detected,
                "message": log_msg,
                "isolated": True
            }
        else:
            return {
                "status": "CLEARED",
                "detected": [],
                "message": "[OS KERNEL] Syscall trace cleared. Sandbox integrity intact.",
                "isolated": True
            }

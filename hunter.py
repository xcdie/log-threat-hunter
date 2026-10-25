import os
import re
import sys
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


THREAT_SIGNATURES = {
    "SQL Injection (SQLi)": re.compile(
        r"(UNION\s+SELECT|SELECT\s+.*\s+FROM|'--|(--)|'OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", 
        re.IGNORECASE
    ),
    "Path Traversal / LFI": re.compile(
        r"(\.\.\/|\.\.\\|/etc/passwd|/boot\.ini|win\.ini)", 
        re.IGNORECASE
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(<script>|javascript:|onerror\s*=|alert\()", 
        re.IGNORECASE
    ),
    "Suspicious Executable Execution": re.compile(
        r"(/bin/sh|/bin/bash|cmd\.exe|powershell\.exe|whoami|id)", 
        re.IGNORECASE
    )
}

class LogSecurityHandler(FileSystemEventHandler):
    def __init__(self, target_log_file):
        self.target_log_file = os.path.abspath(target_log_file)

        self.file = open(self.target_log_file, "r")
        self.file.seek(0, os.SEEK_END)
        print(f"[*] Threat Hunter active. Monitoring target matrix: {self.target_log_file}")

    def on_modified(self, event):
        # Trigger only if our monitored log file updates
        if os.path.abspath(event.src_path) == self.target_log_file:
            lines = self.file.readlines()
            for line in lines:
                self.analyze_log_line(line.strip())

    def analyze_log_line(self, log_entry: str):
        if not log_entry:
            return

        # Scan line against all known attack profiles
        for attack_name, signature in THREAT_SIGNATURES.items():
            if signature.search(log_entry):
                self.trigger_security_alert(attack_name, log_entry)

    def trigger_security_alert(self, attack_type: str, raw_log: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # ANSI Escape Sequences for terminal coloring (Red for alert)
        print(f"\n\033[91m[🚨 SECURITY ALERT] [{timestamp}]\033[0m")
        print(f"\033[93mType:\033[0m {attack_type}")
        print(f"\033[90mRaw Payload:\033[0m {raw_log}\n")

def start_hunter(log_path):
    # Ensure file exists before starting observer setup
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            f.write(f"# Log created on {datetime.now()}\n")

    event_handler = LogSecurityHandler(log_path)
    observer = Observer()
    # Watch the directory containing the file
    observer.schedule(event_handler, path=os.path.dirname(log_path) or ".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Shutting down Threat Hunter Engine.")
        event_handler.file.close()
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Monitor a dummy production log file locally inside the project folder
    target_log = "app_production.log"
    start_hunter(target_log)

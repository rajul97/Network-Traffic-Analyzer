import os

# Configuration
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "suspicious_activity.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

def log_suspicious_activity(message):
    """Logs detected suspicious activities to a file."""
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")
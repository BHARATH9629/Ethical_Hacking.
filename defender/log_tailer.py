"""
Tails the LocalStack container's logs and turns each API request line into a
normalized RequestEvent. LocalStack (with DEBUG=1) logs request lines like:

    2024-01-01T00:00:00.000  DEBUG --- [   Thread-1] localstack.request... : AWS s3.GetObject => 200
    ... "GET /bucket-name/key HTTP/1.1" 200 ...
    ... AWSAccessKeyId=AKIA... / Credential=AKIA.../...

Exact formats vary across LocalStack versions, so this parser uses several
tolerant regexes and only requires enough signal to identify (service, action,
access_key, resource). Rehearse against your installed LocalStack version and
adjust the patterns below if needed.
"""
import re
import subprocess
import threading
import time
from typing import Callable, Optional

from state import RequestEvent

SERVICE_ACTION_RE = re.compile(r"AWS\s+(?P<service>[a-z0-9]+)\.(?P<action>[A-Za-z0-9]+)")
ACCESS_KEY_RE = re.compile(r"(?:AWSAccessKeyId=|Credential=)(?P<key>[A-Z0-9_\-]{8,})")
AUTH_HEADER_RE = re.compile(r"Authorization:.*Credential=(?P<key>[A-Z0-9_\-]{8,})")
PATH_RE = re.compile(r'"[A-Z]+\s+/(?P<resource>[^\s?"]*)')
BYTES_RE = re.compile(r"Content-Length:\s*(?P<bytes>\d+)")


def parse_line(line: str) -> Optional[RequestEvent]:
    sa_match = SERVICE_ACTION_RE.search(line)
    if not sa_match:
        return None

    key_match = ACCESS_KEY_RE.search(line) or AUTH_HEADER_RE.search(line)
    path_match = PATH_RE.search(line)
    bytes_match = BYTES_RE.search(line)

    return RequestEvent(
        access_key=key_match.group("key") if key_match else None,
        service=sa_match.group("service"),
        action=sa_match.group("action"),
        resource=path_match.group("resource") if path_match else "",
        bytes=int(bytes_match.group("bytes")) if bytes_match else 0,
        timestamp=time.time(),
    )


def tail_container_logs(container_name: str, on_event: Callable[[RequestEvent], None], stop_flag: threading.Event):
    """Runs `docker logs -f <container>` and calls on_event for each parsed line.
    Retries if the container isn't up yet."""
    while not stop_flag.is_set():
        try:
            proc = subprocess.Popen(
                ["docker", "logs", "-f", "--tail", "0", container_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            print("[log_tailer] docker CLI not found; retrying in 5s")
            time.sleep(5)
            continue

        try:
            for line in proc.stdout:
                if stop_flag.is_set():
                    break
                event = parse_line(line)
                if event:
                    on_event(event)
        finally:
            proc.terminate()

        if not stop_flag.is_set():
            print("[log_tailer] log stream ended, retrying in 3s")
            time.sleep(3)


def start_tailer_thread(container_name: str, on_event: Callable[[RequestEvent], None]) -> threading.Event:
    stop_flag = threading.Event()
    t = threading.Thread(
        target=tail_container_logs, args=(container_name, on_event, stop_flag), daemon=True
    )
    t.start()
    return stop_flag

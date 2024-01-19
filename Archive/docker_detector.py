"""
Main structure of eBPF detector
- [ ] To detect all internal processes in the container.(Based on its ppid)
"""
from bcc import BPF
from bcc.utils import ArgString, printb
import ctypes as ct
from time import sleep, strftime
import sys
from datetime import datetime, timedelta
bpf=BPF(src_file="docker_detector.c")

def print_headers():
    print(
        "%-16s %-16s %-6s %-6s %-6s %-32s"
        % (
            "TIME",
            "COMM",
            "PID",
            "PPID",
            "TID",
            "FILENAME",
        )
    )

def print_event(cpu, data, size):
    # Merge and print data from the entry and exit
    event = bpf["events"].event(data)
    printb(b"%-6d %-16s %-6d %-6d %-6d %-32d"%(
        event.timestamp,
        event.comm,
        event.pid,
        event.ppid,
        event.tid,
        event.fd
    ))

bpf["events"].open_perf_buffer(print_event, page_cnt=128)
print_headers()


timer = 0  # For debug use, only execute the given seconds to save time
interval = 1  # Extract from the pipe with the given seconds
MAX_DURATION = timedelta(seconds=int(3))  # Max duration of the tracing
start_time = datetime.now()
while not MAX_DURATION or datetime.now() - start_time < MAX_DURATION:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
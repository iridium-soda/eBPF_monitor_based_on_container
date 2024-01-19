"""
To trace kfunc do_sys_openat2 and get the mnt space of the task
"""

from bcc import BPF
from bcc.utils import printb
from datetime import datetime, timedelta
import prettytable as pt
import os
import sys

with open("kfunc_openat2_get_ns.c") as f:
    kernel_code = f.read()

bpf = BPF(text=kernel_code)


def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    # NOTE: add a temp filter
    p.add_row(
        [
            event.timestamp,
            event.comm,
            event.pid,
            event.ppid,
            event.nsinum,
            event.vfsroot,
        ]
    )
    os.system("clear")
    sys.stdout.write("{0}".format(p))
    sys.stdout.flush()
    sys.stdout.write("\n")


# Initialize table header
p = pt.PrettyTable()
p.field_names = ["TIME", "COMM", "PID", "PPID", "MNT INUM", "VFSROOT"]

print("[!] Tracing openat2()... Hit Ctrl-C to end.")

bpf["events"].open_perf_buffer(print_event, page_cnt=128)
MAX_DURATION = timedelta(seconds=int(30))  # Max duration of the tracing
start_time = datetime.now()
while not MAX_DURATION or datetime.now() - start_time < MAX_DURATION:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

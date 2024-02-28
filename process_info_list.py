from bcc import BPF
from bcc.utils import printb
from datetime import datetime, timedelta
import prettytable as pt
import os
import sys

bpf=BPF(src="process_info_list.c")
# Initialize table header
p = pt.PrettyTable()
p.field_names = ["PID", "PPID", "PID INUM",  "CODE"]
def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    # NOTE: add a temp filter
    p.add_row([event.pid, event.ppid, event.pid_ns,  event.debugCode])
    os.system("clear")
    sys.stdout.write("{0}".format(p))
    sys.stdout.flush()
    sys.stdout.write("\n")




print("[!] Tracing syscall write()... Hit Ctrl-C to end.")

bpf["events"].open_perf_buffer(print_event, page_cnt=256)
MAX_DURATION = timedelta(seconds=int(30))  # Max duration of the tracing
start_time = datetime.now()
while not MAX_DURATION or datetime.now() - start_time < MAX_DURATION:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
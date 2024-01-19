"""
To trace kfunc sys_write behaviors by eBPF.
1. 完成对write系统调用的hook,拿到文件路径参数
2. 完成ppid filter,针对runc
3. 完成检查文件mnt namespace的办法(或者完全按照PACED做,用hash table存储)
4. 完成检测逻辑
"""

from bcc import BPF
from bcc.utils import printb
from datetime import datetime, timedelta

with open("kfunc_write_trace.c") as f:
    kernel_code = f.read()

bpf = BPF(text=kernel_code)


def print_headers():
    print(
        "%-18s %-16s %-6s %-6s %-6s %-18s"
        % ("TIME", "COMM", "PID", "PPID", "FD", "PATH")
    )


def print_event(cpu, data, size):
    event = bpf["events"].event(data)
    # NOTE: add a temp filter

    printb(
        b"%-18d %-16s %-6d %-6d %-6d %-18s"
        % (
            event.timestamp,
            event.comm,
            event.pid,
            event.ppid,
            event.fd,
            event.path,
        )
    )


bpf["events"].open_perf_buffer(print_event, page_cnt=128)
print_headers()
timer = 0  # For debug use, only execute the given seconds to save time
interval = 1  # Extract from the pipe with the given seconds
MAX_DURATION = timedelta(seconds=int(30))  # Max duration of the tracing
start_time = datetime.now()
while not MAX_DURATION or datetime.now() - start_time < MAX_DURATION:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

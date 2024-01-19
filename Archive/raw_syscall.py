"""
This is a demonstration script that traces the system calls of a given process.
It is a Python script based on bcc/BPF.
Usage: Run 'sudo python syscall_trace.py -p <pid>' in the terminal. If no -p assigned, stat all syscalls from the systemwide.
Note: Only trace read/write first for test.

"""

import argparse
import sys
from bcc import BPF, USDT, utils
from bcc.utils import printb
from time import sleep, strftime
import ctypes as ct
from bcc.syscall import syscall_name, syscalls

# Set and parse arguments
parser = argparse.ArgumentParser(description="Trace syscalls of a given process")
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")
args = parser.parse_args()


kernel_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
//#include <unistd.h>

struct data_t {
    u64 pid;
    char comm[80];
    char args[128];
    int retval;
    u64 timestamp;
    u64 syscall_id;//syscall_id, not name
    };
BPF_PERF_OUTPUT(syscall); // Register a perf event for user space to output data
BPF_HASH(data, u32, u64); 



TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    //Setup
    struct data_t data = {};
    
    //Get syscall_id
    
    data.syscall_id= args->id;//这里syscall_name还是标号而不是名称，需要改一下
    //Filter syscall_id, if not in the list, return 0
    //由于实例中没有提供内核态下id反查name的方法，所以这里只能先用静态id表过滤，后续再改
    
    /*
    if(data.syscall_id!=__NR_chmod&&data.syscall_id!=__NR_chroot&&data.syscall_id!=__NR_chown)//copilot有点太智能了
    {
        //bpf_trace_printk("Got syscall_id: %d\\n", data.syscall_id); 
        return 0;
    }*/
    
    //To filter read() and write() syscalls
    if(data.syscall_id!=__NR_read&&data.syscall_id!=__NR_write){
        return 0;
    }
    //这种过滤方式比较原始 不如直接用tracepoint_probe的过滤
    
    
    
    //Get pid and tgid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    u32 tgid = (u32)pid_tgid;
    data.pid = pid_tgid >> 32;
    
    #ifdef FILTER_PID// filter the spectific pid
    if (data.pid != FILTER_PID)
        return (0);
    #endif
    
    //Get current command
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    //Get timestamp
    data.timestamp = bpf_ktime_get_ns();
    
    //Get ret value; to be finished
    data.retval = args->ret;

    //Get args; to be finished
    strcpy(data.args,"To be completed");//Here need to be fixed; use a const string first
    
    //Submit data to user space
    syscall.perf_submit(args, &data, sizeof(data));
    return 0;
}

"""
if not args.pid:
    print("[!] No pid given, stat all syscalls from the systemwide.")
else:
    print(f"[+] Tracing syscalls of process {args.pid}")
    kernel_code = f"#define FILTER_PID {args.pid}" + kernel_code


# Define data structure in Python
class SyscallEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("comm", ct.c_char * 80),
        ("args", ct.c_char * 128),
        ("retval", ct.c_int),
        ("timestamp", ct.c_ulonglong),
        ("syscall_id", ct.c_int),
    ]


bpf = BPF(text=kernel_code)  # Load kernel prog


def print_headers():
    print(
        "%-18s %s %-16s %-6s %s %s"
        % ("TIME(s)", "SYSCALL_NAME", "PID", "COMM", "RET", "ARGS")
    )


def print_event(cpu, data, size):
    """
    To print the details informations of a syscall event, including the name of the syscall, the process name, the pid, the return value and the arguments.
    """
    # print("[%s]" % strftime("%H:%M:%S"))
    event = ct.cast(data, ct.POINTER(SyscallEvent)).contents
    print(
        "%d %-16s %-6d %-16s %-2d %s"
        % (
            event.timestamp,
            resolve_syscall_id(event.syscall_id),
            # event.syscall_id, # For debug only
            event.pid,
            event.comm.decode(),
            event.retval,
            event.args.decode(),
        )
    )


def resolve_syscall_id(syscall_id: int) -> str:
    """
    To resolve the syscall id to the syscall name.
    """
    return syscall_name(syscall_id).decode()


# Main loop
bpf["syscall"].open_perf_buffer(print_event)  # 声明使用事件处理函数print_event打印信息
print_headers()

timer = 0  # For debug use, only execute the given seconds to save time
interval = 1  # Extract from the pipe with the given seconds
MAX_DURATION = 5  # Max duration of the tracing
while 1:
    try:
        sleep(interval)  # 指定时间段，当时间超过，提exiting
        timer += interval

        bpf.perf_buffer_poll()  # 持续轮询buffer

    except KeyboardInterrupt:
        print("Interrupted by Ctrl-C")
        exit()
    if timer >= MAX_DURATION:
        print("Max duration reached, detaching...")
        exit()

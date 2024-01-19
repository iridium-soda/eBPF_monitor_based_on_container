# A program to trace the kernel function do_sys_openat2 using BCC/eBPF
# Usage: sudo python kernel_func_trace.py
# Kernel version used: 4.15.0-45-generic

from bcc import BPF
from bcc.utils import ArgString, printb
import ctypes as ct
from time import sleep, strftime
import sys
from datetime import datetime, timedelta

kernel_code = """
#include <uapi/linux/ptrace.h>
# include <linux/sched.h>
# include <linux/fs.h>
# include <linux/file.h>
# include <linux/path.h>
# include <linux/dcache.h>
# include <linux/mount.h>
# include <linux/nsproxy.h>
# include <linux/ns_common.h>
# include <linux/nsfs.h>
# include <linux/pid_namespace.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/openat2.h>

enum event_type {
    EVENT_ARG=0,
    EVENT_RET=1,
};
struct val_t{
    u64 id;
    u32 tid;
    u64 pid;
    char comm[TASK_COMM_LEN];
    char  fname[NAME_MAX];

};
struct data_t {
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    char  filename[NAME_MAX];
    u64 timestamp;
    int retval;
    };
    
BPF_HASH(infotmp, u64, struct val_t);// pid_tid as the key

BPF_PERF_OUTPUT(events); // Register a perf event for user space to output data
int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user * filename, struct open_how *how) {
        struct val_t val = {};
        u64 pid_tid= bpf_get_current_pid_tgid();
        val.id = pid_tid;
        val.pid = pid_tid>>32;//Higher 32 bits is pid
        val.tid=pid_tid;// val.tid is u32; turncate it
        //TODO: add uid_gid info
        
        bpf_get_current_comm(&val.comm, sizeof(val.comm));
        if (bpf_probe_read_user_str(&val.fname, sizeof(val.fname), (void *)filename)<0){
            return 0;}//NOTE: MUST use read_user_str here, otherwise it will fail for no reason.
        u32 ppid =( (struct task_struct *)bpf_get_current_task())->real_parent->pid;
        if (ppid!=86079){
        return 0;//filter non-runc process
        }
        infotmp.update(&pid_tid, &val);//update info table with the key of pid_tid
        return 0;
        }
int kretprobe__do_sys_openat2(struct pt_regs *ctx) {
        struct val_t *valp;
        struct data_t data = {};
        //Lookup the info table with the key of pid_tid
        
        u64 pid_tid= bpf_get_current_pid_tgid();
        valp = infotmp.lookup(&pid_tid);
        if (valp == 0) {
        // missed entry
        return 0;
        }
        
        if (bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm)<0){
            return 0;
        }
        
        if (bpf_probe_read_kernel(&data.filename, sizeof(data.filename), (void *)valp->fname)<0){
            return 0;}//MUST use read_kernel here, otherwise it will fail for no reason.

        pid_tid=valp->id;
        data.pid = pid_tid>>32;
        data.tid = valp->id; //tid is u32; turncate it
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.retval = PT_REGS_RC(ctx);
        data.timestamp = bpf_ktime_get_ns()/1000;
        //Remove data from info table
        infotmp.delete(&pid_tid);
        
        //Submit data to user space
        events.perf_submit(ctx, &data, sizeof(data));
        return 0;
        }
        
        """
bpf = BPF(text=kernel_code)  # Load kernel prog


# with the key of pid
def print_headers():
    print(
        "%-16s %-16s %-6s %-6s %-6s %-32s"
        % (
            "TIME",
            "COMM",
            "RET(FD)",
            "PID",
            "TID",
            "FILENAME",
        )
    )


def print_event(cpu, data, size):
    # Merge and print data from the entry and exit
    event = bpf["events"].event(data)

    printb(
        b"%-6d %-16s %-6d %-6d %-6d %-32s"
        % (
            event.timestamp,
            event.comm,
            event.retval,
            event.pid,
            event.tid,
            event.filename,
        )
    )


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

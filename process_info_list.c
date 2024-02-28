#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/limits.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>

struct data_t
{
    u32 pid;
    u32 ppid;
    u32 pid_ns;
    int debugCode;
}

BPF_PERF_OUTPUT(events); //  Register a perf event for user space to output data

// 需要去看一下追踪点怎么埋,有哪些埋point的方法
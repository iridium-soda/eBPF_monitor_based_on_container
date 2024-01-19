/*Kernel code of docker_detector*/
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/nsfs.h>
#include <linux/pid_namespace.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/openat2.h>
#include <linux/unistd.h>

// When internal process doing ~~read/~~write, capture it.

// root         844  0.0  0.9 1356824 18724 ?       Ssl  Dec19   4:34 /usr/bin/containerd

// sudo python3 raw_syscall.py -p 844
//[+] Tracing syscalls of process 844
// TIME(s)            SYSCALL_NAME PID              COMM   RET ARGS
// 1083015175123406 write            844    containerd       1  To be completed
// 1083015175130838 read             844    containerd       1  To be completed
// 1083015362455051 write            844    containerd       1  To be completed
// 1083015362464241 read             844    containerd       1  To be completed
struct report_data
{
    // To report containerd's info
    u32 pid;
    u32 ppid; // 通过task_struct中的struct task_struct __rcu *parent;去拿
    u32 tid;
    unsigned int fd;
    char comm[TASK_COMM_LEN];
    //char filename[NAME_MAX];
    u64 timestamp;
};
u32 runc_pid = 0;
BPF_PERF_OUTPUT(events); // Register a perf event for user space to output data
static char *get_path_by_fd(struct task_struct *task, unsigned long fd)
{
    // get file abs path by reading files_struct in task_struct
    struct file *file_struct = NULL;
    struct files_struct *files = NULL;
    char path[NAME_MAX] = {'\0'};
    char *ppath = path;
    files = task->files;
    if (!files)
    {
        // printk("NULL file fd list")
        return NULL;
    }
    file_struct = files->fdt->fd[fd];
    if (!file_struct)
    {
        // printk("file is NULL")
        return NULL;
    }
    ppath = d_path(&(file_struct->f_path), ppath, NAME_MAX);
    return ppath;
}

TRACEPOINT_PROBE(syscalls,sys_enter_write)
{
    // All other unused paras are omitted

    // Get basic info
    struct report_data val = {};
    u64 pid_tid = bpf_get_current_pid_tgid();
    val.tid = pid_tid;       // turncate it to u32
    val.pid = pid_tid >> 32; // Higher 32 bits is pid
    val.ppid = 123;          // Just a padding
    val.timestamp = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    val.fd=args->fd;
    // get filename by fd
    char *path = get_path_by_fd(t, args->fd);
    if (!path)
    {
        // Reading fd error
        return 0;
    }
    // Copy to val struct
    /*if (bpf_probe_read_user_str(&val.filename, sizeof(val.filename), (void *)path) < 0)
    {
        return 0;
    } */
    // NOTE: MUST use read_user_str here, otherwise it will fail for no reason.
    // Submit data to user space
    events.perf_submit(args, &val, sizeof(val));
    //FIXME:in function syscall__write i32 (%struct.pt_regs*): Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.
    return 0;
}
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/limits.h>
#include <linux/fdtable.h>
#define PPIDFILTER 86079 // filter non-runc process

// Pre def
struct pid_namespace
{
    struct ns_common ns;
};


struct data_t
{
    u32 pid;
    u32 ppid;
    int fd;
    u64 ns;
    char path[128];
};
BPF_RINGBUF_OUTPUT(events, 8); // Creates a ringbuf called events with 8 pages of space, shared across all CPUs
                               //  Register a perf event for user space to output data
int kprobe__sys_write(struct pt_regs *ctx, int fd, const void *buf, size_t count)
{
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid_tid = bpf_get_current_pid_tgid();
    data.pid = pid_tid >> 32;
    data.ppid = task->real_parent->pid;
    data.fd = fd;
    data.ns = task->nsproxy->pid_ns_for_children->ns.inum;
#ifdef PPIDFILTER
    if (data.ppid != PPIDFILTER)
    {
        return 0; // filter non-runc process
    }
#endif

    // Convert file description to its full path
    struct files_struct *files = NULL;
    struct fdtable __rcu *fdt = NULL;
    struct path files_path;
    struct file *file = NULL;
    char path[128];
    files = task->files;
    if (!files)
    {
        bpf_probe_read_str(&data.path, sizeof(data.path), "Failed at files");
        events.ringbuf_output(&data, sizeof(data), 0 /*flags*/);
        return 0;
    }
    fdt = files->fdt;
    if (!fdt)
    {
        bpf_probe_read_str(&data.path, sizeof(data.path), "Failed at fdt");
        events.ringbuf_output(&data, sizeof(data), 0 /*flags*/);

        return 0;
    }
    file = fdt->fd[fd];
    if (!file)
    {
        bpf_probe_read_str(&data.path, sizeof(data.path), "Failed at file");
        events.ringbuf_output(&data, sizeof(data), 0 /*flags*/);
        return 0;
    }
    files_path = file->f_path;
    bpf_probe_read_str(path, 128, files_path.dentry->d_iname);
    bpf_probe_read_str(&data.path, sizeof(data.path), path);
    events.ringbuf_output(&data, sizeof(data), 0 /*flags*/);
    return 0;
}
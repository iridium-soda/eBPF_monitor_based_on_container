#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/limits.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>
#include "path_ops.h"
#define PPIDFILTER 2263 // filter non-runc process
#define PATHLEN 64

struct data_t
{
    u32 pid;
    u32 ppid;
    unsigned int fd;
    u32 ns;
    char comm[TASK_COMM_LEN];
    char path[PATHLEN];
    int debugCode;
};
BPF_PERF_OUTPUT(events); //  Register a perf event for user space to output data
TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    // Collect necessary info tand save to the HASH table
    struct data_t data = {};
    data.debugCode = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;
#ifdef PPIDFILTER
    if (data.ppid != PPIDFILTER)
    {
        return 0; // filter non-runc process
    }
#endif

    u64 pid_tid = bpf_get_current_pid_tgid();
    data.pid = pid_tid >> 32;
    data.fd = args->fd;
    data.ns = task->nsproxy->pid_ns_for_children->ns.inum; // get ns
    // get path
    struct files_struct *files = task->files;
    struct fdtable *fdt;
    struct file **fdd;
    bpf_probe_read(&fdt, sizeof(fdt), (void *)&files->fdt);
    if (bpf_probe_read(&fdd, sizeof(fdd), (void *)&fdt->fd))
    {
        data.debugCode = -1;
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    struct file *file;
    struct path path;
    struct dentry *dentry;
    struct dentry p_dentry;
    struct qstr pathname;

    bpf_probe_read_kernel(&file, sizeof(file), (void *)&fdd[data.fd]);
    bpf_probe_read_kernel(&path, sizeof(path), (const void *)&file->f_path);
    dentry = path.dentry; // Get the initial dentry which refers the filename
    // bpf_probe_read_kernel(dentry, sizeof(dentry), (const void *)path.dentry);

    // About parent
    /*
    if (!bpf_probe_read_kernel(&p_dentry, sizeof(p_dentry), (const void *)&dentry->d_parent))
    {
        data.debugCode = -1;
    }*/
    /*if (!bpf_probe_read_kernel(&pathname, sizeof(pathname), (const void *)&p_dentry.d_name))
    {
        data.debugCode = -2;
    }*/
    /*
    pathname = p_dentry.d_name;
    if (!bpf_probe_read_kernel_str((void *)data.path, sizeof(data.path), pathname.name))
    {
        data.debugCode = -3;
    }
    */

    // The following is to read filename at the normal way
    bpf_probe_read_kernel(&pathname, sizeof(pathname), (const void *)&dentry->d_name);
    bpf_probe_read_kernel_str((void *)data.path, sizeof(data.path), (const void *)pathname.name);

    // bpf_probe_read(&pathname, sizeof(pathname), (const void *)&p_dentry->d_name);
    // bpf_probe_read_str((void *)data.path, sizeof(data.path), (const void *)pathname.name);

    // bpf_probe_read_kernel(&p_dentry, sizeof(p_dentry), dentry->d_parent);
    int offset = strlen_64(data.path);
    // data.debugCode = offset;

    // struct dentry *cur_den = dentry;
    // char p_name[FILENAME_LEN], tmp[FILENAME_LEN];
    /*
    while (lev < 64 && cur_den->d_parent)
    {
        // Read dentry recursively
        bpf_probe_read_kernel_str(tmp, FILENAME_LEN, cur_den->d_name.name);
        add_head_slash(tmp);
        strcat_64(tmp, data.path, p_name);
        bpf_probe_read_kernel_str(data.path, PATHLEN, p_name);
        cur_den = cur_den->d_parent;
        lev++;
    }
    */

    // Submit
    events.perf_submit(args, &data, sizeof(data));

    return 0;
}

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/limits.h>
#include <linux/fdtable.h>
#define PPIDFILTER 86079 //filter non-runc process

struct data_t
{
    u32 pid;
    u64 timestamp;
    u32 ppid;
    int fd;
    char comm[TASK_COMM_LEN];
    char path[256];
};
BPF_PERF_OUTPUT(events); // Register a perf event for user space to output data
/*
static char* get_path_by_fd(struct pt_regs *ctx, int fd) {
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct path files_path;
    struct file *file = NULL;
    char *path = NULL;
    files = current->files;
    if (!files) {
        return NULL;
    }
    fdt = files_fdtable(files);
    if (!fdt) {
        return NULL;
    }
    file = fdt->fd[fd];
    if (!file) {
        return NULL;
    }
    files_path = file->f_path;
    path = (char *) bpf_kzalloc(PATH_MAX, GFP_KERNEL);
    if (!path) {
        return NULL;
    }
    bpf_probe_read(path, PATH_MAX, files_path.dentry->d_iname);
    return path;
}
*/
int kprobe__sys_write(struct pt_regs *ctx, int fd, const void *buf, size_t count)
{
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid_tid = bpf_get_current_pid_tgid();
    data.pid = pid_tid >> 32;
    data.timestamp = bpf_ktime_get_ns();
    data.ppid = task->real_parent->pid;
    data.fd = fd;
    #ifdef PPIDFILTER
    if (data.ppid!=PPIDFILTER){
        return 0;//filter non-runc process
    }
    #endif
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    //char path[128];
    // To get absloute path by fd and assign it to path[]: ref https://github.com/iovisor/bcc/issues/2538#issuecomment-540489636
    struct task_struct* t;
    struct files_struct* f;
    struct fdtable* fdt;
    struct file** fdd;
    struct file* file;
    struct path path;
    struct dentry* dentry;
    struct qstr pathname;
    t=task;
    f = t->files;
    bpf_probe_read(&fdt, sizeof(fdt), (void*)&f->fdt);
    int ret = bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd); 
    if (ret) {
        //bpf_trace_printk("bpf_probe_read failed: %d\\n", ret);
        return 0;
    }
    bpf_probe_read(&file, sizeof(file), (void*)&fdd[fd]);
    bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);

    dentry = path.dentry;
    bpf_probe_read(&pathname, sizeof(pathname), (const void*)&dentry->d_name);
    bpf_probe_read_str((void*)data.path, sizeof(data.path), (const void*)pathname.name);

    //bpf_trace_printk("File: %s\\n", filename);
    //path=task->files->fdt->fd[fd]->f_path.dentry->d_iname;
    //
    //bpf_probe_read_kernel_str(&data.path, sizeof(data.path), task->files->fdt->fd[fd]->f_path.dentry->d_iname);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
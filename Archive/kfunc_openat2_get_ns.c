#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/mount.h>
#include <linux/nsfs.h>
#include <linux/pid_namespace.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <uapi/linux/limits.h>
#include <uapi/linux/openat2.h>

struct mnt_namespace
{
    atomic_t count;
    struct ns_common ns;
    struct mount *root;
};
struct mount
{
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
};

struct data_t
{
    u32 pid;
    u64 timestamp;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    unsigned int nsinum;
    char vfsroot[256];
};

BPF_PERF_OUTPUT(events); // Register a perf event for user space to output data

int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, struct open_how *how)
{
    struct data_t data = {};
    u64 pid_tid = bpf_get_current_pid_tgid();
    data.pid = pid_tid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;
    data.timestamp = bpf_ktime_get_ns();
    
    if (data.ppid != 86079)
    {
        return 0; // filter non-runc process
    }
    
    int ret = bpf_probe_read_user_str(&data.vfsroot, sizeof(data.vfsroot), (void *)PT_REGS_PARM2(ctx));
    if (ret < 0)
    {
        return 0;
    }
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // get mnt namespace info
    struct nsproxy *nsproxy = task->nsproxy;
    struct mnt_namespace *mnt_ns = nsproxy->mnt_ns;
    data.nsinum = mnt_ns->ns.inum;
    struct mount *mnt_root = mnt_ns->root;
    struct dentry *dentry = mnt_root->mnt_mountpoint;
    struct qstr d_name;
    bpf_probe_read_user(&d_name, sizeof(d_name), &dentry->d_name);
    bpf_probe_read_user_str(&data.vfsroot, sizeof(data.vfsroot), (void *)d_name.name);
   
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
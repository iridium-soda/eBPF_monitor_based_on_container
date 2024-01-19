#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
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

struct data_t
{
    u32 pid;
    u64 timestamp;
    u32 ppid;
    char filename[128];
    char comm[TASK_COMM_LEN];
    char pwdpath[128];
    char rootpath[128];
    unsigned int pidns;
    //char vfsroot[128];
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
    int ret = bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*) PT_REGS_PARM2(ctx));
	if (ret < 0) {
		return 0;
    }
    //bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
    
    if (data.ppid != 86079)
    {
        return 0; // filter non-runc process
    }

    // get pid at the cuttent namespace
    // Temp field
    //data.ppid=bpf_get_ns_current_pid_tgid()>>32;
    data.ppid=dfd;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get PWD of the current process
    struct fs_struct *fs=task->fs;
    struct path pwd=fs->pwd;
    struct dentry* dentry=pwd.dentry;
    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), (void *)&(dentry->d_name));
    const unsigned char *pwd_name=d_name.name;
    bpf_probe_read_kernel_str(&data.pwdpath, sizeof(data.pwdpath),(void *)pwd_name);
    
    // Get root of the current process
    struct path root=fs->root;
    struct dentry* root_dentry=root.dentry;
    struct qstr root_d_name;
    bpf_probe_read_kernel(&root_d_name, sizeof(root_d_name), (void *)&(root_dentry->d_name));
    const unsigned char *root_name=root_d_name.name;

    bpf_probe_read_kernel_str(&data.rootpath, sizeof(data.rootpath),(void *)root_name);
    char* rootpath=NULL;
    
    //char * ko_buf=&rootpath;
    //dentry_path_raw(root_dentry,rootpath, sizeof(data.rootpath));
    //bpf_probe_read_kernel_str((void *)&data.rootpath, sizeof(data.rootpath),(void *)data.rootpath);
    //free_page((unsigned long)ko_buf);


    // Get VFS root of the current process
    /*FIXME:
    struct vfsmount *mnt = pwd.mnt;
    struct dentry *mnt_root;
    bpf_probe_read((void *)mnt_root, sizeof(*mnt_root), (void *)mnt->mnt_root);
    //struct dentry *mnt_root = mnt->mnt_root;
    struct qstr vfs_root_d_name;
    bpf_probe_read_kernel(&vfs_root_d_name, sizeof(vfs_root_d_name), (void *)&(mnt_root->d_name));
    const unsigned char *vfs_root_name=vfs_root_d_name.name;
    //bpf_probe_read_kernel_str(&data.vfsroot, sizeof(data.vfsroot),(void *)vfs_root_name);
    */

    // Get pid namespace of the current process
    u32 pid_ns_id = task->nsproxy->pid_ns_for_children->ns.inum;
    data.pidns = pid_ns_id;

    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}


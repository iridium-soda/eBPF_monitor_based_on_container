#!/usr/bin/python
# Ref:https://github.com/iovisor/bcc/issues/2538#issuecomment-540489636

from bcc import BPF

bpf_text = """
#define randomized_struct_fields_start  struct {
#define randomized_struct_fields_end    };
#include <uapi/linux/bpf.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#define PPIDFILTER 86079 //filter non-runc process

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    unsigned int fd;
    struct task_struct* t;
    struct files_struct* f;
    struct fdtable* fdt;
    struct file** fdd;
    struct file* file;
    struct path path;
    struct dentry* dentry;
    struct qstr pathname;
    char filename[128];
    char vfsroot[128];

    fd =args->fd;
    t = (struct task_struct*)bpf_get_current_task();
    f = t->files;
    
    u32 ppid = t->real_parent->pid;
    #ifdef PPIDFILTER
    if (ppid!=PPIDFILTER){
        return 0;//filter non-runc process
    }
    # endif

    bpf_probe_read_kernel(&fdt, sizeof(fdt), (void*)&f->fdt);
    int ret = bpf_probe_read_kernel(&fdd, sizeof(fdd), (void*)&fdt->fd); 
    if (ret) {
        bpf_trace_printk("bpf_probe_read_kernel failed: %d\\n", ret);
        return 0;
    }
    bpf_probe_read_kernel(&file, sizeof(file), (void*)&fdd[fd]);
    bpf_probe_read_kernel(&path, sizeof(path), (const void*)&file->f_path);

    dentry = path.dentry;
    bpf_probe_read_kernel(&pathname, sizeof(pathname), (const void*)&dentry->d_name);
    bpf_probe_read_kernel_str((void*)filename, sizeof(filename), (const void*)pathname.name);
    

    bpf_probe_read_kernel_str((void*)vfsroot, sizeof(vfsroot), (const void*)path.mnt->mnt_root->d_name.name);

    bpf_trace_printk("File: %s\\n", filename);
    

    return 0;
}
"""

b = BPF(text=bpf_text).trace_print()

#!/usr/bin/python

from bcc import BPF

# BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_HASH(fd_to_path, u32, char[256]);

int trace_sys_open(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u32 fd = PT_REGS_RC(ctx);

    char filename[256];
    bpf_probe_read_user(&filename, sizeof(filename), (void *)PT_REGS_PARM1(ctx));
    
    fd_to_path.update(&fd, &filename);
    
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_program)

# Attach tracepoint
b.attach_kprobe(event="sys_open", fn_name="trace_sys_open")

# Print file path for given file descriptor
try:
    while True:
        print("File paths for descriptors:")
        for k, v in b.get_table("fd_to_path").items():
            print(f"Descriptor {k.value}: {v.value.decode()}")
        b.trace_print()
except KeyboardInterrupt:
    pass

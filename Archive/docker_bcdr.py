"""
To trace container break write behaviors by eBPF.
Doing this by using bcc.
1. 完成对write系统调用的hook,拿到文件路径参数
2. 完成ppid filter,针对runc
3. 完成检查文件mnt namespace的办法(或者完全按照PACED做,用hash table存储)
4. 完成检测逻辑
"""

from bcc import BPF

kernel_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/limits.h>
#include <linux/fdtable.h>
struct data_t {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char path[256];
};

BPF_PERF_OUTPUT(events); // Register a perf event for user space to output data

static char *get_path_by_fd(struct file __rcu **fds, unsigned long fd)
{
    // get file abs path by reading files_struct in task_struct
    struct file *file_struct = NULL;
    //struct files_struct *files = NULL;
    char path[NAME_MAX] = {};
    char *ppath = path;
    //files = task->files;
    //if (!files)
    //{
        // printk("NULL file fd list")
        //return NULL;
    //}
    //file_struct = files->fdt->fd[fd];
    file_struct=fds[fd];
    if (!file_struct)
    {
        // printk("file is NULL")
        return NULL;
    }
    ppath = d_path(&(file_struct->f_path), ppath, NAME_MAX);
    return ppath;
}
int syscall_trace_write(struct pt_regs *ctx, int fd, const void *buf, size_t count){
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid()>>32;
    u32 ppid=0;// Just padding first
    data.pid = pid;
    
    #ifdef PIDFILTER
    if (pid != PIDFILTER)
        return 0;
    #endif
    
    data.ppid = ppid;
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(data.path, sizeof(data.path), get_path_by_fd(((struct task_struct *)bpf_get_current_task())->files->fdt->fd, fd));    
    //Submit data to user space
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}


"""

bpf = BPF(text=kernel_code)


def print_headers():
    print(f"{'TIME':<10} {'PID':<10} {'PPID':<10} {'COMM':<15} {'PATH':<30}")


def print_event(cpu, data, size):
    """
    Print reported data via perf event.
    """
    # print("[%s]" % strftime("%H:%M:%S"))
    event = bpf["write_events"].event(data)
    print(
        "%d %-16s %-6d %-16s %-2d %s"
        % (
            event.timestamp,
            event.pid,
            event.ppid,
            event.comm.decode(),
            event.path.decode(),
        )
    )


print_headers()
bpf.attach_kprobe(
    event=bpf.get_syscall_fnname("write"), fn_name="syscall_trace_write"
)  # hook write syscall
bpf["syscall"].open_perf_buffer(print_event)  # 声明使用事件处理函数print_event打印信息
while 1:
    try:
        bpf.perf_buffer_poll()  # 持续轮询buffer
    except KeyboardInterrupt:
        print("Interrupted by Ctrl-C, detaching...")
        exit()

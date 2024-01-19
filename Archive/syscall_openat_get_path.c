//go:build ignore
// Code from https://blog.csdn.net/qq_42931917/article/details/131732497

// #include "../headers/common.h"
// #include "../headers/arm64_vmlinux.h"
#include "../headers/vmlinux.h"
#include "../headers/bpf_tracing.h"
#include "../headers/bpf_helpers.h"

#define FILE_NMAE_LEN 256
#define COMM_NAME_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct open_info {
	u32 pid;
	int fd;
	u8 comm[COMM_NAME_LEN];
	u8 filename[FILE_NMAE_LEN];
};

// struct bpf_map_def SEC("maps") info_map = {
// 	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(struct open_info),
// 	.max_entries = 256,
// };
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} info_map SEC(".maps");

// Force emitting struct open_info into the ELF.
const struct open_info *unused __attribute__((unused));

SEC("kprobe/do_sys_open")
int kprobe_do_sys_open(struct pt_regs *ctx) {
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
    // 初始化open_info结构体为{}
	struct open_info info = {};
	int ret = 0;
	char fmt[] = "ret error %d\n";

	ret = bpf_probe_read_user_str(info.filename, FILE_NMAE_LEN, (void *)PT_REGS_PARM2(ctx));
	if (ret < 0) {
		bpf_trace_printk(fmt, sizeof(fmt), "bpf_probe_read", ret);
		return 0;
	}

	info.pid = tgid;
	bpf_get_current_comm(&info.comm, COMM_NAME_LEN);

	ret = bpf_perf_event_output(ctx, &info_map, 0, &info, sizeof(info));
	if (ret < 0) {
		bpf_trace_printk(fmt, sizeof(fmt), "bpf_perf_event_output", ret);
		return 0;
	}
	
	return 0;
}

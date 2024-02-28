/*
To get full paths for syscall_write_fullpath.c
*/

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/limits.h>
#include <linux/fdtable.h>
#include <linux/pid_namespace.h>

#define FILENAME_LEN 64

static int strlen_64(char *str)
{
    int i;
#pragma clang loop unroll(full)
    for (i = 0; i < FILENAME_LEN; i++)
    {
        if (str[i] == 0)
            break;
    }
    return i;
}

static int strcat_64(char *s1, char *s2, char *result)
{ // return s1+s2
    int i;
    i = strlen_64(s1);
    if (i < 1)
        return i;
    bpf_probe_read_kernel_str(result, FILENAME_LEN, s1);
    char *_result = &result[i];
    bpf_probe_read_kernel_str(_result, FILENAME_LEN - i, s2);
    return i;
}
static int add_head_slash(char *str)
{
    char tmp[FILENAME_LEN];
    bpf_probe_read_kernel_str(tmp, FILENAME_LEN, str);
    char *_str = &str[1];
    bpf_probe_read_kernel_str(_str, FILENAME_LEN - 1, tmp);
    str[0] = '/';
    return 1;
}

static void get_dentry_name(struct dentry *den, char *name)
{
    // bpf_probe_read[_kernel](name, FILENAME_LEN, den->d_name.name);
    bpf_probe_read_kernel_str(name, FILENAME_LEN, den->d_name.name);
    add_head_slash(name); // 加上路径前的`/`符号
}

static int get_full_filename(struct dentry *den, char *filename)
{
    int i;
    char p_name[FILENAME_LEN], tmp[FILENAME_LEN];
    struct dentry *cur_den = den;
    get_dentry_name(cur_den, filename);
#pragma clang loop unroll(full)
    for (i = 0; i < 64; i++)
    {
        if (cur_den->d_parent == 0)
            break;
        cur_den = cur_den->d_parent;
        get_dentry_name(cur_den, p_name);
        strcat_64(p_name, filename, tmp);
        bpf_probe_read_kernel_str(filename, FILENAME_LEN, tmp);
    }
    return i;
}

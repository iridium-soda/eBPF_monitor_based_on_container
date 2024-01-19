#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <linux/pid.h>

int main() {
    pid_t pid = getpid(); // 获取当前进程的PID

    struct task_struct *task;
    task = pid_task(find_vpid(pid), PIDTYPE_PID); // 获取指定PID的task_struct

    if (task == NULL) {
        perror("Failed to get task_struct");
        return EXIT_FAILURE;
    }

    // 输出task_struct中的一些信息示例
    printf("Process ID: %d\n", task->pid);
    printf("Process State: %ld\n", task->state);
    // 可以继续访问task_struct的其他成员

    return EXIT_SUCCESS;
}

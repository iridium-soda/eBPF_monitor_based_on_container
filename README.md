# eBPF_monitor_based_on_container
A runtime-based container monitor based on eBPF.

## 目标

通过eBPF，拿到：

- 每个openat2进程的基本信息，给出足够的判据证明这是容器内进程
- 取得每个进程的namespace信息（创建时/切换时）（这一部分之前应该有过）
- Extension：拿到open文件的相关信息(Namespace)

## Note

> 当使用 pthread_create() 调用创建一个线程后，在内核里就相应创建了一个调度实体 task_struct。
所以应该根据tid过滤
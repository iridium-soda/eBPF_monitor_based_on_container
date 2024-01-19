#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    // 假设文件描述符是 fd
    int fd = 1; // 更改为你要查询的文件描述符
    
    char fdPath[64];
    sprintf(fdPath, "/proc/86079/fd/%d", fd); // 构建文件描述符对应的路径
    
    char linkTarget[1024];
    ssize_t bytesRead;
    
    // 读取符号链接内容
    bytesRead = readlink(fdPath, linkTarget, sizeof(linkTarget) - 1);
    if (bytesRead != -1) {
        linkTarget[bytesRead] = '\0'; // 添加字符串结束符
        printf("File path for descriptor %d: %s\n", fd, linkTarget);
    } else {
        perror("readlink");
        exit(EXIT_FAILURE);
    }

    return 0;
}

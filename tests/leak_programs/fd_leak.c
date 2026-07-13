#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

/* fd_leak.c - 合成句柄泄露程序（B2 验证用）
 * 编译：gcc -o tests/leak_programs/fd_leak tests/leak_programs/fd_leak.c
 * 运行：./tests/leak_programs/fd_leak
 * 行为：每 0.15s 打开 1 个 fd 不 close → 句柄泄露
 * 预期：约 125s 后 LeakDetect 触发句柄泄露告警（leak_seconds=120 需 120s 跨度）
 */

int main() {
    printf("FD leak: opening files without close\n");
    printf("Expected: LeakDetect alert after ~125s (leak_seconds=120)\n\n");
    for (int i = 0; i < 1000; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            printf("open failed at %d\n", i);
            break;
        }
        usleep(150000);  /* 0.15s，1000×0.15s=150s 增长期 */
    }
    printf("Done. Keeping process alive.\n");
    sleep(600);
    return 0;
}

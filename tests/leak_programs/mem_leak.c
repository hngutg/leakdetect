#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* mem_leak.c - 合成内存泄露程序（B1 验证用）
 * 对应文档：leakdetect-b1-design.md §九
 *
 * 编译：gcc -o tests/leak_programs/mem_leak tests/leak_programs/mem_leak.c
 * 运行：./tests/leak_programs/mem_leak
 *
 * 行为：每 0.1s 分配 1MB，不 free → 内存泄露
 * 预期：60s 后 LeakDetect 触发内存泄露告警
 */

int main() {
    printf("Starting memory leak simulation...\n");
    printf("Allocating 4KB every 0.1s without free\n");
    printf("Expected: LeakDetect alert after ~60s\n\n");

    for (int i = 0; i < 10000; i++) {
        void *p = malloc(4096);  /* 4KB */
        if (p == NULL) {
            printf("malloc failed at iteration %d\n", i);
            break;
        }
        usleep(100000);  /* 0.1s */
    }

    printf("Done allocating. Keeping process alive for monitoring.\n");
    sleep(600);  /* 10 分钟，保持运行供监控 */
    return 0;
}

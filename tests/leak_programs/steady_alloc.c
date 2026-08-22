/* steady_alloc.c - 稳态分配器（不泄露）：高速 malloc+free 等量，变长 size 减少 ptr 复用
 *
 * 用途（精度专项验证）：长跑 25 分钟不得告警
 *   - 噪声误报反例：稳态进程 outstanding 斜率≈0，新检测器（斜率+显著性）不得误报
 *   - allocs 饱和：高吞吐长跑，验证 BPF 驱逐后 outstanding 不漂移（改前会飙升）
 * 编译：gcc -O2 steady_alloc.c -o steady_alloc
 * 运行：./steady_alloc   （跑 1500 秒后自动退出）
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define HOLD 4096
#define DURATION_SEC 1500

int main(void) {
    srand((unsigned)time(NULL));
    static char *buf[HOLD];
    int i;
    for (i = 0; i < HOLD; i++) buf[i] = NULL;

    printf("[steady_alloc] high-throughput alloc+free, no leak. %d sec.\n", DURATION_SEC);
    unsigned long iters = 0;
    time_t end = time(NULL) + DURATION_SEC;
    while (time(NULL) < end) {
        for (i = 0; i < HOLD; i++) {
            size_t sz = 64 + (rand() % 4032);
            if (buf[i]) free(buf[i]);
            buf[i] = malloc(sz);
        }
        iters += HOLD;
        if (iters % (HOLD * 2000) == 0)
            printf("[steady_alloc] %lu cycles, still no leak\n", iters);
        usleep(100);
    }
    for (i = 0; i < HOLD; i++) if (buf[i]) free(buf[i]);
    printf("[steady_alloc] done, %lu cycles, all freed.\n", iters);
    return 0;
}

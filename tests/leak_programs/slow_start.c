/* slow_start.c - 慢启动后稳态（不泄露）：前 90s 爬坡分配，之后稳态不增长
 *
 * 用途（精度专项验证）：启动宽限期 grace_seconds(=120) 内不告警
 *   - 爬坡期（0-90s）outstanding 快速增长（40KB/s 斜率），无宽限会被误判泄露
 *   - grace=120 > ramp=90 → 爬坡期不判定 → 不告警；之后稳态斜率≈0 → 仍不告警
 * 编译：gcc -O2 slow_start.c -o slow_start
 * 运行：./slow_start   （跑 ~10 分钟后自动退出）
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define RAMP_SEC 90
#define STEADY_SEC 540
#define BLOCK 4096

int main(void) {
    printf("[slow_start] ramp %ds then steady %ds (no leak).\n", RAMP_SEC, STEADY_SEC);
    static char *cache[4000];
    int n = 0;
    time_t ramp_end = time(NULL) + RAMP_SEC;
    while (time(NULL) < ramp_end && n < 4000) {
        cache[n] = malloc(BLOCK);
        if (cache[n]) n++;
        usleep(100000);
    }
    printf("[slow_start] ramp done, %d blocks held (~%dKB). entering steady.\n", n, n * 4);

    time_t steady_end = time(NULL) + STEADY_SEC;
    while (time(NULL) < steady_end) {
        char *p = malloc(BLOCK);
        if (p) free(p);
        usleep(1000);
    }

    int i;
    for (i = 0; i < n; i++) free(cache[i]);
    printf("[slow_start] done. no leak expected.\n");
    return 0;
}

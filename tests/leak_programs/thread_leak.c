#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

/* thread_leak.c - 合成线程泄露程序（B2 验证用）
 * 编译：gcc -o tests/leak_programs/thread_leak tests/leak_programs/thread_leak.c -lpthread
 * 运行：./tests/leak_programs/thread_leak
 * 行为：每 1.5s 创建 1 个线程不 join → 线程泄露
 * 预期：约 125s 后 LeakDetect 触发线程泄露告警（leak_seconds=120 需 120s 跨度）
 */

void* worker(void* arg) {
    while (1) sleep(1);
    return NULL;
}

int main() {
    printf("Thread leak: creating 100 threads without join\n");
    printf("Expected: LeakDetect alert after ~125s (leak_seconds=120)\n\n");
    for (int i = 0; i < 100; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        usleep(1500000);  /* 1.5s，100×1.5s=150s 增长期 */
    }
    printf("Done. Keeping process alive.\n");
    sleep(600);
    return 0;
}

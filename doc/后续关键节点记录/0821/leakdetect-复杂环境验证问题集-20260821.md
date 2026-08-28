# LeakDetect 复杂环境验证问题集

> 日期：2026-08-21（arm K8s 节点验证发现）
> 用途：记录在真实复杂环境（arm K8s，ovs-vswitchd 等）验证时发现的问题现象 + 根因分析 + 修复方向。
> 关联：精度专项文档（`leakdetect-精度专项-20260821.md`）、慢泄露设计（§8）。

## 一、问题现象（7 个）

1. **泄露栈大量 `[unknown]`**：ovs-vswitchd 告警栈多帧 `[unknown]`（malloc 上一帧、libc 内部等）。
2. **确认泄露后进程从总值 + top5 消失**：ovs-vswitchd 升"确认泄露"后，资源卡片左上**内存总值**不再含它、**top5** 也看不到；但告警仍挂着。
3. **确认告警循环（消失又重现）**：确认泄露的进程"一会消失，又重新出现在告警中"——confirmed→resolve→re-confirm 循环。
4. **误报（环境无泄露却确认）**：环境未构造泄露异常，却对 ovs-vswitchd 报"确认泄露"。用户判断不正确。
5. **泄露点栈会改变（同进程两次栈不同）**：
   - 疑似时：`malloc → [unknown] → ... → ovsdb_datum_apply_diff_in_place+0x258 → [unknown] → ovsdb_idl_run+0x554 → [unknown] → bridge_run+0x4c → [unknown] → main+0x67c → [unknown]`（多个 ovsdb 符号解析到）。
   - 确认时：`malloc → [unknown] → 0xffffadb9b2c0 → [unknown] → ...（几乎全 [unknown]）→ 0xffffaec7fe64`。
   - 同进程告警栈在变。
6. **跑一段后各进程 mem 急速上升（含自身）**：运行一段时间后，检测到的内存突然急速上升——leakdetect 自身 ~1100MB、ovs-vswitchd ~433MB，各进程均快速上升。
7. **fd 监控同样急速上升（新发现）**：一段时间后，所有进程的句柄(fd)值也突然飞速上涨——与 6（mem）同型现象，体现在 fd。

## 二、根因分析（3 个）

### 根因 A：churn 误报（OLS on 1/100 churning outstanding 伪回归）

**涉及**：1（部分）、3、4、5。

ovs-vswitchd 是 churn daemon（IDL 周期性分配/释放：`ovsdb_idl_run → ovsdb_datum_apply_diff_in_place → malloc`）。BPF malloc outstanding 是 1/100 采样，长周期上**随机游走**（活跃采样 ptr 集大小波动 + 采样噪声）。

`_is_leaking`（OLS 斜率 + 残差 t 检验）在**随机游走信号上伪回归**：残差自相关（单位根）→ OLS SE 低估 → t 统计量虚高 → 持续 240s 的虚假显著斜率 → **假确认**（问题 4）。

- 游走震荡（涨→落→涨）→ 告警 confirmed→resolve→re-confirm **循环**（问题 3）。
- 每次 check 的"代表 sid"（`memory.py _iter_stats` 取 Δ 最大 sid）随 sid 级 outstanding 波动而变 → **栈改变**（问题 5）。
- 部分帧 stripped 无符号 → `[unknown]`（问题 1）。

**本质**：BPF outstanding（1/100 采样）对 churn daemon 是噪声大、非稳态的信号；OLS+t 检验在非稳态随机游走上统计无效（伪回归）。疑似/确认的 sticky + stabilize 对 churn 震荡处理不干净（循环）。

### 根因 B：值算法不一致（sum-clamp vs per-sid clamp）

**涉及**：2。

两处算 ovs-vswitchd 的 outstanding，**算法不同**：
- **告警值**（`memory.py _iter_stats`）：`Σ max(0, 每个 sid 的 cur)` —— **per-sid clamp**（负 sid 算 0，不抵消正 sid）。
- **per-process 值**（`aggregator.get_per_process_mem`，喂总值 + top5）：`max(0, Σ cur)` —— **sum-then-clamp**（负 sid 抵消正 sid，整体 ≤0 归 0）。

ovs-vswitchd 多 sid 混号（有正有负，churn）→ sum-clamp 负 sid 抵消正 sid → per-process 值=0 → **总值不计 + top5 看不到**（问题 2）；告警用 per-sid clamp → 值非零、还挂着。**两者脱节**。

### 根因 C：规模溢出（ring 溢出 / map 饱和）

**涉及**：6、7。

busy K8s 节点事件率高（多进程 × 高分配/fd 周转率）。两条路径：

1. **ring buffer 溢出**：mem `events`（1MB）/ fd `events`（1MB）ring；事件率 > Python ingest 吞吐（~10-20万回调/s）→ free/close 事件被丢 → `alloc_bytes-free_bytes`/`open_count-close_count` 失衡 → **全部进程 outstanding 漂移**（含 leakdetect 自身——它的 malloc/open 也被采样，frees/closes 丢 → 漂）。
2. **map 饱和**：`allocs`（100k cap，key=ptr）/ `fd_map`（100k cap，key={pid,fd}）全局。即使有驱逐（refcount→0 删条目），busy 节点**活跃 live ptr/fd 总数超 cap**（如 200 进程 × ~500 live = 10万，接近/超 100k）→ 新 alloc/open 的 free/close 查不到 → 漂。

**C 是系统性的**：mem（6）+ fd（7）+ leakdetect 自身都漂 → 工具在 busy 节点**值全失真、不可信**。

## 三、问题-根因映射

| 问题 | 根因 | 说明 |
|---|---|---|
| 1 栈 [unknown] | A + stripped | stripped 无符号（装 debuginfo）+ 栈变(5)抓不同 sid |
| 2 确认后消失 | B | sum-clamp vs per-sid clamp 脱节 |
| 3 循环 | A | churn 随机游走震荡 |
| 4 误报 | A | OLS on 1/100 churn outstanding 伪回归→假确认 |
| 5 栈变 | A | top-sid 随 sid 级波动而变 |
| 6 mem 急升 | C | ring 溢出/allocs map 饱和→全漂 |
| 7 fd 急升 | C | fd ring 溢出/fd_map 饱和→全漂 |

## 四、修复方向

### 根因 C（最严重，系统性，先修）

**BPF 改 + 重编 + 重打包**：
- 扩容 map：`allocs` 100k→1M、`fd_map` 100k→1M（`mem.bpf.c`/`fd.bpf.c`）→ 缓解饱和。
- 扩容 ring：`events` 1MB→4-8MB（mem + fd 各自）→ 缓解溢出。
- 降事件率（可选）：mem 采样 1/100→1/1000（减 mem 事件，丢精度）；fd 全量保持（fd 数少，采样丢精度）。
- 优化 ingest：批量回调（一次 poll 多事件、批量进 aggregator）替代每事件 Python 回调 → ingest 吞吐提升数倍。
- 最有效组合：**ring 扩 4-8MB + map 扩 1M + ingest 批量化**（不降采样，保精度）。

### 根因 A（churn 假确认，C 修后再修）

**核心：RSS 做确认门槛**（BPF outstanding 噪声大，RSS 精确）：
- 疑似：BPF outstanding 斜率 > floor + 显著（当前，噪声大，抓快泄露 + 栈）。
- 确认：额外要求 **RSS 也在涨**（`/proc/[pid]/status` VmRSS，精确无采样噪声）。churn 进程 BPF 随机游走涨，RSS 稳定 → 升不到确认（只疑似→自动消除）；真实泄露 BPF + RSS 都涨 → 确认。
- + confirmed 定期复查：置位后复查 BPF slope + RSS；都回落 → 降级/RESOLVED（修 sticky 不复查）。
- 同时缓解 3（循环，确认需 RSS，churn 不确认）、5（栈变，确认少→抓栈少）、1（少抓 stripped sid）。

### 根因 B（值算法，低风险，可随时）

`aggregator.get_per_process_mem` 改 **per-sid clamp**（`Σ max(0, cur) per sid`，与 `_iter_stats` 一致）→ per-process 值=告警值（非零）→ 重现于总值+top5。更正确（释放 sid 不抵消泄露 sid）。

### 问题 1（[unknown]）额外

stripped 无符号 → 装 debuginfo（libc6-dbg/ovs-dbg）环境侧；代码侧无解。

## 五、诊断需求（坐实 C + A）

1. **arm `.o` 驱逐**：`llvm-objdump -d bpf/compiled/mem.o | grep -cE "call 0x3( |$)"`（期望 2）+ `fd.o`（期望 3）→ 驱逐在不在（区分饱和 vs 溢出）。
2. **RSS 采样**：`for i in 1 2 3 4 5; do cat /proc/<pid>/status|grep VmRSS; sleep 30; done`（ovs-vswitchd + leakdetect 自身）→ 真涨=真漏；稳定=FP（BPF 噪声）。
3. **事件率**：看 `[ingest] mem/fd event #N` 增速 vs 实际 → 评估 ring 溢出。
4. **节点 live fd 数**：`ls /proc/*/fd 2>/dev/null | wc -l` → 看是否接近 fd_map 100k cap。

## 六、优先级

| 优先 | 根因 | 问题 | 修复 | 风险 |
|---|---|---|---|---|
| **1（showstopper）**| C 规模溢出 | 6 + 7（全漂，工具不可信）| map/ring 扩容 + ingest 优化（BPF 改+重编+重打包）| 中 |
| 2 | A churn 误报 | 4 + 3 + 5 + 1部分 | RSS 确认门槛 + confirmed 复查 | 中（新 RSS 读取+复查）|
| 3 | B 值算法 | 2 消失 | per-sid clamp（aggregator 一处）| 低 |

**顺序**：C 先（值不漂才有意义调算法）→ A（RSS 确认）→ B（per-sid clamp，可提前做，低风险，不依赖 C）。

## 七、状态

- 精度专项主体（Tier-1 快泄露：OLS + per-PID + 驱逐 + 疑似/确认 + cmdline + 三 tab）已实施。
- 本文档记录的是**复杂环境（arm K8s，ovs-vswitchd）验证暴露的系统性问题**——主要在规模溢出（C）+ churn 误报（A）+ 值算法（B）。
- C 是当前最严重（工具在 busy 节点不可用）；A 是检测精度（churn 假确认）；B 是值一致性。
- 慢泄露（Tier-2 RSS 长基线 + 钻取，精度专项 §8）与 A 的"RSS 确认门槛"方向一致（都用 RSS 精确信号）——A 的 RSS 确认可视作 Tier-2 思路提前用于"确认"层。

## 八、准确性自检（已核验）

- **A**：OLS+t 在随机游走上伪回归——已在 x86 steady_alloc 验证复现（30GB 漂 + 误报），数学已推（残差自相关→SE 低估→t 虚高）。准确。
- **B**：`get_per_process_mem`（`max(0, Σcur)`）vs `_iter_stats`（`Σmax(0,cur)`）——已读代码确认两处算法不同。准确。
- **C**：ring 1MB + map 100k + ingest ~10-20万/s——已在 x86 steady_alloc（百万事件/s→30GB 漂）验证同型；fd 同型（全量采样，事件率高）。arm `.o` 驱逐在不在待诊断（区分饱和 vs 溢出）。准确。
- 问题-根因映射、修复方向、诊断、优先级——均与代码 + 已验证现象一致。

---

## 九、C 诊断结果 + 修复方案分析（2026-08-22 增补）

### 9.1 C 诊断结果（x86 VM）

| 项 | 结果 | 含义 |
|---|---|---|
| mem.o `call 0x3` | 2 | 驱逐在 ✓ |
| fd.o `call 0x3` | 3 | 驱逐在 ✓ |
| live fd 数 | 98 | ≪ fd_map 100k cap → **无饱和** |
| steady_alloc 单跑 10+ min | 无漂移 | 单进程率 ingest 跟得上 |

**结论**：C 是 **ring buffer 溢出**（非 map 饱和）。驱逐在 + 98 fds ≪ cap → map 限界。单 steady_alloc 率 R → ingest 跟得上（不溢）；并发（steady_alloc + slow_start，率 ~2R）→ 超 ingest ~10-20万/s → ring 溢出 → 全漂（之前 30GB）。**8MB ring 只缓冲更大，不根治**（持续 2R 仍溢；busy 节点 5-10R 必溢）。

> 更新 §八 C 条：C 诊断已完成——**ring 溢出（非饱和）**，arm `.o` 驱逐已确认在（call 0x3=2/3）。

### 9.2 C 修复三方案

| 方案 | 做法 | 优缺 |
|---|---|---|
| **A 降采样** | mem 1/100→1/1000（10x 少 mem 事件）；fd 不能采样（破坏 open/close 配对）| mem 减 10x、fd 仍全量；丢 mem 精度；busy 节点 fd 高周转仍溢。**不根治** |
| **B map 聚合（重架构）** | BPF per-(pid,stack) outstanding map + Python 定期读 map（非 per-event）| **根治**（ingest 与事件率脱钩）；大改 |
| **C ring↑+ingest 批量** | ring 1MB→8MB + ingest 批量 ~1.5-2x | 部分修复（中等负载 ~2-3R）；busy 节点（5-10R）仍溢。**不根治** |

### 9.3 B 方案（map 聚合）详细分析

**精度影响：无损** ✓
- 采样不变（mem 1/100，×100 显示）。
- 检测不变（分析器每 5s 读 per-(pid,stack) outstanding 算 OLS 斜率；数据来自 map 读取 vs event 流，检测逻辑/精度一致）。
- 栈归因保留（BPF map 以 `(pid, stack)` 为 key，栈在 key 里；Python 读 map 即得每栈 outstanding + 栈）。

**B 引入的问题/代价**：

1. **BPF 复杂度↑**：2 个 map（allocs per-ptr 配对**保留**——free 需查 ptr 拿 alloc 的栈/size + 新 per-(pid,stack) outstanding 聚合）+ 每次 sampled alloc/free 双 map 更新（allocs refcount + per-(pid,stack) atomic add/sub）。BPF 每事件 2 次 map 操作（vs 当前 1 次 ring 输出）。**但 BPF 内核快，Python 不再 per-event → 把瓶颈从 Python 移到 BPF 内核 → scale**。
2. **fd 栈归因更复杂**：mem 的 `(pid,stack)` map 存栈；fd 的栈是 per-{pid,fd}（fd_map 里）。fd 需 per-pid fd_count map（检测，无栈）+ fd_map（per-{pid,fd}，栈归因，flagged 时读）→ 两 map。
3. **map 迭代开销**：Python 每 5s `bpf_map_get_next_key`+`lookup` 遍历 per-(pid,stack) map。现实规模（~200 进程 × ~50 栈 = 1万条）~0.02s/5s ≈ 0.4% CPU（**可忽略**）；极端 1M 条 ~2s/5s。**与状态大小（有界）成正比，不与事件率（无界）成正比 → 治 C 核心**。
4. **BPF map cap**：per-(pid,stack) map 需 cap（1M）+ 驱逐（outstanding→0 删条目，复用已加驱逐逻辑）。有界（live 栈数 ≪ cap）。
5. **重架构 = 大改**：BPF（加 map + 双 update + 驱逐，改 `mem.bpf.c`/`fd.bpf.c`）+ Python `ingest.py` 重写（map 读取替代 event 流）+ `loader.py`（加 `bpf_map_get_next_key` 迭代 API）。分析器/前端基本不动（数据形态一致）。**~1-2 天设计+实施+验证**。

**B 治 C 的本质**：聚合从 **Python per-event（无界，随事件率）** 移到 **BPF 内核 map + Python 周期读（有界，随状态大小）** → 与事件率脱钩 → busy 节点也扛得住。**根治 C**。

### 9.4 取舍

| | 精度 | C 修复 | 代价 |
|---|---|---|---|
| **B（map 聚合）** | 无损 | 根治 | BPF 复杂（2 map+双 update）+ Python ingest 重写 + fd 栈更复杂。**大改** |
| **C（ring↑+batch）** | 无损 | 部分（中等负载 ~2-3R） | 小改 |
| **A（降采样）** | 丢 mem 精度 | 不根治（fd 仍溢） | 中改，不推荐 |

### 9.5 当前状态

- C 诊断完成：**ring 溢出**（非饱和），8MB ring 不根治。
- B 方案已分析：**精度无损，根治 C，大改**（BPF+ingest 重架构）。
- C 方案：部分修复，小改。
- 待用户定方向：**B（根治，大改）vs C（部分，小改）**。
- B 修复需重编（BPF 改）+ 重打 arm 包；但 arm 节点 5.10（BPF 不加载）→ C 的 arm 验证需 ≥5.12 arm 节点。

### 9.6 类比解释（便于理解 B 方案）

**当前架构（事件队列模型，会溢出）**：
- 生产者（BPF 内核）→ ring buffer（**事件队列**，缓存事件流）→ 消费者（Python，per-event 回调，~10-20万/s）。
- 生产者事件率 > 消费者吞吐 → 队列满 → 事件丢 → 漂移（C）。
- 类比"流水线传送带"：BPF 往传送带上放事件，Python 一个个取；传送带（ring）放不下就溢。

**B 方案（共享状态模型，无队列无溢出）**：
- BPF（写者）→ map（**共享状态**，存聚合后的最新 outstanding）← Python（读者，每 5s 读快照）。
- **没有队列**——map 是"状态"（BPF 持续更新最新值），不是"队列"（不缓存历史事件）。
- Python 不再 per-event 消费，而是**定期读 map 快照**（一次拿到所有 pid/stack 的当前 outstanding）。
- 类比"共享白板"：BPF 在白板上更新每个 pid/栈的最新 outstanding，Python 每 5s 抄一次白板；白板只显示最新值，不存在"放不下"（白板格子数 = 状态大小，有界；BPF 覆盖写最新值）。

**关键区别**：
| | 当前（事件队列）| B（共享状态 map）|
|---|---|---|
| 中间层 | ring buffer（队列）| BPF map（状态）|
| 性质 | 队列（FIFO，会溢出）| 状态（最新值，不溢出）|
| Python 取数据 | per-event 消费（~10-20万/s 上限）| 定期读快照（每 5s，与事件率无关）|
| 溢出？| 会（生产>消费→队列满）| **不会**（map 是状态不是队列；cap 是状态条数，有驱逐则限界于活跃集）|

**一句话**：当前 = 事件队列（溢出）；B = 共享状态 map（无队列、无溢出，Python 读快照）。B 不是"换一个新队列"，是"**去掉队列，改共享状态**"。

---

## 十、allocs/fd_map 死 pid 累积（遗留，pre-existing，非 C）

### 10.1 问题

`allocs` map（`mem.bpf.c`，per-ptr 配对）+ `fd_map`（`fd.bpf.c`，per-{pid,fd} 配对）在**进程退出**时条目不清理：

- **allocs**：死进程的 malloc'd ptrs 永不被 free（进程已死，无 free() 调用）→ `allocs[ptr]` refcount=1 留存 → 驱逐（refcount→0 删）不触发 → **永久留存**。
- **fd_map**：死进程的 fds 不被 `sys_enter_close` tracepoint 关闭（内核进程退出时内部清理 fd 不走 close syscall）→ `fd_map[{pid,fd}]` refcount=1 留存 → **永久留存**。

每个死进程留下 ~其 live ptrs/fds 条目 → 进程不断退出 → **map 逐渐填满**。

### 10.2 来源：pre-existing（非 B 引入）

allocs/fd_map 在 B 之前就存在（配对追踪 map）。B 的 outstanding_map/fd_count_map 也有同样问题，但 B 的 map-reader 会清理它们（先收集后删死 pid）。**allocs/fd_map 没有 cleaner**。

### 10.3 影响：map 饱和 → 新 alloc/fd 不追踪 → 漂移

allocs/fd_map 累积到 cap（100k 当前 / 1M B）后：
1. 新 ptr 的 `bpf_map_update_elem(&allocs, &ptr, ...)` 失败（map 满）→ 新 alloc 不被追踪。
2. 该 ptr 后续 `free` → `allocs[ptr]` lookup miss → free 事件不产生 → outstanding_map 不减 → **outstanding 虚高（漂移）**。
3. fd_map 同理 → fd_count_map 漂移。

**与 C（ring 溢出）不同**：C 是事件丢（即时，秒级）；allocs/fd_map 饱和是配对 map 满（长期，数小时-数天）。

### 10.4 busy 环境影响

| 场景 | 100k cap 饱和时间 | 1M cap（B）饱和时间 |
|---|---|---|
| 稳定节点（少退出）| 数周-数月 | 数月-数年 |
| **busy K8s（pod 重启）**| **数小时-数天** | **数天-数周** |
| 极端（大量短命容器）| 数小时 | 数天 |

→ busy K8s 节点，allocs/fd_map 在**数小时-数天**内饱和 → 漂移。1M cap（B）延缓 10x，**但不根治**。

### 10.5 B 方案对此的处理

- B 的 outstanding_map/fd_count_map：map-reader 清理死 pid → **不累积**。
- B 的 allocs/fd_map：cap 100k→1M（**延缓 10x，不根治**）。
- **B 修了 C（ring 溢出，即时），没修 allocs/fd_map 饱和（长期）。两者是不同的漂移机制。**

### 10.6 修复方向（后续）

| 方案 | 做法 | 代价 |
|---|---|---|
| **A. alloc_info_t 加 pid** | allocs value 加 `u32 pid`；30-60s 清理线程遍历 allocs（per-ptr）+ fd_map（per-{pid,fd}）→ 删死 pid 条目 | 结构体改 + 额外 map 迭代（~0.02-0.2s/30-60s） |
| **B. fd_map 已有 pid** | 不改结构体；30-60s 清理线程遍历 fd_map → 删死 pid | 额外 fd_map 迭代 |
| **C. 进程退出 hook** | `sched_process_exit` tracepoint 里清理该 pid 的 allocs/fd_map 条目 | BPF 遍历 map 删该 pid（复杂，BPF 不支持高效 per-pid 遍历） |
| **D. 不修，cap + 定期重启** | 1M cap + busy 节点定期重启 leakdetect（清空 map） | 最简单；需人工重启 |

**推荐 A+B**：alloc_info_t 加 pid + 30-60s 清理线程遍历 allocs + fd_map 删死 pid。与 B 同轮或后续做。

### 10.7 状态

- **遗留**（B 之后的 follow-up）。
- B 实施时 cap→1M 作为临时延缓。
- 真正修复（A+B）待 B 上线后据 busy 节点实测是否需要再加（若 1M 够用数周，可不急）。

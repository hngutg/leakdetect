# LeakDetect 精度专项 — 完整验证方案

> 日期：2026-08-21
> 前置：精度专项代码改动已完成（见 `leakdetect-精度专项-20260821.md`）。
> 本机（Windows）无 Python/clang-bpf，以下验证在 Linux 构建机 + 目标节点执行。

---

## 阶段 0：构建机前置检查

```bash
clang --version                              # 需支持 -target bpf
ls /usr/include/bpf/bpf_helpers.h           # libbpf-dev 头文件
ls /usr/include/bpf/bpf_tracing.h
python3 --version                            # 3.9-3.12
```
缺则：`sudo apt install clang libbpf-dev python3-pip`

---

## 阶段 1：BPF 重编 + .o 校验

### 1.1 重编（x86 构建机）
```bash
cd ~/workspace/leakdetect
bash tools/build_bpf.sh
```
**预期**：`bpf/compiled/{mem,threads,fd}.o` 生成，无 clang 报错。
若报 `bpf_map_delete_elem` 未声明 → libbpf-dev 太旧（需 ≥0.6，提供该 helper）。

### 1.2 .o 校验（确认驱逐 + 不破坏 verifier）
```bash
# 1) 确认 allocs/fd_map 仍存在
llvm-readelf -S bpf/compiled/mem.o | grep -E "allocs|events"
llvm-readelf -S bpf/compiled/fd.o  | grep -E "fd_map|events"

# 2) 反汇编看 delete 调用（驱逐已编进去）
llvm-objdump -d bpf/compiled/mem.o | grep -A2 -B2 "bpf_map_delete_elem\|call.*12"
# helper 12 = bpf_map_delete_elem；trace_free_entry 内应见 1 处
llvm-objdump -d bpf/compiled/fd.o  | grep -c "call.*12"
# 应为 3（trace_close/dup2/dup3 各 1）

# 3) 加载测试（无 perf_event_open，纯 ringbuf；内核 5.12+ 应过 verifier）
sudo env PYTHONPATH=py-packages:. python3 -c "
from core.loader import BpfLoader
from core.config import load_config
l = BpfLoader(load_config())
l.load_mem(); l.load_threads(); l.load_fd()
print('BPF load OK')
"
```
**预期**：`BPF load OK`。若 `BPF_STX uses reserved fields` → 内核 <5.12（环境需求，非本次问题）。
若 verifier 报 `invalid mem access` → 检查删除后是否误访问 `info`/`val`（应为局部变量）。

---

## 阶段 2：Python 语法 + 单元验证

### 2.1 语法编译
```bash
cd ~/workspace/leakdetect
python -m py_compile analyzer/base.py analyzer/memory.py analyzer/threads.py analyzer/handles.py web/backend.py web/mock.py
echo $?    # 应为 0
```

### 2.2 `_is_leaking` 单元测试（移植 node 验证到 Python）
```bash
python3 - <<'PY'
import sys; sys.path.insert(0, '.')
from analyzer.base import TrendLeakDetector
# 构造一个不依赖 aggregator 的检测器实例
d = TrendLeakDetector.__new__(TrendLeakDetector)
d.threshold = 10240; d.significance_z = 3.0; d.leak_seconds = 60
# S1 真实泄露 40KB/s（×100 信号斜率 40000）
leak = [(i*5, i*200000) for i in range(24)]
# S2 稳态平坦 1MB
flat = [(i*5, 1000000) for i in range(24)]
# S3 噪声（伪随机围绕 1MB）
import random; random.seed(42)
noisy = [(i*5, 1000000 + (random.random()-0.5)*400000) for i in range(24)]
print('S1 leak(40KB/s):', d._is_leaking(leak))   # True
print('S2 flat(1MB):  ', d._is_leaking(flat))    # False
print('S3 noisy:       ', d._is_leaking(noisy))  # False
PY
```
**预期**：`S1=True, S2=False, S3=False`。若不符，检查 `base.py:_is_leaking` 数学。

### 2.3 per-PID 聚合 + 栈归因单测
```bash
python3 - <<'PY'
import sys; sys.path.insert(0, '.')
from core.aggregator import Aggregator
from analyzer.memory import MemoryLeakDetector
from core.config import load_config
agg = Aggregator()
agg.on_mem_event({"pid":1001,"op":'a',"size":4096,"stack_cnt":1,"stack_addrs":[0x400000],"comm":"p1"})
agg.on_mem_event({"pid":1001,"op":'a',"size":4096,"stack_cnt":1,"stack_addrs":[0x500000],"comm":"p1"})  # 第二 sid
det = MemoryLeakDetector(load_config())
items = list(det._iter_stats(agg))
print('count:', len(items))               # 1（per-PID 聚合，非 2）
print('pid:', items[0][0], 'val:', items[0][1])  # 1001, 4096*2*100=819200
print('has stack:', len(items[0][3])>0)   # True（取某 sid 栈）
PY
```
**预期**：`count: 1`（原 per-sid 会是 2）；`pid 1001`；`has stack: True`。

---

## 阶段 3：本地 x86 VM 集成验证

### 3.1 编译测试程序
```bash
cd tests/leak_programs
gcc -O2 mem_leak.c     -o mem_leak
gcc -O2 steady_alloc.c -o steady_alloc
gcc -O2 slow_start.c   -o slow_start
```

### 3.2 启动 leakdetect（真后端）
```bash
cd ~/workspace/leakdetect
sudo ./start.sh    # 或 sudo env PYTHONPATH=py-packages:. python3 web/app.py
# 另开终端验证后端真起（非 mock）
curl -s http://127.0.0.1:8080/api/config/monitoring | python3 -m json.tool | grep -E "grace_seconds|outstanding_delta_bytes"
# 预期：outstanding_delta_bytes: 10240；grace_seconds: 120（三资源都有）
```

### 3.3 真阳性回归：mem_leak 必须告警
```bash
./tests/leak_programs/mem_leak &
# 等 60-150s（grace 120 + 检测窗口）
# 浏览器/REST 看告警
curl -s http://127.0.0.1:8080/api/containers   # 确认非 mock（真后端空容器或真容器）
# 看 dashboard mem 卡片：该 PID outstanding 持续涨；告警区出现 mem leak 告警，栈含 malloc→main
```
**预期**：120s 内出现 mem leak 告警；栈含 `malloc`/`main`。改前改后都应告警（真阳性不回归）。

### 3.4 噪声反例：steady_alloc 不得告警（核心）
```bash
./tests/leak_programs/steady_alloc &   # 跑 25 分钟
# 改前对照（可选）：先在不打驱逐的旧 .o 上跑 → ~17min 起 mem 卡片飙升、误报告警
# 改后（驱逐+斜率检测）：
#   - mem 卡片 outstanding 25min 全程持平（不飙升）→ 驱逐修复饱和
#   - 无 mem leak 告警 → 斜率+显著性不误报噪声
curl -s http://127.0.0.1:8080/api/history?resource=mem&range=1d | python3 -c "import sys,json;d=json.load(sys.stdin);print('points:',len(d['series']),'last:',d['series'][-1] if d['series'] else None)"
```
**预期**：25min 内 steady_alloc 进程 mem 值持平、无告警。若飙升 → 驱逐未生效（查 .o 是否重编）。若误报告警 → 斜率/地板配置问题。

### 3.5 启动宽限：slow_start 不得告警
```bash
./tests/leak_programs/slow_start &   # 爬坡 90s + 稳态 540s
# 爬坡期（0-90s）：outstanding 快速涨（40KB/s 斜率），但 grace=120 > ramp=90 → 不判定 → 不告警
# 爬坡后稳态：斜率≈0 → 不告警
```
**预期**：全程无告警。若爬坡期告警 → grace 未生效（查 `first_seen` 设置 + `grace_seconds` 值）。

---

## 阶段 4：配置/UI 验证

### 4.1 监控配置页（浏览器）
- 进入"监控配置"页 → 各资源：
  - 内存首行"增长斜率阈值"，值 10240，单位"字节/秒"。
  - 新增"启动宽限期"行，值 120。
  - "趋势检测窗口"行（原 leak_seconds），desc 不再提"80%单调递增"。
- 改 grace_seconds 为 60 → 保存 → 重新进页应保留 60（运行时生效）。
- 改斜率阈值 → 保存 → 后端日志 `[backend] monitoring config updated`。

### 4.2 REST 校验
```bash
# get 含 grace_seconds，不含 significance_z（config-only）
curl -s http://127.0.0.1:8080/api/config/monitoring | python3 -m json.tool
# 预期：三资源有 grace_seconds；无 significance_z 键

# 改 grace_seconds 并验证热更新
curl -s -X POST http://127.0.0.1:8080/api/config/monitoring \
  -H 'Content-Type: application/json' \
  -d '{"mem":{"grace_seconds":90,"outstanding_delta_bytes":10240,"observe_seconds":30,"leak_seconds":60,"clear_ratio":0.5,"clear_seconds":30,"resolve_seconds":60,"stabilize_seconds":300}}'
# 预期 {"status":"applied"}；再 GET 确认 grace_seconds=90
```

---

## 阶段 5：arm64 K8s 节点（dfx-syn01）环境验证

### 5.1 打包 + 部署
```bash
# x86 构建机交叉打包
bash tools/package_arm.sh 3.9
scp dist/leakdetect-aarch64-py3.9.tar.gz <user>@<节点>:~/
# 节点上
tar xzf leakdetect-aarch64-py3.9.tar.gz; cd leakdetect-aarch64-py3.9
sudo ./start.sh
```

### 5.2 饱和假说确认（用户环境症状）
> 用户原观测：某些长跑进程 mem"快速上涨"，但若真则环境早崩 → 怀疑饱和伪增长。
```bash
# 启动后选"宿主机"，观察之前"快速上涨"的进程
# 浏览器看 mem 卡片历史曲线：
#   - 改后若回平（不再线性飙升）→ 确认是 allocs/fd_map 饱和，驱逐修复生效
#   - 改后仍涨 → 非饱和，转 VmRSS 交叉核对（见 5.3）
curl -s 'http://127.0.0.1:8080/api/history?resource=mem&range=1d' | python3 -c "import sys,json;d=json.load(sys.stdin);s=d['series'];print('first:',s[0]['v'] if s else None,'last:',s[-1]['v'] if s else None)"
```

### 5.3 若仍涨（非饱和）→ VmRSS 交叉核对
```bash
# 取嫌疑进程 PID，对比 leakdetect 显示值 vs 真实 RSS
PID=<嫌疑pid>
cat /proc/$PID/status | grep VmRSS              # 真实 RSS（KB）
curl -s http://127.0.0.1:8080/api/...           # leakdetect 显示的该 PID outstanding
# 若显示值 ×100 >> VmRSS×1024 → 测量仍不可信 → 查别的原因（如 libc 自身缓存、或该进程真在长）
```

### 5.4 thread/fd 斜率默认值校准
```bash
# 观察 thread/fd 稳态进程是否误报；若误报多 → 调高 delta_threshold（如 thread 0.1→0.2）
# 若漏报慢泄露 → 调低
# 通过监控配置页热调，无需重启
```

### 5.5 宿主误报数 改前/改后对比
- 改前（旧包）：记录 1h 内 mem 误报告警数。
- 改后（新包）：同 1h 误报告警数应大幅下降（接近 0，除真实泄露）。

---

## 阶段 6：回归检查

| 项 | 命令/观察 | 预期 |
|---|---|---|
| threads 检测仍工作 | 跑 `thread_leak` 合成程序 | 告警（thread leak） |
| fd 检测仍工作 | 跑 `fd_leak` 合成程序 | 告警（fd leak） |
| CPU 卡片 | dashboard CPU 卡 | 实时占用率正常（未动） |
| 容器选择 | 切换容器下拉 | per_process 按容器过滤（Phase 1 未动） |
| 自身进程 | dashboard 不含 leakdetect python3 的 mem 告警 | 不再"自己告自己" |
| 历史曲线 | `/api/history` 各资源 | 仍返回数据 |

---

## 阶段 7：回滚

若任一阶段失败且阻塞使用：
```bash
# BPF 层问题：恢复旧 .o（git checkout 旧 mem.o/fd.o）+ 重编
# 分析层问题：git checkout analyzer/base.py analyzer/memory.py analyzer/threads.py analyzer/handles.py config/default.yaml web/backend.py web/mock.py web/static/js/components/monitoring-config.js
# 恢复后旧检测器（双条件）+ 旧阈值回归
```
注：分析层与分析层可独立回滚（BPF 驱逐与分析器斜率检测互不依赖）。

---

## 验证矩阵汇总

| 阶段 | 验证点 | 通过判据 |
|---|---|---|
| 1 | BPF 重编 + 加载 | `BPF load OK`，verifier 无报错 |
| 2.2 | _is_leaking 数学 | S1=True, S2/S3=False |
| 2.3 | per-PID 聚合 | count=1（非 2） |
| 3.3 | mem_leak 真阳性 | 120s 内告警 |
| 3.4 | steady_alloc 噪声反例 | 25min 无告警 + mem 持平 |
| 3.5 | slow_start 启动宽限 | 全程无告警 |
| 4 | 配置/UI | grace 行+斜率标签生效，热更新 |
| 5.2 | 饱和假说 | 长跑进程 mem 回平 |
| 6 | 回归 | threads/fd/cpu/容器/历史均正常 |

# 应急通道的跨域信任撤销与封存回执

离线模拟应急值班系统的跨域消息承诺与中继资格撤销：消息暂存于两条本地通道，
提交绑定 **消息摘要 + 两个独立中继见证 + 当前授权代**；同一信任根下的多个
见证在法定人数中只算一个。全程仅使用 Python 3.12 标准库，无网络依赖。

## 运行

```bat
python demo.py            :: 三交错复测 + 小模型枚举/差分 + 60000 条消息压测
python demo.py --quick    :: 跳过六万条压测
python -m unittest discover -s tests -v
```

落盘产物默认写入 `artifacts/run/`（含 `scenario-report.json`、
`minimodel-enumeration.json`、`minidiff-report.json`、`benchmark-report.json`）。

## 模块结构

| 模块 | 职责 |
| --- | --- |
| `dutyrelay/crypto.py` | SHA-256 消息摘要；HMAC-SHA256 离线见证与核验（替代真实根签名） |
| `dutyrelay/types.py` | 提交/见证/裁决类型，统一原因码 `R`（OK 与各类拒绝证据） |
| `dutyrelay/logstore.py` | 只追加提交日志：长度前缀 + CRC32 帧，追加 fsync，尾部半帧重放时截断 |
| `dutyrelay/segments.py` | 两通道分段暂存、清单 `may_have_pending` 标记、访问仪表 `AccessStats` |
| `dutyrelay/registry.py` | 信任根/中继注册表、根撤销代、当前授权代（原子 JSON 落盘） |
| `dutyrelay/engine.py` | 离线核验、两阶段提交、撤销清扫、搬迁、旧回执核验与崩溃恢复裁决 |
| `dutyrelay/barriers.py` | 可控屏障与承诺/撤销两个工作线程 |
| `dutyrelay/minimodel.py` | 独立小模型：不依赖引擎的内存状态机，枚举短交错的可见集与拒绝证据 |
| `dutyrelay/minidiff.py` | 小模型与真实落盘引擎的逐操作差分比对 |
| `dutyrelay/scenarios.py` | 三种受控交错 + 重启恢复的断言式复测 |
| `dutyrelay/benchmark.py` | 60000 条消息压测与选择性/全量扫描对账 |

## 裁决规则（提交序 LSN/CSN 为唯一裁决依据）

1. 见证少于两个 → `QUORUM_COUNT`；两个见证归属同一信任根 → `QUORUM_TRUST`。
2. 中继未知、冒认信任根、HMAC 不符 → `WITNESS_*` 拒绝并落盘证据。
3. 见证根在绑定授权代已撤销 → `WITNESS_ROOT_REVOKED`；提交代 ≠ 当前代
   → `EPOCH_STALE`。旧代内已落盘的 COMMIT 不受后续撤销影响。
4. `(通道, 序号, 搬迁代)` 定位符已绑定别的摘要 → `DIGEST_MISMATCH`
   （搬迁后同号不同摘要）；重复摘要走 `DUPLICATE_COMMIT`，不分配新 CSN。
5. 撤销先把所有未承诺暂存消息固化为 `REVOKED_UNCOMMITTED` 拒绝证据，
   再写 REVOKE 记录并推进授权代——REVOKE 的 LSN 即裁决分界。
6. 回执只认真实落盘过的承诺；合法旧回执幂等确认、绝不重投，找不到承诺的
   回执给 `RECEIPT_UNKNOWN`。

## 三种交错复测（`scenarios.py`，全部含重启恢复）

- **准备完成但撤销已提交**：屏障把提交线程挂在 prepared，撤销线程先落盘
  REVOKE；恢复后旧代重投必被 `EPOCH_STALE` 拒，重新审批（新代+有效双根）
  才能承诺，COMMIT 数量不增加。
- **搬迁后同号不同摘要**：提交挂起期间通道搬迁；同序号新摘要被
  `DIGEST_MISMATCH` 拒，迟到的合法旧回执幂等确认，伪造/幽灵回执分别给
  `DIGEST_MISMATCH` / `RECEIPT_UNKNOWN`；恢复后旧承诺仍可见。
- **承诺已落盘但回执丢失**：COMMIT fsync 后删除回执并向日志注入半帧；
  重放截断半帧、按日志补写且仅补写缺失回执，全程只有一条 COMMIT。

## 六万条消息压测

两通道各 30000 条、分段容量 1000：目标通道前 27 段全部承诺、后 3 段
（3000 条）只暂存，另一通道全部承诺。维护收紧清单后，单通道撤销只打开
3 个有关分段、检查 3000 条记录；全量扫描需打开 30 段、检查 30000 条；
另一通道访问量为零。选择性与全量得到的未承诺集合逐摘要一致，且与撤销
落盘的拒绝证据集合完全相等。压测以 `durable=False` 跳过行级 fsync 以聚焦
访问量语义，崩溃持久性由上述三个故障注入场景在 `durable=True` 下证明。

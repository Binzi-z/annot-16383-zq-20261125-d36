"""三种受控交错的复测与崩溃恢复证明。

每个场景用 Barrier 精确挂起工作线程，制造题面要求的交错，再模拟进程重启
（只信任磁盘重放日志），并断言两条安全性质：
  P1 不重投旧代：旧授权代的消息不会产生新的 COMMIT，旧回执只做幂等确认；
  P2 不丢有效承诺：落盘时已通过裁决的消息在恢复后必然仍在可见集中。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .barriers import Barrier, CommitWorker, RevokeWorker
from .engine import Engine
from .factory import CHANNELS, TOPOLOGY, make_submission, new_engine
from .types import R


@dataclass
class ScenarioResult:
    name: str
    description: str
    barrier_order: list[tuple[str, str]]
    assertions: list[tuple[str, bool, str]] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def check(self, label: str, condition: bool, detail: str = "") -> None:
        self.assertions.append((label, bool(condition), detail))

    @property
    def passed(self) -> bool:
        return all(ok for _, ok, _ in self.assertions)


def _commit_log_summary(eng: Engine) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rec in eng.log.replay():
        counts[rec["type"]] = counts.get(rec["type"], 0) + 1
    return dict(sorted(counts.items()))


def scenario_prepared_but_revoked(base: Path) -> ScenarioResult:
    """交错一：提交已 prepare（暂存落盘），撤销线程抢先把 REVOKE 落盘。"""
    res = ScenarioResult(
        "interleaving-1-prepared-but-revoked",
        "准备完成但撤销已提交：COMMIT 线程挂在 prepared，REVOKE 先落盘",
        barrier_order=[])
    eng = new_engine(base / "case1")
    sub = make_submission(eng, CHANNELS[0], 101, b"emergency-bulletin-101")
    barrier = Barrier(hold_points={"prepared", "revoked", "committed"})
    commit_w = CommitWorker(eng, sub, barrier, name="commit-worker")
    revoke_w = RevokeWorker(eng, "rootB", barrier, channels=CHANNELS,
                            name="revoke-worker")
    commit_w.start()
    assert barrier.wait_until_arrived("prepared"), "提交线程未到达 prepared"
    revoke_w.start()
    assert barrier.wait_until_arrived("revoked"), "撤销线程未完成落盘"
    # 先放行所有门闩再 join，避免线程在已完成裁决后仍挂在收尾检查点上
    barrier.release("prepared")
    barrier.release("revoked")
    barrier.release("committed")
    commit_w.join(timeout=5)
    revoke_w.join(timeout=5)
    assert commit_w.error is None and revoke_w.error is None
    res.barrier_order = barrier.order

    res.check("屏障顺序：revoked 早于 committed",
              [p for _, p in barrier.order].index("revoked")
              < [p for _, p in barrier.order].index("committed"),
              str(barrier.order))
    res.check("提交线程拿到 EPOCH_STALE 拒绝",
              commit_w.result is not None
              and not commit_w.result.accepted
              and commit_w.result.reason == R.EPOCH_STALE,
              "" if commit_w.result is None else commit_w.result.reason)
    res.check("授权代已推进到 1", eng.current_epoch() == 1)
    res.check("摘要未进入承诺集", sub.digest not in eng.committed)
    before = _commit_log_summary(eng)
    res.check("日志含 REVOKE 且无该消息的 COMMIT",
              before.get("REVOKE", 0) == 1 and before.get("COMMIT", 0) == 0,
              json.dumps(before, ensure_ascii=False))
    eng.close()

    # 模拟重启：只信任磁盘
    eng2 = Engine.reopen(base / "case1")
    res.check("恢复后授权代仍为 1", eng2.current_epoch() == 1)
    visible = {v["digest"] for v in eng2.visible_committed()}
    res.check("P2 不丢有效承诺：本就无承诺，可见集为空", visible == set())
    reject_reasons = [e["reason"] for e in eng2.rejection_evidence()]
    res.check("拒绝证据包含 EPOCH_STALE 与 REVOKED_UNCOMMITTED",
              R.EPOCH_STALE in reject_reasons
              and R.REVOKED_UNCOMMITTED in reject_reasons,
              json.dumps(reject_reasons, ensure_ascii=False))
    # 旧代消息在新代重新提交：必须被拒，绝不产生新 COMMIT（P1）
    stale = make_submission(eng2, CHANNELS[0], 101,
                            b"emergency-bulletin-101", epoch=0)
    again = eng2.submit(stale)
    after = _commit_log_summary(eng2)
    res.check("旧代重投被 EPOCH_STALE 拒绝",
              not again.accepted and again.reason == R.EPOCH_STALE)
    res.check("P1 恢复前后 COMMIT 数量不变（不重投旧代）",
              after.get("COMMIT", 0) == before.get("COMMIT", 0) == 0,
              f"before={before} after={after}")
    # 重新审批：按新授权代、由两个仍有效信任根（rootA + rootC）出具见证
    reapproved = make_submission(eng2, CHANNELS[0], 101,
                                 b"emergency-bulletin-101",
                                 roots=("rootA", "rootC"))
    rv = eng2.submit(reapproved)
    res.check("重新审批（新代见证）成功承诺",
              rv.accepted and rv.reason == R.OK,
              rv.reason)
    res.artifacts = {"log_before_recovery": before,
                     "log_after_recovery": _commit_log_summary(eng2),
                     "rejections": reject_reasons}
    eng2.close()
    return res


def scenario_relocate_same_seq(base: Path) -> ScenarioResult:
    """交错二：通道搬迁后序号复用、同号不同摘要，旧回执迟到。

    定位符 (通道, 序号, 搬迁代) 以搬迁代划分命名空间：
      搬迁前 gen0 的承诺与搬迁后 gen1 的同号消息互不冲突；
      同一搬迁代内同号绑定不同摘要才是 DIGEST_MISMATCH。
    """
    res = ScenarioResult(
        "interleaving-2-relocate-same-seq-different-digest",
        "搬迁后同号不同摘要：跨代序号合法复用、同代冲突被拒、旧回执幂等",
        barrier_order=[])
    eng = new_engine(base / "case2")
    ch = CHANNELS[0]
    # 搬迁前：gen0 序号 202 的旧消息完整承诺
    old_sub = make_submission(eng, ch, 202, b"old-generation-body")
    old_v = eng.submit(old_sub)
    res.check("搬迁前旧消息在 gen0 承诺",
              old_v.accepted and eng.locator[(ch, 202, 0)] == old_sub.digest)

    # 搬迁与新消息 prepare 交错：序号 203 在 gen0 期间 prepare，
    # 挂起期间执行 RELOCATE，放行后在 gen1 落盘承诺
    hold_sub = make_submission(eng, ch, 203, b"held-across-relocation")
    barrier = Barrier(hold_points={"prepared"})
    commit_w = CommitWorker(eng, hold_sub, barrier, name="commit-worker")
    commit_w.start()
    assert barrier.wait_until_arrived("prepared")
    reloc = eng.relocate(ch)
    barrier.release("prepared")
    commit_w.join(timeout=5)
    assert commit_w.error is None
    res.barrier_order = barrier.order
    res.check("搬迁完成，搬迁代=1", reloc.accepted
              and eng.reloc_gen[ch] == 1)
    res.check("prepare 跨越搬迁的消息在新命名空间 gen1 承诺",
              commit_w.result.accepted and commit_w.result.reason == R.OK
              and eng.locator[(ch, 203, 1)] == hold_sub.digest,
              "" if commit_w.result is None else commit_w.result.reason)

    # 搬迁后序号 202 复用：同号不同摘要，但属于新命名空间 gen1，合法
    new_sub = make_submission(eng, ch, 202, b"new-generation-body")
    new_v = eng.submit(new_sub)
    res.check("跨代同号不同摘要在新命名空间 gen1 合法承诺",
              new_v.accepted and new_v.reason == R.OK
              and eng.locator[(ch, 202, 1)] == new_sub.digest,
              new_v.reason)

    # 同一搬迁代 gen1 内同号再来第三个摘要：定位符冲突
    third = make_submission(eng, ch, 202, b"third-body")
    rv = eng.submit(third)
    res.check("同代同号不同摘要被 DIGEST_MISMATCH 拒绝并附绑定证据",
              not rv.accepted and rv.reason == R.DIGEST_MISMATCH
              and rv.evidence["existing_digest"] == new_sub.digest,
              rv.reason)

    # gen0 迟到的合法旧回执：承诺有效，幂等确认，不重投
    receipt = eng.inbound_receipt(ch, 202, old_sub.digest, 0)
    res.check("gen0 合法旧回执幂等确认（不重投）",
              receipt.accepted and receipt.reason == R.OK
              and receipt.evidence.get("receipt_already_present") is True)
    # 已承诺摘要但声明错误搬迁代：定位符不一致
    wrong_gen = eng.inbound_receipt(ch, 202, new_sub.digest, 0)
    res.check("摘要存在但搬迁代不符的回执被 DIGEST_MISMATCH 拒绝",
              not wrong_gen.accepted
              and wrong_gen.reason == R.DIGEST_MISMATCH)
    # 无中生有的回执：使用从未出现过的定位符（序号 999）
    ghost = eng.inbound_receipt(ch, 999, "deadbeef" * 8, 1)
    res.check("无对应承诺且无定位符绑定的回执被 RECEIPT_UNKNOWN 拒绝",
              not ghost.accepted and ghost.reason == R.RECEIPT_UNKNOWN)
    before = _commit_log_summary(eng)
    eng.close()

    eng2 = Engine.reopen(base / "case2")
    visible = {v["digest"] for v in eng2.visible_committed()}
    res.check("P2 恢复后两代有效承诺均仍可见",
              old_sub.digest in visible and new_sub.digest in visible)
    res.check("被拒的同代冲突消息不在可见集", third.digest not in visible)
    receipt2 = eng2.inbound_receipt(ch, 202, old_sub.digest, 0)
    res.check("P1 恢复后旧回执仍只做幂等确认、不新增 COMMIT",
              receipt2.accepted and receipt2.reason == R.OK
              and _commit_log_summary(eng2).get("COMMIT", 0)
              == before.get("COMMIT", 0))
    res.artifacts = {"log_summary": before,
                     "visible": sorted(visible),
                     "locator": {f"{k[0]}#{k[1]}#gen{k[2]}": v
                                 for k, v in eng2.locator.items()}}
    eng2.close()
    return res


def scenario_commit_then_receipt_lost(base: Path) -> ScenarioResult:
    """交错三：COMMIT 已 fsync，回执文件丢失/尾部帧截断后重启。"""
    res = ScenarioResult(
        "interleaving-3-commit-fsynced-receipt-lost",
        "承诺已落盘但回执丢失：恢复按日志补回执，不重复承诺、不丢消息",
        barrier_order=[])
    eng = new_engine(base / "case3")
    ch = CHANNELS[1]
    sub = make_submission(eng, ch, 303, b"sealed-order-303",
                          roots=("rootA", "rootC"))
    barrier = Barrier(hold_points={"committed"})
    commit_w = CommitWorker(eng, sub, barrier, name="commit-worker",
                            write_receipt=True)
    commit_w.start()
    assert barrier.wait_until_arrived("committed")
    barrier.release("committed")
    commit_w.join(timeout=5)
    assert commit_w.error is None and commit_w.result.accepted
    res.barrier_order = barrier.order
    res.check("承诺已落盘并取得 CSN", commit_w.result.csn == 1)
    res.check("回执初始存在", eng.has_receipt(sub.digest))

    # 故障注入一：回执文件丢失
    assert eng.drop_receipt(sub.digest)
    res.check("回执已被删除（模拟丢失）", not eng.has_receipt(sub.digest))
    before = _commit_log_summary(eng)
    eng.close()

    # 故障注入二：在日志尾部追加半帧，模拟崩溃瞬间写了一半的记录
    log_path = base / "case3" / "commit.log"
    with open(log_path, "ab") as fh:
        fh.write(b"DLOG\x10\x00\x00\x00\xff\xff\xff\xff{\"half")
    eng2 = Engine.reopen(base / "case3")
    res.check("重放自动截断尾部半帧，已落盘 COMMIT 不受影响",
              _commit_log_summary(eng2).get("COMMIT", 0) == 1)
    visible = {v["digest"] for v in eng2.visible_committed()}
    res.check("P2 丢回执不丢承诺：消息仍在可见集", sub.digest in visible)

    repaired = eng2.recover_pending_receipts()
    res.check("恢复按日志补写且仅补写缺失回执",
              repaired == [sub.digest] and eng2.has_receipt(sub.digest),
              json.dumps(repaired))
    # 重复恢复必须无副作用
    again = eng2.recover_pending_receipts()
    res.check("再次恢复无回执可补（幂等）", again == [])
    # 迟到回执与重投：都不允许产生第二个 COMMIT
    receipt = eng2.inbound_receipt(ch, 303, sub.digest, 0)
    res.check("迟到回执幂等确认", receipt.accepted and receipt.reason == R.OK)
    replay = eng2.submit(make_submission(eng2, ch, 303, b"sealed-order-303",
                                         roots=("rootA", "rootC")))
    res.check("重复提交走 DUPLICATE_COMMIT，不产生新 CSN",
              replay.accepted and replay.reason == R.DUPLICATE_COMMIT
              and replay.csn == 1)
    after = _commit_log_summary(eng2)
    res.check("P1 全程只有一条 COMMIT（不重投）",
              after.get("COMMIT", 0) == 1
              and before.get("COMMIT", 0) == after.get("COMMIT", 0),
              f"before={before} after={after}")
    res.artifacts = {"log_before": before, "log_after": after,
                     "repaired_receipts": repaired}
    eng2.close()
    return res


def run_all_scenarios(base: str | Path) -> list[ScenarioResult]:
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    results = [
        scenario_prepared_but_revoked(base),
        scenario_relocate_same_seq(base),
        scenario_commit_then_receipt_lost(base),
    ]
    report = {
        "topology": TOPOLOGY,
        "channels": CHANNELS,
        "results": [
            {"name": r.name, "description": r.description,
             "passed": r.passed,
             "barrier_order": [list(x) for x in r.barrier_order],
             "assertions": [{"label": a, "passed": ok, "detail": d}
                            for a, ok, d in r.assertions],
             "artifacts": r.artifacts}
            for r in results],
    }
    out = base / "scenario-report.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return results

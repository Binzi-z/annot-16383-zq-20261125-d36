"""大批量压测：至少六万条消息，核对单通道撤销的选择性访问与全量对账。

布局（两条本地通道，分段容量 1000）：
  ch_north 30000 条 = 30 个分段
      前 27 个分段（27000 条）全部已承诺，维护后清单收紧为整段解决；
      后 3 个分段（3000 条）只暂存不承诺，是撤销必须找出的未承诺消息。
  ch_south 30000 条全部已承诺（单通道撤销时它的任何分段都不得被访问）。
  合计 60000 条合成消息。

测量三组访问量（由 AccessStats 在存储层计数）：
  1) 单通道选择性撤销扫描：只打开"可能含未承诺消息"的有关分段；
  2) 同通道完整全量扫描：打开全部分段，作为结果对账基准；
  3) 另一通道在本次撤销中的访问量：分段打开数与记录检查数必须为零。
并断言选择性扫描与全量扫描得到的未承诺集合逐摘要一致、
撤销落盘的拒绝证据恰好覆盖该集合，且选择性检查量严格小于全量。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .crypto import make_witness, message_digest
from .engine import Engine
from .factory import CHANNELS, TOPOLOGY
from .segments import AccessStats
from .types import R, Submission

TOTAL_MESSAGES = 60_000
PER_CHANNEL = TOTAL_MESSAGES // 2
SEGMENT_CAPACITY = 1_000
# 目标通道最后 PENDING_SEGMENTS 个分段只暂存不承诺
PENDING_SEGMENTS = 3


@dataclass
class BenchmarkReport:
    total_messages: int
    segment_capacity: int
    elapsed_seconds: float
    channels: dict[str, dict[str, Any]] = field(default_factory=dict)
    revocation: dict[str, Any] = field(default_factory=dict)
    consistency: dict[str, Any] = field(default_factory=dict)
    passed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_messages": self.total_messages,
            "segment_capacity": self.segment_capacity,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "channels": self.channels,
            "revocation": self.revocation,
            "consistency": self.consistency,
            "passed": self.passed,
        }


def _make_sub(eng: Engine, channel: str, seq: int) -> Submission:
    # 确定性摘要：不依赖随机源，重放可复现
    digest = message_digest(channel, seq, f"payload-{channel}-{seq}".encode())
    witnesses = []
    for root in ("rootA", "rootB"):
        relay = next(r for r, rr in eng.registry.relay_root.items() if rr == root)
        witnesses.append(make_witness(channel, seq, digest,
                                      eng.current_epoch(), relay, root,
                                      eng.registry.root_keys[root]))
    return Submission(channel, seq, digest, eng.current_epoch(),
                      tuple(witnesses))


def run_benchmark(base: str | Path, *, total: int = TOTAL_MESSAGES,
                  segment_capacity: int = SEGMENT_CAPACITY) -> BenchmarkReport:
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    per_channel = total // len(CHANNELS)
    if per_channel % segment_capacity != 0:
        raise ValueError("每通道消息数必须是分段容量的整数倍")
    segments_per_channel = per_channel // segment_capacity
    pending_cutoff = (segments_per_channel - PENDING_SEGMENTS) * segment_capacity
    report = BenchmarkReport(total_messages=per_channel * len(CHANNELS),
                             segment_capacity=segment_capacity,
                             elapsed_seconds=0.0)
    started = time.perf_counter()

    # durable=False：压测关注访问量与对账正确性；崩溃持久性由 scenarios 覆盖
    eng = Engine.create(base / "store", TOPOLOGY, CHANNELS,
                        segment_capacity=segment_capacity, durable=False)
    pending_digests: dict[str, set[str]] = {ch: set() for ch in CHANNELS}
    committed_count = 0
    staged_count = 0
    for channel in CHANNELS:
        for seq in range(per_channel):
            sub = _make_sub(eng, channel, seq)
            is_pending_segment = (channel == CHANNELS[0]
                                  and seq >= pending_cutoff)
            if is_pending_segment:
                v = eng.prepare(sub)  # 只暂存不承诺
                if not v.accepted:
                    raise AssertionError(f"暂存失败 {channel}#{seq}: {v.reason}")
                pending_digests[channel].add(sub.digest)
                staged_count += 1
            else:
                v = eng.submit(sub, write_receipt=False)
                if not v.accepted:
                    raise AssertionError(f"承诺失败 {channel}#{seq}: {v.reason}")
                committed_count += 1
    eng.close()

    # 重启：只信任磁盘，重建承诺索引与通道清单（durable 标志由 layout 携带）
    eng = Engine.reopen(base / "store")
    assert len(eng.committed) == committed_count
    target_channel = CHANNELS[0]
    other_channel = CHANNELS[1]
    expected = sorted(pending_digests[target_channel])

    # 维护：把已全部承诺的封存分段在清单上收紧（独立仪表，不计入撤销测量）。
    # 收紧后选择性扫描才能跳过这些分段——这是"只访问有关分段"的清单依据。
    maint_stats = AccessStats()
    resolved = 0
    for ch in CHANNELS:
        resolved += eng.reconcile_channel(ch, maint_stats)

    # 撤销前两组基准测量：选择性扫描（只打开有关分段）vs 完整全量扫描
    pre_sel_stats = AccessStats()
    pre_sel_pending = eng.reapproval_candidates(
        target_channel, full=False, stats=pre_sel_stats)
    pre_full_stats = AccessStats()
    pre_full_pending = eng.reapproval_candidates(
        target_channel, full=True, stats=pre_full_stats)
    pre_sel_digests = sorted(r["digest"] for r in pre_sel_pending)
    pre_full_digests = sorted(r["digest"] for r in pre_full_pending)
    assert pre_sel_digests == expected == pre_full_digests

    channel_info: dict[str, dict[str, Any]] = {}
    for ch in CHANNELS:
        store = eng.channels[ch]
        sealed = [s for s in store.manifest["segments"] if s["sealed"]]
        channel_info[ch] = {
            "staged_records": store.total_records(),
            "segment_total": store.segment_count(),
            "sealed_segments": len(sealed),
            "segments_marked_pending":
                sum(1 for s in store.manifest["segments"]
                    if s["may_have_pending"]),
            "segments_marked_resolved":
                sum(1 for s in sealed if not s["may_have_pending"]),
            "known_pending_digests": len(pending_digests[ch]),
        }

    # ---- 测量 1：单通道选择性撤销（只访问有关分段） ----
    sel_stats = AccessStats()
    other_stats = AccessStats()
    revoke_verdict = eng.revoke_root(
        "rootB", channels=[target_channel],
        stats={target_channel: sel_stats, other_channel: other_stats})
    assert revoke_verdict.accepted

    # ---- 测量 2：同通道完整全量扫描（对账基准，独立新仪表）。
    # 撤销只落盘拒绝证据，不删除暂存行：这些消息仍是"必须重新审批"集合，
    # 全量扫描结果必须与撤销前逐摘要一致。 ----
    full_stats = AccessStats()
    full_pending = eng.reapproval_candidates(target_channel,
                                             full=True, stats=full_stats)
    full_digests = sorted(r["digest"] for r in full_pending)

    # 撤销落盘的拒绝证据必须恰好覆盖目标通道全部未承诺消息
    revoked_evidence = [e for e in eng.rejection_evidence()
                        if e["reason"] == R.REVOKED_UNCOMMITTED]
    revoked_digests = sorted(e["evidence"]["digest"] for e in revoked_evidence)

    report.elapsed_seconds = time.perf_counter() - started
    report.channels = channel_info
    report.revocation = {
        "target_channel": target_channel,
        "revoke_lsn": revoke_verdict.lsn,
        "new_epoch": eng.current_epoch(),
        "pre_revoke_selective_scan": pre_sel_stats.to_dict(),
        "pre_revoke_full_scan": pre_full_stats.to_dict(),
        "revoke_selective_scan": sel_stats.to_dict(),
        "post_revoke_full_scan": full_stats.to_dict(),
        "other_channel_access": other_stats.to_dict(),
        "maintenance_scan": maint_stats.to_dict(),
        "resolved_segments": resolved,
        "revoked_uncommitted_evidence": len(revoked_evidence),
    }
    report.consistency = {
        "expected_pending_count": len(expected),
        "pre_revoke_selective_equals_expected": pre_sel_digests == expected,
        "pre_revoke_full_equals_expected": pre_full_digests == expected,
        "post_revoke_full_still_lists_reapproval_set":
            full_digests == expected,
        "revocation_evidence_equals_expected": revoked_digests == expected,
        "selective_opens_fewer_segments":
            pre_sel_stats.segment_opens < pre_full_stats.segment_opens,
        "selective_inspects_fewer_records":
            pre_sel_stats.records_inspected < pre_full_stats.records_inspected,
        "revoke_touches_only_relevant_segments":
            sel_stats.segment_opens == PENDING_SEGMENTS
            and sel_stats.records_inspected
            == PENDING_SEGMENTS * segment_capacity,
        "other_channel_zero_access":
            other_stats.segment_opens == 0
            and other_stats.records_inspected == 0,
        "full_scan_opens_every_segment":
            pre_full_stats.segment_opens == segments_per_channel
            and pre_full_stats.records_inspected == per_channel,
    }
    report.passed = all(report.consistency.values())

    out = base / "benchmark-report.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, ensure_ascii=False, indent=2)
    eng.close()
    return report

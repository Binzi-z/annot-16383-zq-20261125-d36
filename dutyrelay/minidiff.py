"""小模型 vs 真实引擎的差分比对。

把 minimodel 枚举出的每条调度在真实落盘引擎上重放一遍，逐操作比对
裁决原因，并比对最终可见承诺集合与拒绝证据原因序列。任何不一致都作为
差分失败抛出；全部一致时返回统计摘要。
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import minimodel as mm
from .crypto import make_witness, message_digest
from .engine import Engine
from .types import R, Submission

# 小模型原因码 -> 引擎原因码（两套独立声明，这里做显式映射核对）
_REASON_MAP = {
    mm.OK: R.OK,
    mm.QUORUM_TRUST: R.QUORUM_TRUST,
    mm.QUORUM_COUNT: R.QUORUM_COUNT,
    mm.WITNESS_BAD: R.WITNESS_BAD,
    mm.WITNESS_RELAY_UNKNOWN: R.WITNESS_RELAY_UNKNOWN,
    mm.WITNESS_ROOT_REVOKED: R.WITNESS_ROOT_REVOKED,
    mm.EPOCH_STALE: R.EPOCH_STALE,
    mm.DIGEST_MISMATCH: R.DIGEST_MISMATCH,
    mm.REVOKED_UNCOMMITTED: R.REVOKED_UNCOMMITTED,
    mm.DUPLICATE_COMMIT: R.DUPLICATE_COMMIT,
    mm.RECEIPT_UNKNOWN: R.RECEIPT_UNKNOWN,
}


@dataclass
class DiffReport:
    interleavings_checked: int
    mismatches: list[dict[str, Any]]
    reason_coverage: dict[str, int]

    @property
    def passed(self) -> bool:
        return not self.mismatches


def _build_submissions(eng: Engine, channel: str, topology: dict[str, list[str]]):
    """构造与小模型 m1/m2 逐字段对应的真实 Submission（含合法 HMAC 见证）。"""
    keys = eng.registry.root_keys
    roots = list(topology)

    def one(seq: int, digest: str, epoch: int, witness_roots: tuple[str, ...]):
        witnesses = []
        for root in witness_roots:
            relay = next(r for r, rr in eng.registry.relay_root.items()
                         if rr == root)
            witnesses.append(make_witness(channel, seq, digest, epoch,
                                          relay, root, keys[root]))
        return Submission(channel, seq, digest, epoch, tuple(witnesses))

    m1 = one(1, "digest-m1", 0, tuple(roots[:2]))
    # 同一信任根下两个不同中继的见证：法定人数按独立根折算后只有一个
    root = roots[0]
    relays = [r for r, rr in eng.registry.relay_root.items() if rr == root]
    w1 = make_witness(channel, 2, "digest-m2", 0, relays[0], root, keys[root])
    w2 = make_witness(channel, 2, "digest-m2", 0, relays[1], root, keys[root])
    m2 = Submission(channel, 2, "digest-m2", 0, (w1, w2))
    return m1, m2


def run_differential(base_dir: str | Path | None = None) -> DiffReport:
    topology = {"rootA": ["relay-A1", "relay-A2"], "rootB": ["relay-B1"]}
    channels = ["ch1", "ch2"]
    interleavings = mm.enumerate_interleavings(topology, channels)
    mismatches: list[dict[str, Any]] = []
    coverage: dict[str, int] = {}

    owner = tempfile.TemporaryDirectory() if base_dir is None else None
    base = Path(base_dir) if base_dir is not None else Path(owner.name)
    try:
        for index, item in enumerate(interleavings):
            run_dir = base / f"diff-{index:04d}"
            eng = Engine.create(run_dir, topology, channels)
            m1, m2 = _build_submissions(eng, channels[0], topology)
            engine_outcomes: list[tuple[str, bool, str]] = []
            for label in item.schedule:
                if label == "prepare:m1":
                    v = eng.prepare(m1)
                elif label == "commit:m1":
                    v = eng.commit_prepared(m1)
                elif label == "commit:m2":
                    v = eng.submit(m2)
                elif label == "revoke":
                    v = eng.revoke_root("rootB", channels=channels)
                elif label == "relocate":
                    v = eng.relocate(channels[0])
                else:
                    raise AssertionError(label)
                engine_outcomes.append((label, v.accepted, v.reason))
            # 逐操作原因比对
            for (label, ok_m, r_m), (_l2, ok_e, r_e) in zip(
                    item.outcomes, engine_outcomes):
                coverage[r_m] = coverage.get(r_m, 0) + 1
                expected = _REASON_MAP[r_m]
                if ok_m != ok_e or expected != r_e:
                    mismatches.append({
                        "schedule": list(item.schedule), "op": label,
                        "mini": (ok_m, r_m), "engine": (ok_e, r_e)})
            # 最终可见集比对（摘要集合 + CSN 顺序）
            mini_visible = item.visible_digests
            eng_visible = tuple(v["digest"] for v in eng.visible_committed())
            if mini_visible != eng_visible:
                mismatches.append({
                    "schedule": list(item.schedule),
                    "visible_mini": list(mini_visible),
                    "visible_engine": list(eng_visible)})
            # 拒绝证据原因序列比对（引擎持久化的 REJECT 记录）
            mini_reasons = list(item.rejection_reasons)
            eng_reasons = [e["reason"] for e in eng.rejection_evidence()]
            if sorted(mini_reasons) != sorted(eng_reasons):
                mismatches.append({
                    "schedule": list(item.schedule),
                    "reject_mini": mini_reasons,
                    "reject_engine": eng_reasons})
            eng.close()
    finally:
        if owner is not None:
            owner.cleanup()
    return DiffReport(len(interleavings), mismatches,
                      dict(sorted(coverage.items())))

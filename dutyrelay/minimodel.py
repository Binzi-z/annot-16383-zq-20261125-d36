"""独立小模型：从零实现的内存状态机，枚举短交错并给出可见集/拒绝证据。

设计上刻意不 import dutyrelay.engine——只共享 types 中的原因码字符串约定，
全部状态结构与裁决规则独立重写，再由 tests 与 demo 对真实引擎做差分比对：
两套实现对同一条操作交错必须给出逐字相同的裁决原因与相同的可见集合。

模型抽象（足以覆盖题面全部交错，不含磁盘/线程）：
  消息 m = (channel, seq, digest, epoch)
  见证 = 中继列表；模型只关心其折叠出的独立信任根，另支持"坏见证"注入：
      坏见证类型 unknown_relay / wrong_root / bad_mac / revoked_root
  状态 = 当前授权代、各根撤销代、已承诺摘要、定位符(channel,seq,gen)->digest、
         已暂存摘要、搬迁代、拒绝证据列表
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from typing import Any

# 与 dutyrelay.types.R 逐字一致的原因码（此处独立声明，杜绝隐式耦合）
OK = "OK"
QUORUM_TRUST = "QUORUM_TRUST"
QUORUM_COUNT = "QUORUM_COUNT"
WITNESS_BAD = "WITNESS_BAD"
WITNESS_RELAY_UNKNOWN = "WITNESS_RELAY_UNKNOWN"
WITNESS_ROOT_REVOKED = "WITNESS_ROOT_REVOKED"
EPOCH_STALE = "EPOCH_STALE"
DIGEST_MISMATCH = "DIGEST_MISMATCH"
REVOKED_UNCOMMITTED = "REVOKED_UNCOMMITTED"
DUPLICATE_COMMIT = "DUPLICATE_COMMIT"
RECEIPT_UNKNOWN = "RECEIPT_UNKNOWN"


@dataclass(frozen=True)
class MiniMsg:
    channel: str
    seq: int
    digest: str
    epoch: int
    roots: tuple[str, ...]          # 见证折叠出的信任根（顺序保留）
    witness_fault: str | None = None  # None 表示全部见证合法


@dataclass
class MiniState:
    topology: dict[str, list[str]]                     # root -> relays
    epoch: int = 0
    revoked_at: dict[str, int | None] = field(default_factory=dict)
    reloc_gen: dict[str, int] = field(default_factory=dict)
    committed: dict[str, MiniMsg] = field(default_factory=dict)
    csn_of: dict[str, int] = field(default_factory=dict)
    commit_gen: dict[str, int] = field(default_factory=dict)
    locator: dict[tuple[str, int, int], str] = field(default_factory=dict)
    staged: dict[str, MiniMsg] = field(default_factory=dict)
    rejections: list[dict[str, Any]] = field(default_factory=list)
    csn: int = 0
    lsn: int = 0

    @classmethod
    def fresh(cls, topology: dict[str, list[str]],
              channels: list[str]) -> "MiniState":
        st = cls(topology=topology)
        st.revoked_at = {root: None for root in topology}
        st.reloc_gen = {ch: 0 for ch in channels}
        return st

    def relay_root(self, relay: str) -> str | None:
        for root, relays in self.topology.items():
            if relay in relays:
                return root
        return None

    def visible(self) -> list[dict[str, Any]]:
        return [{"csn": self.csn_of[d], "digest": d,
                 "channel_id": m.channel, "seq": m.seq, "epoch": m.epoch,
                 "relocation_gen": self.commit_gen[d]}
                for d, m in sorted(self.committed.items(),
                                   key=lambda kv: self.csn_of[kv[0]])]


def _reject(st: MiniState, reason: str, msg: MiniMsg,
            extra: dict[str, Any] | None = None) -> tuple[bool, str]:
    st.lsn += 1
    evidence = {"digest": msg.digest, "channel_id": msg.channel,
                "seq": msg.seq, "epoch": msg.epoch}
    if extra:
        evidence.update(extra)
    st.rejections.append({"lsn": st.lsn, "reason": reason, "evidence": evidence})
    return False, reason


def _check_witnesses(st: MiniState, msg: MiniMsg) -> tuple[bool, str]:
    """见证法定人数核验，规则顺序与真实引擎 validate() 完全一致。"""
    if msg.witness_fault == "unknown_relay":
        return _reject(st, WITNESS_RELAY_UNKNOWN, msg)
    if msg.witness_fault == "wrong_root":
        return _reject(st, WITNESS_BAD, msg, {"fault": "wrong_root"})
    if msg.witness_fault == "bad_mac":
        return _reject(st, WITNESS_BAD, msg, {"fault": "bad_mac"})
    if len(msg.roots) < 2:
        return _reject(st, QUORUM_COUNT, msg,
                       {"witness_count": len(msg.roots)})
    if msg.witness_fault == "revoked_root" or any(
            not _root_active(st, root, msg.epoch) for root in msg.roots):
        bad = next(root for root in msg.roots
                   if not _root_active(st, root, msg.epoch))
        return _reject(st, WITNESS_ROOT_REVOKED, msg,
                       {"root_id": bad, "revoked_at": st.revoked_at.get(bad)})
    distinct: list[str] = []
    for root in msg.roots:
        if root not in distinct:
            distinct.append(root)
    if len(distinct) < 2:
        return _reject(st, QUORUM_TRUST, msg, {"distinct_roots": distinct})
    return True, OK


def _root_active(st: MiniState, root: str, epoch: int) -> bool:
    if root not in st.revoked_at:
        return False
    at = st.revoked_at[root]
    return at is None or epoch <= at


def op_prepare(st: MiniState, msg: MiniMsg) -> tuple[bool, str]:
    """准备：核验后进入暂存，不产生 CSN。"""
    ok, reason = _check_witnesses(st, msg)
    if not ok:
        return False, reason
    if msg.epoch != st.epoch:
        return _reject(st, EPOCH_STALE, msg,
                       {"submitted_epoch": msg.epoch,
                        "current_epoch": st.epoch})
    key = (msg.channel, msg.seq, st.reloc_gen[msg.channel])
    bound = st.locator.get(key)
    if bound is not None and bound != msg.digest:
        return _reject(st, DIGEST_MISMATCH, msg,
                       {"locator": list(key), "bound_digest": bound})
    if msg.digest in st.committed:
        return True, DUPLICATE_COMMIT
    st.staged[msg.digest] = msg
    return True, OK


def op_commit(st: MiniState, msg: MiniMsg) -> tuple[bool, str]:
    """承诺：锁内等价的重新裁决 + 单调 CSN。"""
    ok, reason = _check_witnesses(st, msg)
    if not ok:
        return False, reason
    if msg.epoch != st.epoch:
        return _reject(st, EPOCH_STALE, msg,
                       {"submitted_epoch": msg.epoch,
                        "current_epoch": st.epoch})
    key = (msg.channel, msg.seq, st.reloc_gen[msg.channel])
    bound = st.locator.get(key)
    if bound is not None and bound != msg.digest:
        return _reject(st, DIGEST_MISMATCH, msg,
                       {"locator": list(key), "bound_digest": bound})
    if msg.digest in st.committed:
        return True, DUPLICATE_COMMIT
    st.lsn += 1
    st.csn += 1
    gen = st.reloc_gen[msg.channel]
    st.committed[msg.digest] = msg
    st.csn_of[msg.digest] = st.csn
    st.commit_gen[msg.digest] = gen
    st.locator[(msg.channel, msg.seq, gen)] = msg.digest
    st.staged.pop(msg.digest, None)
    return True, OK


def op_revoke(st: MiniState, root: str) -> tuple[bool, str]:
    """撤销：先把仍未承诺的暂存消息固化为拒绝证据，再推进授权代。"""
    if root not in st.revoked_at:
        return False, WITNESS_ROOT_REVOKED
    new_epoch = st.epoch + 1
    for digest, msg in list(st.staged.items()):
        st.lsn += 1
        st.rejections.append({
            "lsn": st.lsn, "reason": REVOKED_UNCOMMITTED,
            "evidence": {"digest": digest, "channel_id": msg.channel,
                         "seq": msg.seq, "epoch": msg.epoch,
                         "root_id": root, "new_epoch": new_epoch}})
    st.staged.clear()
    st.lsn += 1
    st.revoked_at[root] = st.epoch
    st.epoch = new_epoch
    return True, OK


def op_relocate(st: MiniState, channel: str) -> tuple[bool, str]:
    st.reloc_gen[channel] += 1
    st.lsn += 1
    return True, OK


def op_receipt(st: MiniState, channel: str, seq: int, digest: str,
               gen: int) -> tuple[bool, str]:
    """搬迁期旧回执核验：只认真实承诺过的摘要与定位符。"""
    msg = st.committed.get(digest)
    if msg is not None:
        if (msg.channel, msg.seq, st.commit_gen[digest]) == (channel, seq, gen):
            return True, OK
        return False, DIGEST_MISMATCH
    bound = st.locator.get((channel, seq, gen))
    if bound is not None:
        return False, DIGEST_MISMATCH
    return False, RECEIPT_UNKNOWN


# ---------- 短交错枚举 ----------

@dataclass
class Interleaving:
    schedule: tuple[str, ...]
    outcomes: tuple[tuple[str, bool, str], ...]   # (操作, accepted, reason)
    visible_digests: tuple[str, ...]
    rejection_reasons: tuple[str, ...]
    rejection_count: int


def enumerate_interleavings(topology: dict[str, list[str]],
                            channels: list[str],
                            *,
                            max_revokes: int = 1,
                            max_relocates: int = 1) -> list[Interleaving]:
    """枚举两个角色（承诺线程 C / 撤销线程 R）在短消息集上的全部合法交错。

    固定消息宇宙：m1（合法双根）、m2（同根双见证，必被 QUORUM_TRUST 拒）。
    每个线程的内部顺序固定（C: prepare m1 -> commit m1 -> 处理 m2），
    枚举的是两个线程操作之间的相对顺序，外加可选搬迁步骤；
    重复调度在状态层天然幂等/去重，最终按 (调度, 结果) 去重。
    """
    roots = tuple(topology)
    m1 = MiniMsg(channels[0], 1, "digest-m1", 0, roots[:2])
    m2 = MiniMsg(channels[0], 2, "digest-m2", 0,
                 (roots[0], roots[0]))  # 同一信任根的两个中继见证
    c_steps = [("prepare:m1", "C"), ("commit:m1", "C"), ("commit:m2", "C")]
    r_steps = [("revoke", "R")] * max_revokes
    l_steps = [("relocate", "L")] * max_relocates
    all_steps = c_steps + r_steps + l_steps
    n = len(all_steps)
    results: dict[tuple[str, ...], Interleaving] = {}

    def apply(st: MiniState, label: str) -> tuple[bool, str]:
        if label == "prepare:m1":
            return op_prepare(st, m1)
        if label == "commit:m1":
            return op_commit(st, m1)
        if label == "commit:m2":
            return op_commit(st, m2)
        if label == "revoke":
            return op_revoke(st, roots[1])  # 撤销第二个根
        if label == "relocate":
            return op_relocate(st, channels[0])
        raise AssertionError(label)

    for picks in product(range(n), repeat=n):
        if sorted(picks) != list(range(n)):
            continue  # 只取每个步骤恰好出现一次的排列
        order = [all_steps[i][0] for i in picks]
        # 保持同一线程内部顺序（跨线程任意交错）
        if any(order.index(a) > order.index(b)
               for a, b in [("prepare:m1", "commit:m1"),
                            ("commit:m1", "commit:m2")]):
            continue
        st = MiniState.fresh(topology, channels)
        outcomes: list[tuple[str, bool, str]] = []
        for label in order:
            accepted, reason = apply(st, label)
            outcomes.append((label, accepted, reason))
        key = tuple(order)
        results[key] = Interleaving(
            schedule=key,
            outcomes=tuple(outcomes),
            visible_digests=tuple(sorted(st.committed)),
            rejection_reasons=tuple(r["reason"] for r in st.rejections),
            rejection_count=len(st.rejections))
    return list(results.values())


def summarize(interleavings: list[Interleaving]) -> dict[str, Any]:
    """汇总可见集形状与每类拒绝证据的出现次数。"""
    visible_shapes: dict[tuple[str, ...], int] = {}
    reason_counts: dict[str, int] = {}
    for item in interleavings:
        visible_shapes[item.visible_digests] = \
            visible_shapes.get(item.visible_digests, 0) + 1
        for reason in item.rejection_reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return {
        "total_interleavings": len(interleavings),
        "visible_set_shapes": {
            "|".join(k) if k else "<empty>": v
            for k, v in sorted(visible_shapes.items())},
        "rejection_reason_counts": dict(sorted(reason_counts.items())),
    }

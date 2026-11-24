"""承诺引擎：离线核验、持久化提交序裁决、撤销、搬迁与崩溃恢复。

线程模型：所有状态变更在同一把 RLock 下串行化，提交日志的追加顺序（LSN）
即权威裁决顺序；COMMIT 记录另分配单调提交序号 CSN。两个工作线程
（commit/revoke）无论怎样被屏障交错，最终结果只由落盘顺序决定。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterable

from .crypto import verify_witness
from .logstore import CommitLog
from .registry import TrustRegistry
from .segments import AccessStats, ChannelStore, atomic_write_json
from .types import R, Submission, Verdict


class Engine:
    # ---------- 生命周期 ----------

    def __init__(self, base_dir: str | os.PathLike[str],
                 segment_capacity: int = 1000, durable: bool = True):
        self.base = Path(base_dir)
        (self.base / "receipts").mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.segment_capacity = segment_capacity
        # 已部署的存储以 layout 中的持久化标志为准
        layout_path = self.base / "layout.json"
        if layout_path.exists():
            with open(layout_path, encoding="utf-8") as fh:
                durable = bool(json.load(fh).get("durable", durable))
        self.durable = durable
        self.registry = TrustRegistry(self.base / "registry.json")
        self.log = CommitLog(self.base / "commit.log", durable=durable)
        self.channels: dict[str, ChannelStore] = {}
        self.lsn = 0
        self.csn = 0
        self.committed: dict[str, dict[str, Any]] = {}
        self.locator: dict[tuple[str, int, int], str] = {}
        self.rejections: list[dict[str, Any]] = []
        self.revocations: list[dict[str, Any]] = []
        self.reloc_gen: dict[str, int] = {}
        self._rebuild()

    @classmethod
    def create(cls, base_dir: str | os.PathLike[str],
               topology: dict[str, list[str]], channel_ids: Iterable[str],
               segment_capacity: int = 1000,
               durable: bool = True) -> "Engine":
        """全新部署：建立信任拓扑、两条通道与空提交日志。"""
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        TrustRegistry.bootstrap(base / "registry.json", topology)
        eng = cls(base, segment_capacity=segment_capacity, durable=durable)
        for channel_id in channel_ids:
            eng.channels[channel_id] = ChannelStore(
                base / "channels", channel_id, segment_capacity,
                durable=durable)
            eng.reloc_gen[channel_id] = 0
        eng._write_layout()
        return eng

    def _write_layout(self) -> None:
        atomic_write_json(self.base / "layout.json", {
            "segment_capacity": self.segment_capacity,
            "durable": self.durable,
            "channels": sorted(self.channels),
        })

    def _rebuild(self) -> None:
        """重放提交日志重建内存索引；通道分段由各自清单自行恢复。"""
        layout_path = self.base / "layout.json"
        channel_ids: list[str] = []
        if layout_path.exists():
            with open(layout_path, encoding="utf-8") as fh:
                channel_ids = list(json.load(fh)["channels"])
        for channel_id in channel_ids:
            store = ChannelStore(self.base / "channels", channel_id,
                                 self.segment_capacity, durable=self.durable)
            self.channels[channel_id] = store
            self.reloc_gen[channel_id] = store.manifest["relocation_gen"]
        for rec in self.log.replay():
            self.lsn = max(self.lsn, int(rec["lsn"]))
            kind = rec["type"]
            if kind == "COMMIT":
                self.csn = max(self.csn, int(rec["csn"]))
                self._index_commit(rec)
            elif kind == "REJECT":
                self.rejections.append(rec)
            elif kind == "REVOKE":
                self.revocations.append(rec)
                self.registry.apply_revocation(rec["root_id"],
                                               int(rec["epoch_new"]))
            elif kind == "RELOCATE":
                self.reloc_gen[rec["channel_id"]] = int(rec["gen_new"])
        self.registry.set_epoch(self.current_epoch())

    @classmethod
    def reopen(cls, base_dir: str | os.PathLike[str],
               segment_capacity: int = 1000) -> "Engine":
        """模拟进程重启：只信任磁盘，重放日志恢复全部裁决状态。

        持久化标志自动从部署时写入的 layout.json 读取。
        """
        return cls(base_dir, segment_capacity=segment_capacity)

    def close(self) -> None:
        with self.lock:
            if getattr(self, "_closed", False):
                return
            for store in self.channels.values():
                store.close()
            self.log.close()
            self._closed = True

    # ---------- 基础查询 ----------

    def current_epoch(self) -> int:
        return int(self.registry.epoch)

    def _append(self, record: dict[str, Any]) -> dict[str, Any]:
        self.lsn += 1
        record = dict(record)
        record["lsn"] = self.lsn
        self.log.append(record)
        return record

    def _index_commit(self, rec: dict[str, Any]) -> None:
        sub = rec["sub"]
        self.committed[sub["digest"]] = rec
        self.locator[(sub["channel_id"], int(sub["seq"]),
                      int(rec["relocation_gen"]))] = sub["digest"]

    # ---------- 离线核验 ----------

    def validate(self, sub: Submission) -> Verdict:
        """纯离线核验：见证法定人数、独立信任根、授权代、定位符冲突。"""
        witnesses = list(sub.witnesses)
        if len(witnesses) < 2:
            return Verdict(False, R.QUORUM_COUNT,
                           f"仅 {len(witnesses)} 个见证，法定人数需要 2 个",
                           evidence={"submission": sub.to_dict()})
        roots: list[str] = []
        for w in witnesses:
            claimed_root = self.registry.root_of(w.relay_id)
            if claimed_root is None:
                return Verdict(False, R.WITNESS_RELAY_UNKNOWN,
                               f"未知中继 {w.relay_id}",
                               evidence={"submission": sub.to_dict(),
                                         "relay_id": w.relay_id})
            if claimed_root != w.root_id:
                return Verdict(False, R.WITNESS_BAD,
                               f"中继 {w.relay_id} 冒称信任根 {w.root_id}",
                               evidence={"submission": sub.to_dict(),
                                         "relay_id": w.relay_id,
                                         "claimed_root": w.root_id,
                                         "actual_root": claimed_root})
            if not verify_witness(w, sub.channel_id, sub.seq, sub.digest,
                                  sub.epoch, self.registry.root_keys):
                return Verdict(False, R.WITNESS_BAD,
                               f"中继 {w.relay_id} 的见证 HMAC 核验失败",
                               evidence={"submission": sub.to_dict(),
                                         "relay_id": w.relay_id})
            if not self.registry.is_root_active_for(w.root_id, sub.epoch):
                return Verdict(False, R.WITNESS_ROOT_REVOKED,
                               f"信任根 {w.root_id} 在授权代 {sub.epoch} 已被撤销",
                               evidence={"submission": sub.to_dict(),
                                         "root_id": w.root_id,
                                         "revoked_at":
                                             self.registry.root_revoked_at[w.root_id]})
            if w.root_id not in roots:
                roots.append(w.root_id)
        # 信任根相同的两个见证只能算一个：独立根不足两个即无法定人数
        if len(roots) < 2:
            return Verdict(False, R.QUORUM_TRUST,
                           f"见证只覆盖独立信任根 {roots}，需要两个不同根",
                           evidence={"submission": sub.to_dict(),
                                     "distinct_roots": roots})
        if sub.epoch != self.current_epoch():
            return Verdict(False, R.EPOCH_STALE,
                           f"提交绑定授权代 {sub.epoch}，当前授权代 "
                           f"{self.current_epoch()}",
                           evidence={"submission": sub.to_dict(),
                                     "submitted_epoch": sub.epoch,
                                     "current_epoch": self.current_epoch()})
        key = (sub.channel_id, sub.seq, self.reloc_gen[sub.channel_id])
        existing = self.locator.get(key)
        if existing is not None and existing != sub.digest:
            return Verdict(False, R.DIGEST_MISMATCH,
                           f"定位符 {key} 已绑定摘要 {existing}，"
                           f"与本次 {sub.digest} 不同（同号不同摘要）",
                           evidence={"locator": list(key),
                                     "existing_digest": existing,
                                     "incoming_digest": sub.digest})
        if sub.digest in self.committed:
            old = self.committed[sub.digest]
            return Verdict(True, R.DUPLICATE_COMMIT,
                           "摘要已承诺，幂等重放不产生新提交",
                           lsn=old["lsn"], csn=old["csn"],
                           evidence={"digest": sub.digest, "csn": old["csn"]})
        return Verdict(True, R.OK, "核验通过",
                       evidence={"distinct_roots": roots})

    # ---------- 两阶段提交（prepare / commit，供屏障交错） ----------

    def prepare(self, sub: Submission) -> Verdict:
        """准备：离线核验并暂存到通道分段；此阶段不写提交日志。"""
        with self.lock:
            verdict = self.validate(sub)
            if not verdict.accepted and verdict.reason != R.DUPLICATE_COMMIT:
                # 拒绝同样落盘，形成可离线复核的拒绝证据
                rec = self._append({"type": "REJECT", "reason": verdict.reason,
                                    "detail": verdict.detail,
                                    "sub": sub.to_dict(),
                                    "evidence": verdict.evidence})
                self.rejections.append(rec)
                return verdict
            if verdict.reason == R.DUPLICATE_COMMIT:
                return verdict
            gen = self.reloc_gen[sub.channel_id]
            self.channels[sub.channel_id].stage(sub.to_dict(), gen)
            return Verdict(True, R.OK, "已暂存，等待承诺",
                           evidence={"relocation_gen": gen})

    def commit_prepared(self, sub: Submission, *, write_receipt: bool = True) -> Verdict:
        """承诺：锁内重新裁决（授权代可能已被撤销线程推进），落盘后写回执。"""
        with self.lock:
            verdict = self.validate(sub)
            if not verdict.accepted:
                rec = self._append({"type": "REJECT", "reason": verdict.reason,
                                    "detail": verdict.detail,
                                    "sub": sub.to_dict(),
                                    "evidence": verdict.evidence})
                self.rejections.append(rec)
                return Verdict(False, verdict.reason, verdict.detail,
                               lsn=rec["lsn"], evidence=verdict.evidence)
            if verdict.reason == R.DUPLICATE_COMMIT:
                return verdict
            gen = self.reloc_gen[sub.channel_id]
            commit_rec = self._append(
                {"type": "COMMIT", "csn": self.csn + 1,
                 "sub": sub.to_dict(), "relocation_gen": gen})
            self.csn += 1
            self._index_commit(commit_rec)
            if write_receipt:
                self._write_receipt(commit_rec)
            return Verdict(True, R.OK, "承诺已落盘",
                           lsn=commit_rec["lsn"], csn=self.csn,
                           evidence={"relocation_gen": gen})

    def submit(self, sub: Submission, *, write_receipt: bool = True) -> Verdict:
        """一次性 准备+承诺（小模型差分与批量压测使用）。"""
        with self.lock:
            prepared = self.prepare(sub)
            if not prepared.accepted:
                return prepared
            return self.commit_prepared(sub, write_receipt=write_receipt)

    # ---------- 撤销 ----------

    def revoke_root(self, root_id: str, channels: Iterable[str] | None = None,
                    stats: dict[str, AccessStats] | None = None) -> Verdict:
        """撤销某信任根（中继资格）并推进授权代。

        落盘顺序先逐条固化"未承诺即被撤销"的拒绝证据，最后写 REVOKE 记录；
        因此 REVOKE 的 LSN 就是裁决分界：其后任何旧代提交必然 EPOCH_STALE。
        channels 给定时只清扫给定通道（单通道撤销），其余通道分段零访问。
        """
        with self.lock:
            if root_id not in self.registry.root_keys:
                return Verdict(False, R.WITNESS_ROOT_REVOKED,
                               f"未知信任根 {root_id}")
            target_channels = list(self.channels if channels is None else channels)
            new_epoch = self.current_epoch() + 1
            pending: list[dict[str, Any]] = []
            for channel_id in target_channels:
                store = self.channels[channel_id]
                channel_stats = stats[channel_id] if stats else None
                for meta in list(store.manifest["segments"]):
                    if meta["sealed"] and not meta["may_have_pending"]:
                        continue  # 清单已证明整段承诺完毕，跳过
                    rows = store._read_segment(meta["name"], channel_stats)
                    open_pending = [row for row in rows
                                    if row["digest"] not in self.committed]
                    for row in open_pending:
                        evidence = {
                            "channel_id": row["channel_id"], "seq": row["seq"],
                            "digest": row["digest"], "epoch": row["epoch"],
                            "relocation_gen": row["relocation_gen"],
                            "root_id": root_id, "new_epoch": new_epoch,
                        }
                        rec = self._append(
                            {"type": "REJECT",
                             "reason": R.REVOKED_UNCOMMITTED,
                             "detail": "撤销落盘时消息仍未承诺，必须重新审批",
                             "sub": {"channel_id": row["channel_id"],
                                     "seq": row["seq"],
                                     "digest": row["digest"],
                                     "epoch": row["epoch"]},
                             "evidence": evidence})
                        self.rejections.append(rec)
                        pending.append(evidence)
                    if meta["sealed"] and not open_pending:
                        store.mark_segment_resolved(meta["name"])
            revoke_rec = self._append({"type": "REVOKE", "root_id": root_id,
                                       "relay_ids": [r for r, rr
                                                     in self.registry.relay_root.items()
                                                     if rr == root_id],
                                       "epoch_new": new_epoch,
                                       "pending_evidence": pending})
            self.revocations.append(revoke_rec)
            self.registry.apply_revocation(root_id, new_epoch)
            return Verdict(True, R.OK,
                           f"信任根 {root_id} 已撤销，授权代推进至 {new_epoch}",
                           lsn=revoke_rec["lsn"],
                           evidence={"new_epoch": new_epoch,
                                     "pending_count": len(pending),
                                     "pending": pending})

    # ---------- 通道搬迁与旧回执 ----------

    def relocate(self, channel_id: str) -> Verdict:
        with self.lock:
            store = self.channels[channel_id]
            new_gen = store.relocate()
            self.reloc_gen[channel_id] = new_gen
            rec = self._append({"type": "RELOCATE",
                                "channel_id": channel_id,
                                "gen_new": new_gen})
            return Verdict(True, R.OK,
                           f"通道 {channel_id} 搬迁至第 {new_gen} 代",
                           lsn=rec["lsn"], evidence={"gen_new": new_gen})

    def inbound_receipt(self, channel_id: str, seq: int, digest: str,
                        relocation_gen: int) -> Verdict:
        """搬迁期到达的回执离线核验：只认真实落盘过的承诺摘要。"""
        with self.lock:
            commit_rec = self.committed.get(digest)
            if commit_rec is not None:
                sub = commit_rec["sub"]
                loc = (sub["channel_id"], int(sub["seq"]),
                       int(commit_rec["relocation_gen"]))
                if loc == (channel_id, seq, relocation_gen):
                    # 合法旧回执：承诺有效，幂等确认，绝不重新投递
                    already = self.has_receipt(digest)
                    if not already:
                        self._write_receipt(commit_rec)
                    return Verdict(True, R.OK,
                                   "旧代承诺仍有效，回执幂等确认（不重投）",
                                   lsn=commit_rec["lsn"], csn=commit_rec["csn"],
                                   evidence={"receipt_already_present": already})
                return Verdict(False, R.DIGEST_MISMATCH,
                               "摘要存在但定位符与回执不一致",
                               evidence={"receipt_locator":
                                             [channel_id, seq, relocation_gen],
                                         "commit_locator": list(loc)})
            bound = self.locator.get((channel_id, seq, relocation_gen))
            if bound is not None:
                return Verdict(False, R.DIGEST_MISMATCH,
                               "同号定位符绑定的是另一个摘要（搬迁后同号不同摘要）",
                               evidence={"locator":
                                             [channel_id, seq, relocation_gen],
                                         "bound_digest": bound,
                                         "incoming_digest": digest})
            return Verdict(False, R.RECEIPT_UNKNOWN,
                           "回执在提交日志中找不到任何对应承诺，拒绝并重审批",
                           evidence={"locator":
                                         [channel_id, seq, relocation_gen],
                                     "incoming_digest": digest})

    # ---------- 回执与恢复 ----------

    def _receipt_path(self, digest: str) -> Path:
        return self.base / "receipts" / f"receipt-{digest}.json"

    def _write_receipt(self, commit_rec: dict[str, Any]) -> None:
        sub = commit_rec["sub"]
        payload = {"csn": commit_rec["csn"], "lsn": commit_rec["lsn"],
                   "digest": sub["digest"], "channel_id": sub["channel_id"],
                   "seq": sub["seq"], "epoch": sub["epoch"],
                   "relocation_gen": commit_rec["relocation_gen"]}
        atomic_write_json(self._receipt_path(sub["digest"]), payload)

    def has_receipt(self, digest: str) -> bool:
        return self._receipt_path(digest).exists()

    def drop_receipt(self, digest: str) -> bool:
        """模拟回执丢失（承诺已落盘但回执文件缺失）。"""
        path = self._receipt_path(digest)
        if path.exists():
            path.unlink()
            return True
        return False

    def recover_pending_receipts(self) -> list[str]:
        """重启后补写缺失回执：只依据已落盘承诺，不产生任何新 COMMIT。"""
        with self.lock:
            repaired: list[str] = []
            for digest, rec in sorted(self.committed.items(),
                                      key=lambda kv: kv[1]["csn"]):
                if not self.has_receipt(digest):
                    self._write_receipt(rec)
                    repaired.append(digest)
            return repaired

    # ---------- 可见集与重新审批候选 ----------

    def visible_committed(self) -> list[dict[str, Any]]:
        """恢复后对外可见的承诺集合，按持久化提交序 CSN 排列。"""
        out = []
        for rec in sorted(self.committed.values(), key=lambda r: r["csn"]):
            sub = rec["sub"]
            out.append({"csn": rec["csn"], "lsn": rec["lsn"],
                        "channel_id": sub["channel_id"], "seq": sub["seq"],
                        "digest": sub["digest"], "epoch": sub["epoch"],
                        "relocation_gen": rec["relocation_gen"]})
        return out

    def rejection_evidence(self) -> list[dict[str, Any]]:
        return [{"lsn": rec.get("lsn"), "reason": rec["reason"],
                 "detail": rec.get("detail", ""),
                 "evidence": rec.get("evidence", {})}
                for rec in self.rejections]

    def reapproval_candidates(self, channel_id: str, *, full: bool = False,
                              stats: AccessStats | None = None
                              ) -> list[dict[str, Any]]:
        """未承诺的暂存消息 = 必须重新审批的集合。

        full=False 走清单选择性扫描（单通道撤销路径）；full=True 读取
        全部分段作为对账基准。两种方式的结果必须逐摘要一致。
        """
        store = self.channels[channel_id]
        scanner = store.scan_all if full else store.scan_relevant
        seen: dict[str, dict[str, Any]] = {}
        for row in scanner(stats):
            if row["digest"] in self.committed:
                continue
            seen.setdefault(row["digest"], {
                "channel_id": row["channel_id"], "seq": row["seq"],
                "digest": row["digest"], "epoch": row["epoch"],
                "relocation_gen": row["relocation_gen"]})
        return sorted(seen.values(), key=lambda r: (r["seq"], r["digest"]))

    def reconcile_channel(self, channel_id: str,
                          stats: AccessStats | None = None) -> int:
        """后台维护：封存分段若已全部承诺，收紧 may_have_pending 标记。

        依据内存承诺索引判定，每个封存分段生命周期内只读一次，
        访问量计入独立 stats，不混入撤销测量。
        """
        with self.lock:
            store = self.channels[channel_id]
            resolved = 0
            for meta in list(store.manifest["segments"]):
                if not meta["sealed"] or not meta["may_have_pending"]:
                    continue
                rows = store._read_segment(meta["name"], stats)
                if all(row["digest"] in self.committed for row in rows):
                    store.mark_segment_resolved(meta["name"])
                    resolved += 1
            return resolved

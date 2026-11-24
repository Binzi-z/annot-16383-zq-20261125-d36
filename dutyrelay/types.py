"""通用数据类型与裁决原因码。

裁决原因码同时被引擎、工作线程和独立小模型（minimodel）以字符串方式引用，
保证拒绝证据的语义在两套实现之间逐字一致，便于差分比对。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class R:
    """所有裁决原因（含接受 OK 与各类拒绝证据）。"""

    OK = "OK"
    QUORUM_TRUST = "QUORUM_TRUST"              # 两个见证共享同一信任根，独立信任根不足两个
    QUORUM_COUNT = "QUORUM_COUNT"              # 见证数量不足两个
    WITNESS_BAD = "WITNESS_BAD"                # 见证签名/HMAC 核验失败
    WITNESS_RELAY_UNKNOWN = "WITNESS_RELAY_UNKNOWN"
    WITNESS_ROOT_REVOKED = "WITNESS_ROOT_REVOKED"
    EPOCH_STALE = "EPOCH_STALE"                # 提交绑定的授权代已过期
    DIGEST_MISMATCH = "DIGEST_MISMATCH"        # 同号不同摘要（搬迁期旧回执/旧提交）
    REVOKED_UNCOMMITTED = "REVOKED_UNCOMMITTED"  # 撤销落盘时仍未承诺，必须重新审批
    DUPLICATE_COMMIT = "DUPLICATE_COMMIT"      # 同一摘要已承诺，幂等重放
    RECEIPT_UNKNOWN = "RECEIPT_UNKNOWN"        # 回执在持久化日志中找不到对应承诺


@dataclass(frozen=True)
class Witness:
    """一个中继对提交的见证。

    relay_id 标识中继，root_id 是该中继当前归属的信任根；
    两个 root_id 相同的见证在法定人数上只能算一个。
    """

    relay_id: str
    root_id: str
    mac: str  # 离线模拟的见证签名：HMAC-SHA256(根密钥, 规范见证载荷) 的十六进制串

    def to_dict(self) -> dict[str, str]:
        return {"relay_id": self.relay_id, "root_id": self.root_id, "mac": self.mac}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Witness":
        return cls(relay_id=str(d["relay_id"]),
                   root_id=str(d["root_id"]),
                   mac=str(d["mac"]))


@dataclass(frozen=True)
class Submission:
    """绑定消息摘要、两个独立中继见证与当前授权代的一次提交。"""

    channel_id: str
    seq: int
    digest: str
    epoch: int
    witnesses: tuple[Witness, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel_id": self.channel_id,
            "seq": self.seq,
            "digest": self.digest,
            "epoch": self.epoch,
            "witnesses": [w.to_dict() for w in self.witnesses],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Submission":
        return cls(
            channel_id=str(d["channel_id"]),
            seq=int(d["seq"]),
            digest=str(d["digest"]),
            epoch=int(d["epoch"]),
            witnesses=tuple(Witness.from_dict(w) for w in d["witnesses"]),
        )


@dataclass(frozen=True)
class Verdict:
    """一次裁决的结果；拒绝时 evidence 给出可落盘、可离线复核的证据。"""

    accepted: bool
    reason: str
    detail: str = ""
    lsn: int | None = None
    csn: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "detail": self.detail,
            "lsn": self.lsn,
            "csn": self.csn,
            "evidence": dict(self.evidence),
        }

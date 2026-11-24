"""合成数据工厂：标准信任拓扑、两条通道与提交构造助手（全部本地生成）。"""

from __future__ import annotations

from typing import Sequence

from .crypto import make_witness, message_digest
from .engine import Engine
from .types import Submission

# 三个信任根：rootA 有两个中继（用于同根双见证用例），rootB/rootC 各两个
TOPOLOGY: dict[str, list[str]] = {
    "rootA": ["relay-A1", "relay-A2"],
    "rootB": ["relay-B1", "relay-B2"],
    "rootC": ["relay-C1", "relay-C2"],
}
CHANNELS: list[str] = ["duty-north", "duty-south"]


def new_engine(base_dir, *, segment_capacity: int = 1000) -> Engine:
    return Engine.create(base_dir, TOPOLOGY, CHANNELS,
                         segment_capacity=segment_capacity)


def make_submission(eng: Engine, channel: str, seq: int, payload: bytes,
                    epoch: int | None = None,
                    roots: Sequence[str] = ("rootA", "rootB")) -> Submission:
    """按当前授权代构造一条带两个独立信任根见证的合成提交。"""
    if epoch is None:
        epoch = eng.current_epoch()
    digest = message_digest(channel, seq, payload)
    witnesses = []
    for root in roots:
        relay = next(r for r, rr in eng.registry.relay_root.items()
                     if rr == root)
        witnesses.append(make_witness(channel, seq, digest, epoch,
                                      relay, root,
                                      eng.registry.root_keys[root]))
    return Submission(channel, seq, digest, epoch, tuple(witnesses))


def make_same_root_submission(eng: Engine, channel: str, seq: int,
                              payload: bytes, root: str = "rootA"
                              ) -> Submission:
    """同信任根下两个不同中继的见证：按独立根折算只有一个，应被拒。"""
    epoch = eng.current_epoch()
    digest = message_digest(channel, seq, payload)
    relays = [r for r, rr in eng.registry.relay_root.items() if rr == root]
    witnesses = [
        make_witness(channel, seq, digest, epoch, relays[0], root,
                     eng.registry.root_keys[root]),
        make_witness(channel, seq, digest, epoch, relays[1], root,
                     eng.registry.root_keys[root]),
    ]
    return Submission(channel, seq, digest, epoch, tuple(witnesses))


def iter_log_records(eng: Engine) -> list[dict]:
    """直接重放底层提交日志，供测试核对落盘记录的真实数量与类型。"""
    return list(eng.log.replay())

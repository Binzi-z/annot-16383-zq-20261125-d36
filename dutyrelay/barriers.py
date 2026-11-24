"""可控屏障与两个工作线程。

Barrier 把一次提交切成三个可挂起的检查点：
    prepared  —— prepare() 已完成（暂存落盘，COMMIT 尚未写日志）
    committed —— commit_prepared() 已返回（COMMIT 已 fsync）
    done      —— 工作线程收尾
撤销线程可在提交线程挂在 prepared 时抢先把 REVOKE 落盘，从而精确复测
"准备完成但撤销已提交"交错。屏障同时记录两个线程实际到达检查点的顺序，
作为持久化提交序裁决的旁证。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from .types import Submission, Verdict


@dataclass
class Barrier:
    """事件门闩：线程到达 wait_point 处阻塞，直到控制方放行或放行指定点。"""

    hold_points: set[str] = field(default_factory=set)
    _gates: dict[str, threading.Event] = field(default_factory=dict)
    _arrival: dict[str, list[str]] = field(default_factory=dict)
    _order: list[tuple[str, str]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        for point in ("prepared", "committed", "done", "revoked"):
            self._gates[point] = threading.Event()
            self._arrival[point] = []

    def wait_point(self, worker: str, point: str) -> None:
        """工作线程调用：登记到达顺序；若该点被挂起则阻塞到 release。"""
        with self._lock:
            self._arrival[point].append(worker)
            self._order.append((worker, point))
            gate = self._gates[point]
        if point in self.hold_points:
            gate.wait()

    def release(self, point: str) -> None:
        """放行某个检查点上所有等待者。"""
        self._gates[point].set()

    def release_all(self) -> None:
        for gate in self._gates.values():
            gate.set()

    def arrived(self, point: str) -> bool:
        with self._lock:
            return bool(self._arrival[point])

    def wait_until_arrived(self, point: str, timeout: float = 5.0) -> bool:
        """控制方等待某线程到达挂起点（但尚未越过）。"""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if self._arrival[point]:
                    return True
            time.sleep(0.002)
        return False

    @property
    def order(self) -> list[tuple[str, str]]:
        with self._lock:
            return list(self._order)


class CommitWorker(threading.Thread):
    """承诺工作线程：prepare -> 屏障 -> commit -> 屏障。"""

    def __init__(self, engine: Any, submission: Submission,
                 barrier: Barrier, *, write_receipt: bool = True,
                 name: str = "commit-worker"):
        super().__init__(name=name, daemon=True)
        self.engine = engine
        self.submission = submission
        self.barrier = barrier
        self.write_receipt = write_receipt
        self.result: Verdict | None = None
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            prepared = self.engine.prepare(self.submission)
            self.barrier.wait_point(self.name, "prepared")
            if not prepared.accepted:
                self.result = prepared
            else:
                self.result = self.engine.commit_prepared(
                    self.submission, write_receipt=self.write_receipt)
            self.barrier.wait_point(self.name, "committed")
        except BaseException as exc:  # 线程内异常回传，不静默吞掉
            self.error = exc
        finally:
            self.barrier.wait_point(self.name, "done")


class RevokeWorker(threading.Thread):
    """撤销工作线程：可在任意点被挂起，落盘 REVOKE 并推进授权代。"""

    def __init__(self, engine: Any, root_id: str, barrier: Barrier,
                 channels: list[str] | None = None,
                 stats: dict[str, Any] | None = None,
                 *, name: str = "revoke-worker"):
        super().__init__(name=name, daemon=True)
        self.engine = engine
        self.root_id = root_id
        self.barrier = barrier
        self.channels = channels
        self.stats = stats
        self.result: Verdict | None = None
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.result = self.engine.revoke_root(
                self.root_id, channels=self.channels, stats=self.stats)
            self.barrier.wait_point(self.name, "revoked")
        except BaseException as exc:
            self.error = exc
        finally:
            self.barrier.wait_point(self.name, "done")

"""两条本地通道的分段暂存。

每个通道是一个目录，消息按顺序写入容量受限的分段（segment）文件；
分段封存（roll）时刷新清单 manifest，记录每段的序号区间与"是否仍可能
含有未承诺消息"。单通道撤销时只访问该通道的相关分段，访问量由
AccessStats 仪表计数，便于与完整全量扫描对账。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


def atomic_write_json(path: Path, obj: Any) -> None:
    """同目录临时文件 + os.replace 原子落盘（Windows 上同样保证替换原子性）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, sort_keys=True, separators=(",", ":"))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


@dataclass
class AccessStats:
    """存储层访问仪表：统计实际触碰的分段与记录，而非逻辑候选数。"""

    segment_opens: int = 0
    manifest_reads: int = 0
    records_inspected: int = 0
    bytes_read: int = 0
    opened_segments: set[str] = field(default_factory=set)

    def note_segment(self, seg_name: str, record_count: int, byte_count: int) -> None:
        if seg_name not in self.opened_segments:
            self.opened_segments.add(seg_name)
            self.segment_opens += 1
        self.records_inspected += record_count
        self.bytes_read += byte_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_opens": self.segment_opens,
            "manifest_reads": self.manifest_reads,
            "records_inspected": self.records_inspected,
            "bytes_read": self.bytes_read,
            "opened_segments": sorted(self.opened_segments),
        }


class ChannelStore:
    def __init__(self, root: str | os.PathLike[str], channel_id: str,
                 segment_capacity: int = 1000, durable: bool = True):
        self.channel_id = channel_id
        self.dir = Path(root) / channel_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.segment_capacity = segment_capacity
        # durable=False 仅用于大批量压测：跳过行级 fsync，崩溃恢复的持久性
        # 保证由 scenarios 的故障注入单独证明。
        self.durable = durable
        self.manifest_path = self.dir / "manifest.json"
        self.manifest: dict[str, Any] = self._load_manifest()
        self._closed = False
        # (尾分段名, 已读入行, 持续打开的追加句柄)
        self._tail: tuple[str, list[dict[str, Any]], Any] = self._open_tail()

    # ---------- 清单与分段 ----------

    def _load_manifest(self) -> dict[str, Any]:
        if self.manifest_path.exists():
            with open(self.manifest_path, encoding="utf-8") as fh:
                return json.load(fh)
        return {"channel_id": self.channel_id, "segments": [],
                "relocation_gen": 0}

    def _write_manifest(self) -> None:
        atomic_write_json(self.manifest_path, self.manifest)

    def _segment_path(self, name: str) -> Path:
        return self.dir / name

    def _open_tail(self) -> tuple[str, list[dict[str, Any]], Any]:
        if self.manifest["segments"]:
            last = self.manifest["segments"][-1]
            if not last["sealed"]:
                name = last["name"]
                with open(self._segment_path(name), encoding="utf-8") as fh:
                    rows = [json.loads(line) for line in fh if line.strip()]
                # 清单 rows 可能因崩溃滞后，以分段文件实际行数为准
                last["rows"] = len(rows)
                fh = open(self._segment_path(name), "a", encoding="utf-8")
                return name, rows, fh
        name = self._new_segment_name()
        self.manifest["segments"].append({
            "name": name, "first_seq": None, "last_seq": None,
            "sealed": False, "may_have_pending": True, "rows": 0,
        })
        self._write_manifest()
        fh = open(self._segment_path(name), "a", encoding="utf-8")
        return name, [], fh

    def _new_segment_name(self) -> str:
        idx = len(self.manifest["segments"])
        return f"seg-{idx:08d}.jsonl"

    def _fsync(self, fh: Any) -> None:
        if self.durable:
            fh.flush()
            os.fsync(fh.fileno())
        else:
            fh.flush()

    def _roll_if_full(self) -> None:
        name, rows, fh = self._tail
        if len(rows) < self.segment_capacity:
            return
        self._fsync(fh)
        fh.close()
        meta = next(s for s in self.manifest["segments"] if s["name"] == name)
        meta["sealed"] = True
        # 封存瞬间无法仅凭分段判断承诺状态，保守标记为可能含未承诺消息；
        # 撤销扫描后或恢复重放日志时可收紧为 False。
        meta["may_have_pending"] = True
        self._write_manifest()
        new_name = self._new_segment_name()
        self.manifest["segments"].append({
            "name": new_name, "first_seq": None, "last_seq": None,
            "sealed": False, "may_have_pending": True, "rows": 0,
        })
        self._write_manifest()
        new_fh = open(self._segment_path(new_name), "a", encoding="utf-8")
        self._tail = (new_name, [], new_fh)

    # ---------- 写入（暂存） ----------

    def stage(self, submission: dict[str, Any], relocation_gen: int) -> dict[str, Any]:
        """把一条合成提交暂存到当前尾分段，返回落盘的暂存记录。

        行级 flush+fsync 保证暂存本身持久；清单只在分段封存/搬迁/关闭时
        落盘，避免每条消息一次清单 fsync。
        """
        self._roll_if_full()
        name, rows, fh = self._tail
        record = {
            "channel_id": submission["channel_id"],
            "seq": submission["seq"],
            "digest": submission["digest"],
            "epoch": submission["epoch"],
            "relocation_gen": relocation_gen,
            "staged": True,
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        fh.write(line)
        self._fsync(fh)
        rows.append(record)
        meta = next(s for s in self.manifest["segments"] if s["name"] == name)
        meta["rows"] = len(rows)
        if meta["first_seq"] is None:
            meta["first_seq"] = record["seq"]
        meta["last_seq"] = record["seq"]
        return record

    # ---------- 读取（带访问仪表） ----------

    def _read_segment(self, name: str, stats: AccessStats | None) -> list[dict[str, Any]]:
        path = self._segment_path(name)
        rows: list[dict[str, Any]] = []
        byte_count = 0
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rows.append(json.loads(line))
                    byte_count += len(line.encode("utf-8"))
        if stats is not None:
            stats.note_segment(name, len(rows), byte_count)
        return rows

    def scan_all(self, stats: AccessStats | None = None) -> Iterator[dict[str, Any]]:
        """完整全量扫描：读取本通道每一个分段（撤销对账的基准结果）。"""
        if stats is not None:
            stats.manifest_reads += 1
        for meta in self.manifest["segments"]:
            yield from self._read_segment(meta["name"], stats)

    def scan_relevant(self, stats: AccessStats | None = None) -> Iterator[dict[str, Any]]:
        """选择性扫描：只打开清单判定为可能含未承诺消息的分段。

        已确认整段承诺完毕（may_have_pending=False）的封存分段直接跳过，
        尾分段永远打开。单通道撤销只走这条路径。
        """
        if stats is not None:
            stats.manifest_reads += 1
        for meta in self.manifest["segments"]:
            if meta["sealed"] and not meta["may_have_pending"]:
                continue
            yield from self._read_segment(meta["name"], stats)

    def mark_segment_resolved(self, name: str) -> None:
        """撤销扫描确认某封存分段已无未承诺消息后收紧清单标记。"""
        for meta in self.manifest["segments"]:
            if meta["name"] == name and meta["sealed"]:
                if meta["may_have_pending"]:
                    meta["may_have_pending"] = False
                    self._write_manifest()
                return

    def segment_count(self) -> int:
        return len(self.manifest["segments"])

    def total_records(self) -> int:
        return int(sum(s["rows"] for s in self.manifest["segments"]))

    # ---------- 通道搬迁 ----------

    def relocate(self) -> int:
        """通道搬迁：封存当前尾分段并开启新代，序号空间可复用。

        旧分段原样保留（搬迁后到达的旧回执仍需对照旧摘要核验），
        新代从空尾分段开始，同号不同摘要的新消息与旧记录通过
        relocation_gen + digest 区分。
        """
        name, _rows, fh = self._tail
        self._fsync(fh)
        fh.close()
        meta = next(s for s in self.manifest["segments"] if s["name"] == name)
        meta["sealed"] = True
        self.manifest["relocation_gen"] += 1
        new_gen = int(self.manifest["relocation_gen"])
        self._write_manifest()
        new_name = self._new_segment_name()
        self.manifest["segments"].append({
            "name": new_name, "first_seq": None, "last_seq": None,
            "sealed": False, "may_have_pending": True, "rows": 0,
        })
        self._write_manifest()
        new_fh = open(self._segment_path(new_name), "a", encoding="utf-8")
        self._tail = (new_name, [], new_fh)
        return new_gen

    def close(self) -> None:
        if self._closed:
            return
        name, _rows, fh = self._tail
        self._fsync(fh)
        fh.close()
        self._write_manifest()
        self._closed = True

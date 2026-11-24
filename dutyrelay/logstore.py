"""持久化提交日志：带长度前缀与 CRC 校验的只追加记录流。

每条记录帧布局（小端）：
    magic(4 字节 b"DLOG") | payload_len(uint32) | crc32(uint32, 覆盖 payload) | payload
payload 为 UTF-8 编码的 JSON。追加后 flush + os.fsync，模拟一次落盘承诺。
重放时尾部不完整/CRC 失败的帧视为崩溃残留并截断，之前完整帧全部有效——
这正是"承诺已落盘"与"尚未落盘"的物理分界。
"""

from __future__ import annotations

import json
import os
import struct
import zlib
from pathlib import Path
from typing import Any, Iterator

_MAGIC = b"DLOG"
_HEADER = struct.Struct("<4sII")


class CorruptLogError(RuntimeError):
    """完整帧 CRC 不匹配（区别于尾部截断，后者可安全修复）。"""


class CommitLog:
    def __init__(self, path: str | os.PathLike[str], durable: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # durable=False 仅供大批量压测跳过 fsync；崩溃持久性由故障注入场景覆盖
        self.durable = durable
        self._closed = False
        self._fh = open(self.path, "a+b", buffering=0)

    def append(self, record: dict[str, Any]) -> int:
        """原子追加一条记录；durable 时 fsync，返回该记录的字节结束偏移。"""
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        frame = _HEADER.pack(_MAGIC, len(payload), crc) + payload
        pos_before = self._fh.seek(0, os.SEEK_END)
        self._fh.write(frame)
        if self.durable:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        return pos_before + len(frame)

    def replay(self) -> Iterator[dict[str, Any]]:
        """顺序重放全部完整帧；发现尾部截断时截断文件并停止。"""
        self._fh.seek(0)
        offset = 0
        while True:
            header = self._fh.read(_HEADER.size)
            if not header:
                return
            if len(header) < _HEADER.size:
                self._truncate_tail(offset)
                return
            magic, payload_len, crc = _HEADER.unpack(header)
            if magic != _MAGIC:
                raise CorruptLogError(f"偏移 {offset} 处 magic 错误: {magic!r}")
            payload = self._fh.read(payload_len)
            if len(payload) < payload_len:
                # 写了一半的崩溃帧：头在、体不全
                self._truncate_tail(offset)
                return
            if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
                # 体写全了但 CRC 不符：同样视为未完成的尾部帧
                self._truncate_tail(offset)
                return
            offset += _HEADER.size + payload_len
            yield json.loads(payload.decode("utf-8"))

    def _truncate_tail(self, good_offset: int) -> None:
        self._fh.seek(good_offset)
        self._fh.truncate()
        if self.durable:
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self.durable:
                self._fh.flush()
                os.fsync(self._fh.fileno())
        finally:
            self._fh.close()
            self._closed = True

    def __enter__(self) -> "CommitLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

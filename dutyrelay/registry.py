"""信任根与中继注册表（离线信任材料）。

- 每个信任根 root 持有一根 HMAC 密钥（模拟根证书/私钥材料）；
- 每个中继 relay 归属且仅归属一个信任根；
- 撤销中继资格即把该信任根标记为"在授权代 e 之后失效"并推进授权代，
  旧代内已落盘的承诺仍然有效，新代提交不再接受该根出具的见证。
注册表自身用原子 JSON 落盘；授权代的权威值以提交日志中的 REVOKE 记录为准，
注册表只是缓存，恢复时以日志重放结果覆盖。
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from .segments import atomic_write_json


class TrustRegistry:
    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.root_keys: dict[str, bytes] = {}
        self.relay_root: dict[str, str] = {}
        # root -> 失效代：该根在 epoch > revoked_at 的提交中不再有效；None 表示现行
        self.root_revoked_at: dict[str, int | None] = {}
        self.epoch = 0
        if self.path.exists():
            self._load()

    @classmethod
    def bootstrap(cls, path: str | os.PathLike[str],
                  topology: dict[str, list[str]]) -> "TrustRegistry":
        """按 {root_id: [relay_id, ...]} 建立初始信任拓扑并落盘。"""
        reg = cls(path)
        reg.root_keys = {}
        reg.relay_root = {}
        reg.root_revoked_at = {}
        for root_id, relays in topology.items():
            reg.root_keys[root_id] = secrets.token_bytes(32)
            reg.root_revoked_at[root_id] = None
            for relay_id in relays:
                reg.relay_root[relay_id] = root_id
        reg.epoch = 0
        reg._save()
        return reg

    def _save(self) -> None:
        obj = {
            "epoch": self.epoch,
            "roots": {
                root_id: {
                    "key_hex": key.hex(),
                    "revoked_at": self.root_revoked_at[root_id],
                    "relays": [r for r, rr in self.relay_root.items() if rr == root_id],
                }
                for root_id, key in self.root_keys.items()
            },
        }
        atomic_write_json(self.path, obj)

    def _load(self) -> None:
        import json
        with open(self.path, encoding="utf-8") as fh:
            obj = json.load(fh)
        self.epoch = int(obj["epoch"])
        self.root_keys = {}
        self.relay_root = {}
        self.root_revoked_at = {}
        for root_id, info in obj["roots"].items():
            self.root_keys[root_id] = bytes.fromhex(info["key_hex"])
            self.root_revoked_at[root_id] = info["revoked_at"]
            for relay_id in info["relays"]:
                self.relay_root[relay_id] = root_id

    # ---------- 查询 ----------

    def root_of(self, relay_id: str) -> str | None:
        return self.relay_root.get(relay_id)

    def is_root_active_for(self, root_id: str, epoch: int) -> bool:
        """见证根在给定授权代是否仍具资格。"""
        revoked_at = self.root_revoked_at.get(root_id)
        if revoked_at is None:
            return root_id in self.root_keys
        return epoch <= revoked_at

    def distinct_roots(self, relay_ids: list[str]) -> list[str]:
        """把中继见证折叠为独立信任根集合（同根见证只算一个）。"""
        seen: list[str] = []
        for relay_id in relay_ids:
            root_id = self.relay_root.get(relay_id)
            if root_id is not None and root_id not in seen:
                seen.append(root_id)
        return seen

    # ---------- 变更（引擎在 REVOKE 落盘后调用） ----------

    def apply_revocation(self, root_id: str, new_epoch: int) -> None:
        if root_id not in self.root_keys:
            raise KeyError(f"未知信任根: {root_id}")
        # 该根在旧代 new_epoch-1 仍有效，进入 new_epoch 起失效
        self.root_revoked_at[root_id] = new_epoch - 1
        self.epoch = new_epoch
        self._save()

    def set_epoch(self, epoch: int) -> None:
        """恢复路径：以日志重放出的权威授权代覆盖缓存。"""
        self.epoch = epoch
        self._save()

    def snapshot(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "roots": sorted(self.root_keys),
            "relay_root": dict(sorted(self.relay_root.items())),
            "root_revoked_at": dict(sorted(
                (k, v) for k, v in self.root_revoked_at.items())),
        }

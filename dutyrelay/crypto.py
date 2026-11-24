"""离线密码学原语：消息摘要与中继见证。

真实系统中中继见证应是信任根私钥下的数字签名；本模拟完全离线，
用每个信任根持有的本地 HMAC 密钥替代私钥。核验只需公开的根->密钥映射
（模拟信任根证书/预共享材料），不依赖任何网络服务。
"""

from __future__ import annotations

import hashlib
import hmac
import json

from .types import Witness


def message_digest(channel_id: str, seq: int, payload: bytes) -> str:
    """合成消息的摘要：SHA-256(通道 || 序号 || 载荷)。"""
    h = hashlib.sha256()
    h.update(channel_id.encode("utf-8"))
    h.update(b"\x1f")
    h.update(str(seq).encode("ascii"))
    h.update(b"\x1f")
    h.update(payload)
    return h.hexdigest()


def _canonical_witness_bytes(channel_id: str, seq: int, digest: str,
                             epoch: int, relay_id: str, root_id: str) -> bytes:
    """规范见证载荷：字段顺序固定、JSON 紧凑编码，杜绝等价多编码。"""
    body = {
        "channel_id": channel_id,
        "seq": seq,
        "digest": digest,
        "epoch": epoch,
        "relay_id": relay_id,
        "root_id": root_id,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_witness(channel_id: str, seq: int, digest: str, epoch: int,
                 relay_id: str, root_id: str, root_key: bytes) -> Witness:
    """中继在其信任根密钥下对提交要素出具见证。"""
    msg = _canonical_witness_bytes(channel_id, seq, digest, epoch,
                                   relay_id, root_id)
    mac = hmac.new(root_key, msg, hashlib.sha256).hexdigest()
    return Witness(relay_id=relay_id, root_id=root_id, mac=mac)


def verify_witness(w: Witness, channel_id: str, seq: int, digest: str,
                   epoch: int, root_keys: dict[str, bytes]) -> bool:
    """离线核验单个见证：根必须已知且 HMAC 必须逐字节匹配。"""
    key = root_keys.get(w.root_id)
    if key is None:
        return False
    msg = _canonical_witness_bytes(channel_id, seq, digest, epoch,
                                   w.relay_id, w.root_id)
    expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, w.mac)

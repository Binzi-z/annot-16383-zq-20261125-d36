"""单元测试：核验规则、落盘恢复、小模型差分与分段访问语义。

运行：python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dutyrelay import minimodel as mm
from dutyrelay.crypto import make_witness, message_digest
from dutyrelay.engine import Engine
from dutyrelay.factory import (CHANNELS, TOPOLOGY, make_same_root_submission,
                               make_submission, new_engine)
from dutyrelay.logstore import CommitLog
from dutyrelay.minidiff import run_differential
from dutyrelay.segments import AccessStats
from dutyrelay.types import R, Submission


class EngineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.eng = new_engine(self.base / "engine")

    def tearDown(self) -> None:
        self.eng.close()
        self._tmp.cleanup()


class TestValidationRules(EngineTestBase):
    def test_two_distinct_roots_commit(self):
        sub = make_submission(self.eng, CHANNELS[0], 1, b"ok")
        v = self.eng.submit(sub)
        self.assertTrue(v.accepted)
        self.assertEqual(v.reason, R.OK)
        self.assertEqual(v.csn, 1)

    def test_same_root_witnesses_count_as_one(self):
        sub = make_same_root_submission(self.eng, CHANNELS[0], 2, b"same")
        v = self.eng.submit(sub)
        self.assertFalse(v.accepted)
        self.assertEqual(v.reason, R.QUORUM_TRUST)
        self.assertEqual(v.evidence["distinct_roots"], ["rootA"])

    def test_single_witness_quorum_count(self):
        digest = message_digest(CHANNELS[0], 3, b"one")
        relay, root = next(
            (r, rr) for r, rr in self.eng.registry.relay_root.items()
            if rr == "rootA")
        w = make_witness(CHANNELS[0], 3, digest, 0, relay, root,
                         self.eng.registry.root_keys[root])
        v = self.eng.submit(Submission(CHANNELS[0], 3, digest, 0, (w,)))
        self.assertEqual(v.reason, R.QUORUM_COUNT)

    def test_tampered_mac_rejected(self):
        sub = make_submission(self.eng, CHANNELS[0], 4, b"mac")
        bad_w = sub.witnesses[0]
        from dutyrelay.types import Witness
        tampered = Witness(bad_w.relay_id, bad_w.root_id, "00" * 32)
        bad_sub = Submission(sub.channel_id, sub.seq, sub.digest, sub.epoch,
                             (tampered, sub.witnesses[1]))
        self.assertEqual(self.eng.submit(bad_sub).reason, R.WITNESS_BAD)

    def test_wrong_root_claim_rejected(self):
        sub = make_submission(self.eng, CHANNELS[0], 5, b"claim")
        from dutyrelay.types import Witness
        w0 = sub.witnesses[0]
        fake = Witness(w0.relay_id, "rootC", w0.mac)  # 中继并不属于 rootC
        bad_sub = Submission(sub.channel_id, sub.seq, sub.digest, sub.epoch,
                             (fake, sub.witnesses[1]))
        self.assertEqual(self.eng.submit(bad_sub).reason, R.WITNESS_BAD)

    def test_stale_epoch_rejected_after_revocation(self):
        self.eng.revoke_root("rootB", channels=CHANNELS)
        stale = make_submission(self.eng, CHANNELS[0], 6, b"stale", epoch=0)
        v = self.eng.submit(stale)
        self.assertEqual(v.reason, R.EPOCH_STALE)
        # 重新审批：授权代必须是新代，且见证须来自两个仍有效的根
        # （rootB 已撤销，改用 rootA + rootC）
        digest = message_digest(CHANNELS[0], 6, b"stale")
        ws = []
        for root in ("rootA", "rootC"):
            relay = next(r for r, rr in self.eng.registry.relay_root.items()
                         if rr == root)
            ws.append(make_witness(CHANNELS[0], 6, digest, 1, relay, root,
                                   self.eng.registry.root_keys[root]))
        fresh = Submission(CHANNELS[0], 6, digest, 1, tuple(ws))
        self.assertTrue(self.eng.submit(fresh).accepted)

    def test_revoked_root_witness_rejected(self):
        self.eng.revoke_root("rootB", channels=CHANNELS)
        # 手工绑定新代号但仍使用已撤销根的见证
        digest = message_digest(CHANNELS[0], 7, b"dead-root")
        ws = []
        for root in ("rootA", "rootB"):
            relay = next(r for r, rr in self.eng.registry.relay_root.items()
                         if rr == root)
            ws.append(make_witness(CHANNELS[0], 7, digest, 1, relay, root,
                                   self.eng.registry.root_keys[root]))
        v = self.eng.submit(Submission(CHANNELS[0], 7, digest, 1, tuple(ws)))
        self.assertEqual(v.reason, R.WITNESS_ROOT_REVOKED)

    def test_duplicate_commit_is_idempotent(self):
        sub = make_submission(self.eng, CHANNELS[0], 8, b"dup")
        first = self.eng.submit(sub)
        second = self.eng.submit(sub)
        self.assertEqual(first.csn, second.csn)
        self.assertEqual(second.reason, R.DUPLICATE_COMMIT)
        commits = [r for r in self.eng.log.replay() if r["type"] == "COMMIT"]
        self.assertEqual(len(commits), 1)


class TestPersistenceAndRecovery(EngineTestBase):
    def test_reopen_rebuilds_indices(self):
        for seq in range(5):
            self.eng.submit(make_submission(self.eng, CHANNELS[0], seq,
                                            f"p{seq}".encode()))
        self.eng.revoke_root("rootC", channels=CHANNELS)
        self.eng.close()
        reopened = Engine.reopen(self.base / "engine")
        try:
            self.assertEqual(reopened.current_epoch(), 1)
            self.assertEqual(len(reopened.committed), 5)
            self.assertEqual(len(reopened.revocations), 1)
            visible = reopened.visible_committed()
            self.assertEqual([v["csn"] for v in visible], [1, 2, 3, 4, 5])
        finally:
            reopened.close()

    def test_torn_tail_frame_is_truncated(self):
        sub = make_submission(self.eng, CHANNELS[0], 9, b"torn")
        self.eng.submit(sub)
        self.eng.close()
        log_path = self.base / "engine" / "commit.log"
        with open(log_path, "ab") as fh:
            fh.write(b"DLOG\x20\x00\x00\x00\x01\x02\x03\x04partial")
        reopened = Engine.reopen(self.base / "engine")
        try:
            self.assertEqual(len(reopened.committed), 1)
            # 半帧已被物理截断
            raw = log_path.read_bytes()
            self.assertNotIn(b"partial", raw)
        finally:
            reopened.close()

    def test_corrupt_tail_payload_is_truncated(self):
        sub = make_submission(self.eng, CHANNELS[0], 10, b"corrupt")
        self.eng.submit(sub)
        self.eng.close()
        log_path = self.base / "engine" / "commit.log"
        data = bytearray(log_path.read_bytes())
        data[-1] ^= 0xFF  # 破坏最后一帧 payload 末字节 -> CRC 不符，按未完成尾部帧截断
        log_path.write_bytes(bytes(data))
        reopened = Engine.reopen(self.base / "engine")
        try:
            self.assertEqual(len(reopened.committed), 0)
        finally:
            reopened.close()

    def test_receipt_loss_repair_no_new_commit(self):
        sub = make_submission(self.eng, CHANNELS[1], 11, b"receipt")
        self.eng.submit(sub)
        self.assertTrue(self.eng.drop_receipt(sub.digest))
        self.eng.close()
        reopened = Engine.reopen(self.base / "engine")
        try:
            repaired = reopened.recover_pending_receipts()
            self.assertEqual(repaired, [sub.digest])
            self.assertEqual(reopened.recover_pending_receipts(), [])
            commits = [r for r in reopened.log.replay()
                       if r["type"] == "COMMIT"]
            self.assertEqual(len(commits), 1)
        finally:
            reopened.close()


class TestRelocationAndReceipts(EngineTestBase):
    def test_same_seq_different_digest_and_late_receipt(self):
        ch = CHANNELS[0]
        old = make_submission(self.eng, ch, 20, b"old")
        self.eng.submit(old)          # 定位符 (ch, 20, gen0) -> old
        self.eng.relocate(ch)
        # 搬迁开启新一代命名空间：同序号 20、不同摘要在 gen1 是合法新消息
        new = make_submission(self.eng, ch, 20, b"new")
        self.assertTrue(self.eng.submit(new).accepted)
        # 同代同号再来第三个摘要：定位符 (ch, 20, gen1) 已绑定 new -> 冲突
        third = make_submission(self.eng, ch, 20, b"third-body")
        v = self.eng.submit(third)
        self.assertEqual(v.reason, R.DIGEST_MISMATCH)
        self.assertEqual(v.evidence["existing_digest"], new.digest)
        self.assertEqual(v.evidence["incoming_digest"], third.digest)
        # 旧代（gen0）迟到回执仍然有效且幂等
        ok = self.eng.inbound_receipt(ch, 20, old.digest, 0)
        self.assertTrue(ok.accepted)
        # 已承诺摘要但定位符代不符 -> DIGEST_MISMATCH
        bad_gen = self.eng.inbound_receipt(ch, 20, new.digest, 0)
        self.assertEqual(bad_gen.reason, R.DIGEST_MISMATCH)
        # 幽灵回执：从未出现过的定位符
        ghost = self.eng.inbound_receipt(ch, 999, "ff" * 32, 0)
        self.assertEqual(ghost.reason, R.RECEIPT_UNKNOWN)

    def test_receipt_after_relocate_with_new_gen_locator(self):
        ch = CHANNELS[1]
        self.eng.relocate(ch)
        sub = make_submission(self.eng, ch, 21, b"gen1")
        self.eng.submit(sub)
        ok = self.eng.inbound_receipt(ch, 21, sub.digest, 1)
        self.assertTrue(ok.accepted)
        # 摘要真实存在但回执声明的搬迁代不对：定位符不一致
        wrong_gen = self.eng.inbound_receipt(ch, 21, sub.digest, 0)
        self.assertEqual(wrong_gen.reason, R.DIGEST_MISMATCH)
        # 完全未知的摘要与定位符
        ghost = self.eng.inbound_receipt(ch, 888, "ab" * 32, 1)
        self.assertEqual(ghost.reason, R.RECEIPT_UNKNOWN)


class TestSegmentAccess(unittest.TestCase):
    def test_selective_scan_skips_resolved_segments(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Engine.create(Path(d) / "e", TOPOLOGY, CHANNELS,
                                segment_capacity=2, durable=False)
            ch = CHANNELS[0]
            # 填满两个分段并全部承诺
            for seq in range(4):
                eng.submit(make_submission(eng, ch, seq, f"s{seq}".encode()))
            # 第三条尾分段里放一条未承诺
            pending = make_submission(eng, ch, 4, b"pending")
            eng.prepare(pending)
            eng.reconcile_channel(ch, AccessStats())
            stats = AccessStats()
            found = eng.reapproval_candidates(ch, full=False, stats=stats)
            self.assertEqual([r["digest"] for r in found], [pending.digest])
            # 只打开 1 个有关分段（尾分段），跳过两个已解决封存分段
            self.assertEqual(stats.segment_opens, 1)
            self.assertEqual(stats.records_inspected, 1)
            full = AccessStats()
            eng.reapproval_candidates(ch, full=True, stats=full)
            self.assertEqual(full.segment_opens, 3)
            self.assertEqual(full.records_inspected, 5)
            eng.close()


class TestCommitLogFrames(unittest.TestCase):
    def test_round_trip_many_records(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.log"
            with CommitLog(path) as log:
                for i in range(200):
                    log.append({"i": i, "kind": "COMMIT" if i % 2 else "REVOKE"})
            with CommitLog(path) as log:
                records = list(log.replay())
            self.assertEqual([r["i"] for r in records], list(range(200)))


class TestMiniModel(unittest.TestCase):
    def test_enumeration_covers_both_visible_shapes(self):
        items = mm.enumerate_interleavings(
            {"rootA": ["a1", "a2"], "rootB": ["b1"]}, ["c1", "c2"])
        self.assertGreater(len(items), 1)
        summary = mm.summarize(items)
        shapes = summary["visible_set_shapes"]
        # 至少存在"m1 可见"与"m1 不可见（撤销抢先）"两类可见集
        self.assertIn("digest-m1", shapes)
        self.assertIn("<empty>", shapes)
        # 拒绝证据里同时出现 EPOCH_STALE 与 QUORUM_TRUST
        reasons = summary["rejection_reason_counts"]
        self.assertIn(mm.EPOCH_STALE, reasons)
        self.assertIn(mm.QUORUM_TRUST, reasons)

    def test_differential_against_real_engine(self):
        report = run_differential()
        self.assertTrue(
            report.passed,
            msg=json.dumps(report.mismatches, ensure_ascii=False, indent=2))
        # 差分必须覆盖到全部关键原因码
        for reason in (mm.OK, mm.QUORUM_TRUST, mm.EPOCH_STALE):
            self.assertIn(reason, report.reason_coverage)


if __name__ == "__main__":
    unittest.main(verbosity=2)

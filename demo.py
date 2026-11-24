"""离线核验与落盘模拟的统一演示入口（仅标准库）。

用法：
    python demo.py                # 全量运行：三交错 + 小模型差分 + 六万消息压测
    python demo.py --quick        # 跳过六万消息压测
所有落盘产物写入 artifacts/ 下的独立目录，并生成 JSON 报告。
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

# Windows 传统控制台可能是 GBK：统一 UTF-8 输出并对无法显示的字符降级，
# 保证任何原因码/中文证据都不会让演示进程崩溃。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from dutyrelay.benchmark import TOTAL_MESSAGES, run_benchmark
from dutyrelay.minidiff import run_differential
from dutyrelay.minimodel import enumerate_interleavings, summarize
from dutyrelay.scenarios import run_all_scenarios


def _print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="应急通道跨域信任撤销模拟")
    parser.add_argument("--quick", action="store_true",
                        help="跳过六万消息压测")
    parser.add_argument("--out", default="artifacts/run",
                        help="落盘产物目录（默认 artifacts/run）")
    args = parser.parse_args(argv)

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    overall_ok = True
    started = time.perf_counter()

    # ---------- 1. 三种受控交错 + 崩溃恢复 ----------
    _print_header("一、三种受控交错复测（屏障驱动 + 重启恢复）")
    results = run_all_scenarios(out / "scenarios")
    for res in results:
        status = "PASS" if res.passed else "FAIL"
        print(f"[{status}] {res.name}")
        print(f"       {res.description}")
        for label, ok, detail in res.assertions:
            mark = "  [v]" if ok else "  [x]"
            tail = f" -- {detail}" if detail and not ok else ""
            print(f"   {mark} {label}{tail}")
        overall_ok &= res.passed

    # ---------- 2. 独立小模型枚举 + 差分 ----------
    _print_header("二、独立小模型枚举短交错（可见集 / 拒绝证据）")
    topology = {"rootA": ["relay-A1", "relay-A2"],
                "rootB": ["relay-B1"]}
    interleavings = enumerate_interleavings(topology, ["ch1", "ch2"])
    summary = summarize(interleavings)
    print(f"枚举交错数：{summary['total_interleavings']}")
    print("可见集形状（摘要集合 -> 交错数）：")
    for shape, count in summary["visible_set_shapes"].items():
        print(f"  {shape:24s} {count}")
    print("拒绝证据原因计数：")
    for reason, count in summary["rejection_reason_counts"].items():
        print(f"  {reason:24s} {count}")
    with open(out / "minimodel-enumeration.json", "w", encoding="utf-8") as fh:
        json.dump({"summary": summary,
                   "interleavings": [
                       {"schedule": list(i.schedule),
                        "outcomes": [list(o) for o in i.outcomes],
                        "visible_digests": list(i.visible_digests),
                        "rejection_reasons": list(i.rejection_reasons)}
                       for i in interleavings]},
                  fh, ensure_ascii=False, indent=2)

    _print_header("三、小模型 vs 真实落盘引擎差分比对")
    diff = run_differential(base_dir=out / "minidiff")
    print(f"比对交错数：{diff.interleavings_checked}")
    print(f"原因码覆盖：{json.dumps(diff.reason_coverage, ensure_ascii=False)}")
    print(f"差分结果：{'全部一致 PASS' if diff.passed else '存在不一致 FAIL'}")
    if not diff.passed:
        print(json.dumps(diff.mismatches, ensure_ascii=False, indent=2))
    overall_ok &= diff.passed
    with open(out / "minidiff-report.json", "w", encoding="utf-8") as fh:
        json.dump({"interleavings_checked": diff.interleavings_checked,
                   "passed": diff.passed,
                   "reason_coverage": diff.reason_coverage,
                   "mismatches": diff.mismatches},
                  fh, ensure_ascii=False, indent=2)

    # ---------- 3. 六万消息压测 ----------
    if not args.quick:
        _print_header(f"四、{TOTAL_MESSAGES} 条消息单通道撤销选择性访问核对")
        bench = run_benchmark(out / "benchmark")
        for ch, info in bench.channels.items():
            print(f"通道 {ch}：暂存 {info['staged_records']} 条 / "
                  f"{info['segment_total']} 分段，"
                  f"未承诺 {info['known_pending_digests']} 条，"
                  f"清单标记解决 {info['segments_marked_resolved']} 段")
        rev = bench.revocation
        pre_sel = rev["pre_revoke_selective_scan"]
        pre_full = rev["pre_revoke_full_scan"]
        revoke_sel = rev["revoke_selective_scan"]
        other = rev["other_channel_access"]
        print("撤销前选择性扫描：打开 "
              f"{pre_sel['segment_opens']} 分段 / 检查 "
              f"{pre_sel['records_inspected']} 条记录")
        print("撤销前完整全量扫描：打开 "
              f"{pre_full['segment_opens']} 分段 / 检查 "
              f"{pre_full['records_inspected']} 条记录")
        print("撤销清扫实际访问：打开 "
              f"{revoke_sel['segment_opens']} 分段 / 检查 "
              f"{revoke_sel['records_inspected']} 条记录，"
              f"落盘拒绝证据 {rev['revoked_uncommitted_evidence']} 条")
        print(f"另一通道访问量：分段 {other['segment_opens']} / "
              f"记录 {other['records_inspected']}（必须为 0）")
        print("一致性核对：")
        for key, value in bench.consistency.items():
            print(f"  {'[v]' if value else '[x]'} {key}: {value}")
        print(f"压测耗时：{bench.elapsed_seconds:.2f}s")
        overall_ok &= bench.passed

    _print_header("总结")
    elapsed = time.perf_counter() - started
    print(f"总耗时 {elapsed:.2f}s；总体结果："
          f"{'全部通过 PASS' if overall_ok else '存在失败 FAIL'}")
    print(f"落盘产物与报告目录：{out.resolve()}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())

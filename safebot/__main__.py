from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from safebot.bot import create_runtime, discover_target_windows, run_forever
from safebot.logging_config import configure_logging
from safebot.risk import format_group_reply
from safebot.scanners.file_scanner import FileScanner
from safebot.scanners.safebrowsing import SafeBrowsingClient
from safebot.scanners.url_rules import UrlRuleScanner
from safebot.scanners.url_scanner import UrlScanner
from safebot.scanners.virustotal import VirusTotalClient
from safebot.settings import Settings, load_settings
from safebot.ui.uia_adapter import QQAutomation
from safebot.whitelist import Whitelist


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    if getattr(args, "dry_run", None) is not None:
        settings.bot.dry_run = args.dry_run
    configure_logging(settings.bot.log_file, verbose=args.verbose)

    if args.command == "list-windows":
        return cmd_list_windows(settings)
    if args.command == "dump-tree":
        return cmd_dump_tree(settings, args)
    if args.command == "scan-url":
        return cmd_scan_url(settings, args.url)
    if args.command == "scan-file":
        return cmd_scan_file(settings, args.path)
    if args.command == "run":
        return cmd_run(settings, assume_yes=args.yes)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m safebot", description="QQ 群聊安全扫描 Bot")
    parser.set_defaults(config="config/settings.json", verbose=False)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config/settings.json", help="配置文件路径")
    common.add_argument("--verbose", action="store_true", help="输出调试日志")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-windows", parents=[common], help="列出当前可发现的 QQ/聊天窗口")

    dump_tree = subparsers.add_parser("dump-tree", parents=[common], help="导出指定窗口的 UIAutomation 树")
    dump_tree.add_argument("--title", required=True, help="窗口标题关键字")
    dump_tree.add_argument("--depth", type=int, default=6, help="导出深度")
    dump_tree.add_argument("--output", help="输出文件路径")

    scan_url = subparsers.add_parser("scan-url", parents=[common], help="扫描单个 URL")
    scan_url.add_argument("url")

    scan_file = subparsers.add_parser("scan-file", parents=[common], help="扫描本地文件")
    scan_file.add_argument("path")

    run = subparsers.add_parser("run", parents=[common], help="开始监控已打开的群聊窗口")
    run.add_argument("--yes", action="store_true", help="跳过窗口确认")
    send_group = run.add_mutually_exclusive_group()
    send_group.add_argument("--dry-run", dest="dry_run", action="store_true", help="只记录不发送")
    send_group.add_argument("--send", dest="dry_run", action="store_false", help="真实发送群消息")
    run.set_defaults(dry_run=None)
    return parser


def cmd_list_windows(settings: Settings) -> int:
    automation = QQAutomation(settings.bot.accessibility_map_path)
    windows = automation.discover_windows(
        title_keywords=settings.bot.window_title_keywords,
        class_keywords=settings.bot.window_class_keywords,
    )
    if not windows:
        print("未发现匹配窗口。请确认 QQ 群聊独立窗口已打开，或调整 window_*_keywords。")
        return 1
    for index, window in enumerate(windows, start=1):
        print(
            f"{index}. title={window.title!r} class={window.class_name!r} "
            f"hwnd={window.hwnd} id={window.window_id} process={window.process_path!r}"
        )
    return 0


def cmd_dump_tree(settings: Settings, args: argparse.Namespace) -> int:
    automation = QQAutomation(settings.bot.accessibility_map_path)
    windows = automation.discover_windows(title_keywords=[args.title], class_keywords=settings.bot.window_class_keywords)
    if not windows:
        print(f"未发现标题包含 {args.title!r} 的窗口")
        return 1
    text = automation.dump_tree(windows[0], max_depth=args.depth)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"已写入：{args.output}")
    else:
        print(text)
    return 0


def cmd_scan_url(settings: Settings, url: str) -> int:
    whitelist = Whitelist(settings.bot.whitelist_path)
    scanner = UrlScanner(
        virustotal=_vt(settings),
        safe_browsing=_safe_browsing(settings),
        rules=UrlRuleScanner(settings.rules),
        whitelist=whitelist,
        submit_to_virustotal=settings.api.submit_urls_to_virustotal,
    )
    result = scanner.scan(url)
    print(json.dumps(_result_to_dict(result), ensure_ascii=False, indent=2))
    if result.level.value != "safe":
        print()
        print(format_group_reply(result, sender="命令行", target_label="链接"))
    return 0


def cmd_scan_file(settings: Settings, path: str) -> int:
    scanner = FileScanner(
        virustotal=_vt(settings),
        upload_to_virustotal=settings.api.upload_files_to_virustotal,
    )
    result = scanner.scan(path)
    print(json.dumps(_result_to_dict(result), ensure_ascii=False, indent=2))
    return 0


def cmd_run(settings: Settings, assume_yes: bool) -> int:
    runtime = create_runtime(settings)
    windows = discover_target_windows(runtime)
    if not windows:
        print("当前未发现可监控聊天窗口；程序会继续运行，并在后续轮询中自动发现新打开的 QQ 聊天窗口。")
    else:
        print("当前将监控以下窗口，后续新打开的 QQ 聊天窗口也会自动加入：")
        for index, window in enumerate(windows, start=1):
            print(f"{index}. {window.title} ({window.class_name})")
    if not assume_yes:
        answer = input("确认开始监控？输入 yes 继续：").strip().lower()
        if answer != "yes":
            return 0
    run_forever(runtime, windows)
    return 0


def _vt(settings: Settings) -> VirusTotalClient | None:
    if not settings.api.virustotal_api_key:
        return None
    return VirusTotalClient(
        settings.api.virustotal_api_key,
        requests_per_minute=settings.api.virustotal_requests_per_minute,
    )


def _safe_browsing(settings: Settings) -> SafeBrowsingClient | None:
    if not settings.api.google_safe_browsing_api_key:
        return None
    return SafeBrowsingClient(settings.api.google_safe_browsing_api_key)


def _result_to_dict(result: object) -> dict:
    return {
        "target": result.target,
        "target_type": result.target_type,
        "score": result.score,
        "level": result.level.value,
        "suppressed": result.suppressed,
        "vt_hits": result.vt_hits,
        "vt_total": result.vt_total,
        "safe_browsing_matches": result.safe_browsing_matches,
        "findings": [
            {
                "code": item.code,
                "title": item.title,
                "detail": item.detail,
                "points": item.points,
                "source": item.source,
            }
            for item in result.findings
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

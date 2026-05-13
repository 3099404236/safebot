from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from safebot.commands import handle_command
from safebot.models import ChatMessage, RiskLevel
from safebot.risk import format_group_reply
from safebot.scanners.file_scanner import FileScanner
from safebot.scanners.safebrowsing import SafeBrowsingClient
from safebot.scanners.url_rules import UrlRuleScanner
from safebot.scanners.url_scanner import UrlScanner
from safebot.scanners.virustotal import VirusTotalClient
from safebot.settings import Settings
from safebot.ui.uia_adapter import QQAutomation, QQWindow
from safebot.url_utils import extract_urls
from safebot.whitelist import Whitelist

LOG = logging.getLogger(__name__)

FILE_NAME_RE = re.compile(
    r"(?P<name>[\w\u4e00-\u9fff .()\[\]-]+\.(?:exe|zip|rar|7z|docx|docm|xlsx|xlsm|pptx|pptm|pdf|js|vbs|bat|cmd|msi|jar|scr|lnk))",
    re.IGNORECASE,
)


@dataclass
class BotRuntime:
    settings: Settings
    automation: QQAutomation
    whitelist: Whitelist
    url_scanner: UrlScanner
    file_scanner: FileScanner
    seen_messages: set[str] = field(default_factory=set)


def create_runtime(settings: Settings) -> BotRuntime:
    whitelist = Whitelist(settings.bot.whitelist_path)
    vt_client = None
    if settings.api.virustotal_api_key:
        vt_client = VirusTotalClient(
            settings.api.virustotal_api_key,
            requests_per_minute=settings.api.virustotal_requests_per_minute,
        )
    safe_browsing = None
    if settings.api.google_safe_browsing_api_key:
        safe_browsing = SafeBrowsingClient(settings.api.google_safe_browsing_api_key)

    rules = UrlRuleScanner(settings.rules)
    return BotRuntime(
        settings=settings,
        automation=QQAutomation(settings.bot.accessibility_map_path),
        whitelist=whitelist,
        url_scanner=UrlScanner(
            virustotal=vt_client,
            safe_browsing=safe_browsing,
            rules=rules,
            whitelist=whitelist,
            submit_to_virustotal=settings.api.submit_urls_to_virustotal,
        ),
        file_scanner=FileScanner(
            virustotal=vt_client,
            upload_to_virustotal=settings.api.upload_files_to_virustotal,
        ),
    )


def discover_target_windows(runtime: BotRuntime) -> list[QQWindow]:
    settings = runtime.settings.bot
    windows = runtime.automation.discover_windows(
        title_keywords=settings.window_title_keywords,
        class_keywords=settings.window_class_keywords,
    )
    if settings.monitored_window_titles:
        titles = [item.lower() for item in settings.monitored_window_titles]
        windows = [window for window in windows if any(title in window.title.lower() for title in titles)]
    return windows


def run_forever(runtime: BotRuntime, windows: list[QQWindow]) -> None:
    LOG.info("Monitoring %d QQ windows; dry_run=%s", len(windows), runtime.settings.bot.dry_run)
    while True:
        for window in windows:
            try:
                _process_window(runtime, window)
            except Exception:
                LOG.exception("Failed to process window %s", window.title)
        time.sleep(runtime.settings.bot.poll_interval_seconds)


def _process_window(runtime: BotRuntime, window: QQWindow) -> None:
    for message in runtime.automation.read_visible_messages(window):
        if _already_seen(runtime, message):
            continue
        _handle_message(runtime, window, message)


def _already_seen(runtime: BotRuntime, message: ChatMessage) -> bool:
    key = message.raw_id or message.dedupe_key
    if key in runtime.seen_messages:
        return True
    runtime.seen_messages.add(key)
    if len(runtime.seen_messages) > 10_000:
        runtime.seen_messages = set(list(runtime.seen_messages)[-5_000:])
    return False


def _handle_message(runtime: BotRuntime, window: QQWindow, message: ChatMessage) -> None:
    command = handle_command(message.content, runtime.whitelist)
    if command.handled:
        if command.reply:
            _send(runtime, window, command.reply)
        return

    for url in extract_urls(message.content):
        LOG.info("Scanning URL from %s/%s: %s", window.title, message.sender, url)
        result = runtime.url_scanner.scan(url)
        if result.suppressed:
            LOG.info("URL is whitelisted; suppressing group report: %s", url)
            continue
        if result.level == RiskLevel.SAFE:
            LOG.info("URL score is safe; suppressing group report: %s score=%d", url, result.score)
            continue
        reply = format_group_reply(result, sender=message.sender, target_label="链接")
        _send(runtime, window, reply)

    _handle_file_message(runtime, window, message)


def _send(runtime: BotRuntime, window: QQWindow, text: str) -> None:
    if runtime.settings.bot.dry_run:
        LOG.info("[dry-run] would send to %s:\n%s", window.title, text)
        return
    runtime.automation.send_text(window, text, send_mode=runtime.settings.bot.send_mode)


def _handle_file_message(runtime: BotRuntime, window: QQWindow, message: ChatMessage) -> None:
    filename = _extract_file_name(message.content)
    if not filename:
        return
    download_dir = runtime.settings.bot.qq_download_dir
    if not download_dir:
        LOG.info("File message detected but qq_download_dir is not configured: %s", filename)
        return
    directory = Path(download_dir)
    if not directory.exists():
        LOG.warning("Configured QQ download dir does not exist: %s", directory)
        return
    if runtime.settings.bot.dry_run:
        LOG.info("[dry-run] would download and scan file from %s/%s: %s", window.title, message.sender, filename)
        return

    before = _snapshot_files(directory)
    if not runtime.automation.click_download_for_message(message):
        LOG.warning("Download button not found for file message: %s", filename)
        return
    downloaded = _wait_for_download(directory, before, preferred_name=filename, timeout_seconds=30)
    if downloaded is None:
        LOG.warning("Timed out waiting for QQ download: %s", filename)
        return

    max_bytes = runtime.settings.bot.max_file_size_mb * 1024 * 1024
    if downloaded.stat().st_size > max_bytes:
        LOG.info("Skipping oversized file %s (%d bytes)", downloaded, downloaded.stat().st_size)
        return

    result = runtime.file_scanner.scan(downloaded)
    if result.level != RiskLevel.SAFE:
        reply = format_group_reply(result, sender=message.sender, target_label="文件")
        _send(runtime, window, reply)

    if runtime.settings.bot.delete_scanned_files_after_scan:
        try:
            downloaded.unlink()
        except OSError:
            LOG.warning("Failed to delete scanned file: %s", downloaded)


def _extract_file_name(text: str) -> str | None:
    match = FILE_NAME_RE.search(text or "")
    if not match:
        return None
    return match.group("name").strip()


def _snapshot_files(directory: Path) -> dict[Path, tuple[float, int]]:
    snapshot: dict[Path, tuple[float, int]] = {}
    for path in directory.iterdir():
        if path.is_file():
            stat = path.stat()
            snapshot[path] = (stat.st_mtime, stat.st_size)
    return snapshot


def _wait_for_download(
    directory: Path,
    before: dict[Path, tuple[float, int]],
    *,
    preferred_name: str,
    timeout_seconds: float,
) -> Path | None:
    deadline = time.monotonic() + timeout_seconds
    last_candidate: Path | None = None
    last_size = -1
    while time.monotonic() < deadline:
        candidates = []
        for path in directory.iterdir():
            if not path.is_file() or path.suffix.lower() in {".tmp", ".crdownload"}:
                continue
            stat = path.stat()
            previous = before.get(path)
            if previous is None or previous != (stat.st_mtime, stat.st_size):
                candidates.append(path)
        preferred = [path for path in candidates if path.name == preferred_name]
        candidate = (preferred or sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True))[:1]
        if candidate:
            current = candidate[0]
            size = current.stat().st_size
            if current == last_candidate and size == last_size:
                return current
            last_candidate = current
            last_size = size
        time.sleep(1)
    return None

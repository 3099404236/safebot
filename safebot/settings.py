from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ApiSettings:
    virustotal_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    virustotal_requests_per_minute: int = 4
    submit_urls_to_virustotal: bool = False
    upload_files_to_virustotal: bool = False


@dataclass
class BotSettings:
    poll_interval_seconds: float = 2.5
    dry_run: bool = True
    send_mode: str = "enter"
    monitored_window_titles: list[str] = field(default_factory=list)
    window_title_keywords: list[str] = field(default_factory=list)
    window_class_keywords: list[str] = field(default_factory=lambda: ["Chrome", "Qt", "TXGui", "Electron"])
    whitelist_path: str = "config/whitelist.json"
    accessibility_map_path: str = "config/accessibility_map.example.json"
    max_file_size_mb: int = 50
    qq_download_dir: str = ""
    delete_scanned_files_after_scan: bool = False
    log_file: str = "logs/safebot.log"


@dataclass
class RuleSettings:
    request_timeout_seconds: float = 8.0
    max_html_bytes: int = 1_048_576
    new_domain_days: int = 30
    brand_keywords: list[str] = field(default_factory=lambda: ["qq", "weixin", "wechat", "学校", "教务", "统一身份认证"])


@dataclass
class Settings:
    api: ApiSettings = field(default_factory=ApiSettings)
    bot: BotSettings = field(default_factory=BotSettings)
    rules: RuleSettings = field(default_factory=RuleSettings)


def _update_dataclass(instance: Any, values: dict[str, Any]) -> None:
    for key, value in values.items():
        if hasattr(instance, key):
            setattr(instance, key, value)


def load_settings(path: str | Path | None = None) -> Settings:
    settings = Settings()
    _load_dotenv(Path(".env"))
    config_path = Path(path) if path else Path("config/settings.json")
    if config_path.exists():
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        _update_dataclass(settings.api, raw.get("api", {}))
        _update_dataclass(settings.bot, raw.get("bot", {}))
        _update_dataclass(settings.rules, raw.get("rules", {}))

    settings.api.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", settings.api.virustotal_api_key)
    settings.api.google_safe_browsing_api_key = os.getenv(
        "GOOGLE_SAFE_BROWSING_API_KEY",
        settings.api.google_safe_browsing_api_key,
    )
    return settings


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def load_json_file(path: str | Path, default: Any) -> Any:
    file_path = Path(path)
    if not file_path.exists():
        return default
    return json.loads(file_path.read_text(encoding="utf-8"))

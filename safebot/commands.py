from __future__ import annotations

from dataclasses import dataclass

from safebot.whitelist import Whitelist


@dataclass(frozen=True)
class CommandResult:
    handled: bool
    reply: str = ""


def handle_command(text: str, whitelist: Whitelist) -> CommandResult:
    normalized = (text or "").strip()
    if normalized.startswith("#信任 "):
        domain = normalized.removeprefix("#信任 ").strip()
        if not domain:
            return CommandResult(True, "白名单指令缺少域名")
        added = whitelist.add(domain)
        return CommandResult(True, f"已加入白名单：{added}")

    if normalized.startswith("#取消信任 "):
        domain = normalized.removeprefix("#取消信任 ").strip()
        if not domain:
            return CommandResult(True, "取消白名单指令缺少域名")
        removed = whitelist.remove(domain)
        return CommandResult(True, f"已从白名单移除：{removed}")

    if normalized == "#白名单列表":
        domains = whitelist.list_domains()
        if not domains:
            return CommandResult(True, "当前白名单为空")
        return CommandResult(True, "当前白名单：\n" + "\n".join(f"- {item}" for item in domains))

    return CommandResult(False)

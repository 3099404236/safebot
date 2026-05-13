from __future__ import annotations

import ctypes
import hashlib
import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from safebot.models import ChatMessage
from safebot.settings import load_json_file

LOG = logging.getLogger(__name__)


@dataclass
class QQWindow:
    control: Any
    title: str
    class_name: str
    window_id: str
    hwnd: int | None = None
    process_path: str = ""


class UIAutomationUnavailable(RuntimeError):
    pass


class QQAutomation:
    def __init__(self, accessibility_map_path: str):
        self.auto = _load_uiautomation()
        self.map = load_json_file(accessibility_map_path, default={})

    def discover_windows(
        self,
        *,
        title_keywords: list[str] | None = None,
        class_keywords: list[str] | None = None,
    ) -> list[QQWindow]:
        title_keywords = [item.lower() for item in (title_keywords or []) if item]
        class_keywords = [item.lower() for item in (class_keywords or []) if item]
        windows: list[QQWindow] = []
        for hwnd, title, class_name, process_path in _enum_visible_windows():
            if not title:
                continue
            title_match = not title_keywords or any(keyword in title.lower() for keyword in title_keywords)
            class_match = not class_keywords or any(keyword in class_name.lower() for keyword in class_keywords)
            process_match = _looks_like_qq_process(process_path)
            if title_match and class_match and (process_match or title_keywords):
                control = self.auto.ControlFromHandle(hwnd)
                windows.append(
                    QQWindow(
                        control=control,
                        title=_attr(control, "Name") or title,
                        class_name=_attr(control, "ClassName") or class_name,
                        window_id=_window_id(title, class_name, hwnd),
                        hwnd=hwnd,
                        process_path=process_path,
                    )
                )
        return windows

    def dump_tree(self, window: QQWindow, max_depth: int = 6) -> str:
        lines: list[str] = []

        def walk(control: Any, depth: int) -> None:
            if depth > max_depth:
                return
            info = control_info(control)
            indent = "  " * depth
            lines.append(
                f"{indent}- type={info['control_type']} name={info['name']!r} class={info['class_name']!r} "
                f"automation_id={info['automation_id']!r}"
            )
            for child in _safe_children(control):
                walk(child, depth + 1)

        walk(window.control, 0)
        return "\n".join(lines)

    def read_visible_messages(self, window: QQWindow) -> list[ChatMessage]:
        message_list = self._find_slot(window.control, "message_list")
        if message_list is None:
            message_list = self._heuristic_message_list(window.control)
        if message_list is None:
            LOG.warning("Message list not found for window %s", window.title)
            return []

        messages: list[ChatMessage] = []
        items = _message_item_controls(message_list) or _safe_children(message_list) or [message_list]
        for item in items:
            parsed = _parse_message_item(item)
            if parsed is None:
                continue
            sender, content, text = parsed
            sender, content = _guess_sender_and_content(text)
            messages.append(
                ChatMessage(
                    window_id=window.window_id,
                    group_name=window.title,
                    sender=sender,
                    content=content,
                    observed_at=datetime.now(),
                    raw_id=hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest(),
                    source_control=item,
                )
            )
        return messages

    def click_download_for_message(self, message: ChatMessage) -> bool:
        if message.source_control is None:
            return False
        slot = self.map.get("download_button") or {}
        button = None
        if slot.get("selector"):
            button = _find_descendant(message.source_control, slot["selector"], max_depth=5)
        if button is None:
            button = _find_descendant(
                message.source_control,
                {"control_type": "Button", "name_contains": "下载"},
                max_depth=5,
            )
        if button is None:
            return False
        _invoke(button)
        return True

    def send_text(self, window: QQWindow, text: str, send_mode: str = "enter") -> None:
        input_box = self._find_slot(window.control, "input_box")
        if input_box is None:
            input_box = self._find_first_by_type(window.control, "Edit")
        if input_box is None:
            raise RuntimeError(f"input box not found for window {window.title}")

        _set_focus(input_box)
        if not _set_value(input_box, text):
            _paste_text(self.auto, text)

        if send_mode == "button":
            button = self._find_slot(window.control, "send_button")
            if button is None:
                raise RuntimeError(f"send button not found for window {window.title}")
            _invoke(button)
        elif send_mode == "ctrl_enter":
            _send_keys(self.auto, "^({ENTER})", "{Ctrl}{Enter}")
        else:
            _send_keys(self.auto, "{ENTER}", "{Enter}")

    def _find_slot(self, root: Any, slot_name: str) -> Any | None:
        slot = self.map.get(slot_name) or {}
        path = slot.get("path") or []
        if path:
            current = root
            for selector in path:
                current = _find_child(current, selector)
                if current is None:
                    return None
            return current
        selector = slot.get("selector")
        if selector:
            return _find_descendant(root, selector)
        return None

    def _heuristic_message_list(self, root: Any) -> Any | None:
        candidates: list[tuple[int, Any]] = []
        for control in _walk(root, max_depth=8):
            control_type = _attr(control, "ControlTypeName").lower()
            if any(token in control_type for token in ("list", "document", "pane")):
                text_length = len(_extract_text(control, max_depth=2))
                child_count = len(_safe_children(control))
                score = text_length + child_count * 20
                candidates.append((score, control))
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    def _find_first_by_type(self, root: Any, control_type: str) -> Any | None:
        return _find_descendant(root, {"control_type": control_type})


def _load_uiautomation() -> Any:
    try:
        import uiautomation as auto  # type: ignore
    except Exception as exc:
        raise UIAutomationUnavailable(
            "uiautomation is not installed. Run: pip install uiautomation pywinauto"
        ) from exc
    return auto


def control_info(control: Any) -> dict[str, str]:
    return {
        "name": _attr(control, "Name"),
        "class_name": _attr(control, "ClassName"),
        "automation_id": _attr(control, "AutomationId"),
        "control_type": _attr(control, "ControlTypeName") or _attr(control, "ControlType"),
    }


def _attr(control: Any, name: str) -> str:
    try:
        value = getattr(control, name)
        return "" if value is None else str(value)
    except Exception:
        return ""


def _safe_children(control: Any) -> list[Any]:
    try:
        return list(control.GetChildren())
    except Exception:
        return []


def _walk(root: Any, max_depth: int, depth: int = 0) -> list[Any]:
    if depth > max_depth:
        return []
    controls = [root]
    for child in _safe_children(root):
        controls.extend(_walk(child, max_depth=max_depth, depth=depth + 1))
    return controls


def _find_child(parent: Any, selector: dict[str, Any]) -> Any | None:
    matches = [child for child in _safe_children(parent) if _matches(child, selector)]
    index = int(selector.get("index", 0))
    if not matches or index >= len(matches):
        return None
    return matches[index]


def _find_descendant(root: Any, selector: dict[str, Any], max_depth: int = 10) -> Any | None:
    for control in _walk(root, max_depth=max_depth):
        if control is root:
            continue
        if _matches(control, selector):
            return control
    return None


def _matches(control: Any, selector: dict[str, Any]) -> bool:
    info = control_info(control)
    if selector.get("control_type"):
        expected = str(selector["control_type"]).lower()
        if expected not in info["control_type"].lower():
            return False
    if selector.get("name"):
        if info["name"] != str(selector["name"]):
            return False
    if selector.get("name_contains"):
        if str(selector["name_contains"]).lower() not in info["name"].lower():
            return False
    if selector.get("name_regex"):
        if not re.search(str(selector["name_regex"]), info["name"]):
            return False
    if selector.get("class_name"):
        if info["class_name"] != str(selector["class_name"]):
            return False
    if selector.get("class_name_contains"):
        if str(selector["class_name_contains"]).lower() not in info["class_name"].lower():
            return False
    if selector.get("automation_id"):
        if info["automation_id"] != str(selector["automation_id"]):
            return False
    return True


def _extract_text(control: Any, max_depth: int = 6) -> str:
    values: list[str] = []
    for item in _walk(control, max_depth=max_depth):
        name = _attr(item, "Name").strip()
        if name and (not values or values[-1] != name):
            values.append(name)
        value = _value_pattern_text(item).strip()
        if value and value != name and (not values or values[-1] != value):
            values.append(value)
    return "\n".join(values).strip()


def _value_pattern_text(control: Any) -> str:
    try:
        pattern = control.GetValuePattern()
        return str(pattern.Value)
    except Exception:
        return ""


def _guess_sender_and_content(text: str) -> tuple[str, str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "未知", ""
    if len(lines) == 1:
        return "未知", lines[0]
    sender = lines[0]
    content = "\n".join(lines[1:]).strip()
    return sender, content or text


def _message_item_controls(message_list: Any) -> list[Any]:
    root = _find_descendant(message_list, {"automation_id": "ml-root"}, max_depth=3)
    if root is None:
        root = message_list
    items: list[Any] = []
    for control in _walk(root, max_depth=3):
        automation_id = _attr(control, "AutomationId")
        if automation_id.isdigit() and _attr(control, "ControlTypeName").lower().startswith("group"):
            items.append(control)
    return items


def _parse_message_item(item: Any) -> tuple[str, str, str] | None:
    sender = _first_sender_name(item)
    texts = _text_control_names(item)
    if not sender and not texts:
        return None
    if not sender:
        sender = _first_non_time_text(texts) or "未知"
    content_parts = _strip_message_metadata(texts, sender)
    content = "\n".join(content_parts).strip()
    if not content:
        content = _extract_text(item)
    raw_text = "\n".join([sender, content]).strip()
    return sender, content, raw_text


def _first_sender_name(item: Any) -> str:
    ignored = {"图片", "表情", "文件"}
    for control in _walk(item, max_depth=4):
        if not _attr(control, "ControlTypeName").lower().startswith("group"):
            continue
        name = _attr(control, "Name").strip()
        if name and name not in ignored:
            return name
    return ""


def _text_control_names(item: Any) -> list[str]:
    names: list[str] = []
    for control in _walk(item, max_depth=10):
        if not _attr(control, "ControlTypeName").lower().startswith("text"):
            continue
        name = _attr(control, "Name").strip()
        if name:
            names.append(name)
    return names


def _first_non_time_text(texts: list[str]) -> str:
    for text in texts:
        if not _is_time_label(text):
            return text
    return ""


def _strip_message_metadata(texts: list[str], sender: str) -> list[str]:
    parts = list(texts)
    if parts and _is_time_label(parts[0]):
        parts.pop(0)
    if parts and parts[0] == sender:
        parts.pop(0)
    skipped_level = False
    if parts and re.fullmatch(r"LV\d+", parts[0], flags=re.IGNORECASE):
        parts.pop(0)
        skipped_level = True
    if skipped_level and len(parts) > 1:
        parts.pop(0)
    return parts


def _is_time_label(text: str) -> bool:
    return bool(re.fullmatch(r"\d{1,2}:\d{2}", text.strip()))


def _set_focus(control: Any) -> None:
    try:
        control.SetFocus()
    except Exception:
        try:
            control.Click()
        except Exception:
            pass


def _set_value(control: Any, text: str) -> bool:
    try:
        pattern = control.GetValuePattern()
        pattern.SetValue(text)
        return True
    except Exception:
        return False


def _paste_text(auto: Any, text: str) -> None:
    if not _set_clipboard_text(text):
        auto.SendKeys(text, waitTime=0.01)
        return
    _send_keys(auto, "^v", "{Ctrl}v")


def _send_keys(auto: Any, pywinauto_keys: str, uia_keys: str) -> None:
    try:
        from pywinauto.keyboard import send_keys  # type: ignore

        send_keys(pywinauto_keys)
    except Exception:
        auto.SendKeys(uia_keys, waitTime=0.01)


def _invoke(control: Any) -> None:
    try:
        control.GetInvokePattern().Invoke()
    except Exception:
        control.Click()


def _set_clipboard_text(text: str) -> bool:
    if sys.platform != "win32":
        return False
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    cf_unicode_text = 13
    gmem_moveable = 0x0002

    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]

    data = (text + "\0").encode("utf-16-le")
    handle = kernel32.GlobalAlloc(gmem_moveable, len(data))
    if not handle:
        return False
    locked = kernel32.GlobalLock(handle)
    if not locked:
        kernel32.GlobalFree(handle)
        return False
    ctypes.memmove(locked, data, len(data))
    kernel32.GlobalUnlock(handle)

    if not user32.OpenClipboard(None):
        kernel32.GlobalFree(handle)
        return False
    try:
        user32.EmptyClipboard()
        if not user32.SetClipboardData(cf_unicode_text, handle):
            kernel32.GlobalFree(handle)
            return False
        return True
    finally:
        user32.CloseClipboard()


def _enum_visible_windows() -> list[tuple[int, str, str, str]]:
    if sys.platform != "win32":
        return []

    user32 = ctypes.windll.user32
    enum_windows_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    items: list[tuple[int, str, str, str]] = []

    def callback(hwnd: int, _lparam: int) -> bool:
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        title_buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title_buffer, length + 1)
        class_buffer = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, class_buffer, 256)
        title = title_buffer.value
        class_name = class_buffer.value
        if title or class_name:
            items.append((int(hwnd), title, class_name, _process_path_for_window(int(hwnd))))
        return True

    user32.EnumWindows(enum_windows_proc(callback), 0)
    return items


def _process_path_for_window(hwnd: int) -> str:
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        pid = ctypes.c_uint32()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        process_query_limited_information = 0x1000
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid.value)
        if not handle:
            return ""
        try:
            size = ctypes.c_uint32(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
            return buffer.value
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return ""


def _looks_like_qq_process(process_path: str) -> bool:
    lowered = process_path.lower()
    return lowered.endswith("\\qq.exe") or lowered.endswith("\\qqnt.exe") or "\\qq\\" in lowered


def _window_id(title: str, class_name: str, hwnd: int | None = None) -> str:
    return hashlib.sha1(f"{title}|{class_name}|{hwnd or ''}".encode("utf-8", errors="ignore")).hexdigest()[:12]

import unittest
from datetime import datetime

from safebot.models import ChatMessage
from safebot.ui.uia_adapter import _contains_rich_card, _control_strings_for_url_search, _window_id


class FakeValuePattern:
    def __init__(self, value=""):
        self.Value = value


class FakeLegacyPattern:
    def __init__(self, name="", value="", description=""):
        self.Name = name
        self.Value = value
        self.Description = description


class FakeControl:
    def __init__(self, *, name="", automation_id="", help_text="", value="", legacy=None, children=None):
        self.Name = name
        self.AutomationId = automation_id
        self.HelpText = help_text
        self.Value = value
        self._legacy = legacy
        self._children = children or []

    def GetChildren(self):
        return self._children

    def GetValuePattern(self):
        return FakeValuePattern(self.Value)

    def GetLegacyIAccessiblePattern(self):
        if self._legacy is None:
            raise RuntimeError("no legacy pattern")
        return self._legacy


class UIAAdapterUrlExtractionTest(unittest.TestCase):
    def test_control_strings_include_nested_attribute_urls(self):
        root = FakeControl(
            children=[
                FakeControl(help_text="open https://example.com/card"),
                FakeControl(legacy=FakeLegacyPattern(description="https://legacy.example/path")),
            ]
        )
        values = _control_strings_for_url_search(root)
        self.assertIn("open https://example.com/card", values)
        self.assertIn("https://legacy.example/path", values)

    def test_rich_card_detection(self):
        card = FakeControl(
            children=[
                FakeControl(name="\u5361\u7247", automation_id="ark-msg-content-container_123"),
                FakeControl(automation_id="com_tencent_tuwen_lua_qqconnect_sdkshare_1"),
            ]
        )
        self.assertTrue(_contains_rich_card(card))

    def test_chat_message_can_hold_source_control(self):
        message = ChatMessage(
            window_id="w",
            group_name="g",
            sender="s",
            content="c",
            observed_at=datetime.now(),
            source_control=FakeControl(),
        )
        self.assertIsNotNone(message.source_control)

    def test_window_id_prefers_stable_hwnd(self):
        self.assertEqual(
            _window_id("old title", "Chrome_WidgetWin_1", 123),
            _window_id("new title", "Chrome_WidgetWin_1", 123),
        )
        self.assertNotEqual(
            _window_id("old title", "Chrome_WidgetWin_1", 123),
            _window_id("old title", "Chrome_WidgetWin_1", 456),
        )


if __name__ == "__main__":
    unittest.main()

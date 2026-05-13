import unittest
from types import SimpleNamespace

from safebot.bot import _already_seen, _is_monitorable_chat_window
from safebot.models import ChatMessage
from safebot.ui.uia_adapter import QQWindow


class BotWindowMonitoringTest(unittest.TestCase):
    def test_main_qq_window_is_excluded(self):
        self.assertFalse(_is_monitorable_chat_window(QQWindow(None, "QQ", "Chrome_WidgetWin_1", "main")))
        self.assertTrue(_is_monitorable_chat_window(QQWindow(None, "测试群", "Chrome_WidgetWin_1", "chat")))

    def test_seen_key_includes_window_id(self):
        runtime = SimpleNamespace(seen_messages=set())
        first = ChatMessage("w1", "g1", "alice", "same", raw_id="same-hash")
        second = ChatMessage("w2", "g2", "bob", "same", raw_id="same-hash")

        self.assertFalse(_already_seen(runtime, first))
        self.assertFalse(_already_seen(runtime, second))
        self.assertTrue(_already_seen(runtime, first))


if __name__ == "__main__":
    unittest.main()

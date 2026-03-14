
import time
import unittest

from src.core.events import get_event_bus


class TestEventPublishing(unittest.TestCase):
    def test_sync_handler_called(self) -> None:
        bus = get_event_bus()
        received = []

        def handler(name: str, payload) -> None:
            received.append((name, payload))

        bus.subscribe("TestSyncEvent", handler)
        bus.publish("TestSyncEvent", {"x": 1})

        self.assertTrue(received)
        self.assertEqual(received[0][0], "TestSyncEvent")

    def test_async_handler_called(self) -> None:
        bus = get_event_bus()
        received = []

        def handler(name: str, payload) -> None:
            received.append((name, payload))

        bus.subscribe("TestAsyncEvent", handler, async_handler=True)
        bus.publish("TestAsyncEvent", {"y": 2})

        # ждём немного, чтобы фоновой поток успел обработать событие
        time.sleep(0.2)
        self.assertTrue(received)
        self.assertEqual(received[0][0], "TestAsyncEvent")


if __name__ == "__main__":
    unittest.main()

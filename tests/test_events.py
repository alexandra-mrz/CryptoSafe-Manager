import os
import sys
import unittest
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from src.core.events import EventBus, get_event_bus, ENTRY_ADDED, USER_LOGGED_IN

class TestEvents(unittest.TestCase):
    def test_publish_subscribe(self):
        bus = EventBus()
        received = []
        def handler(entry_id=None, **kwargs):
            received.append(entry_id)
        bus.subscribe(ENTRY_ADDED, handler)
        bus.publish(ENTRY_ADDED, entry_id=42)
        self.assertEqual(received, [42])
    def test_get_event_bus_singleton(self):
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        self.assertIs(bus1, bus2)

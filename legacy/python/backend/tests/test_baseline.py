import time
import unittest

from backend.engine import Engine
from backend.storage import Store
from backend.tests.test_protocols import HMI_MAC, PLC_MAC, mbap, tcp

READ_HR = mbap(1, b"\x03\x00\x00\x00\x02")
WRITE_REG = mbap(1, b"\x06\x00\x10\x00\x01")
UMAS_STOP = mbap(0, b"\x5a\x00\x41")


def feed(engine: Engine, *frames: bytes, start: int = 1_700_000_000) -> None:
    for i, frame in enumerate(frames):
        engine.process_raw(frame, start + i)


def baseline_alerts(engine: Engine) -> list[dict]:
    return [a for a in engine.snapshot()["alerts"] if a["source"] == "baseline"]


class BaselineTests(unittest.TestCase):
    def learned_engine(self, store=None) -> Engine:
        engine = Engine(store)
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, READ_HR))
        engine.set_mode("detecting")
        return engine

    def test_learning_mode_raises_no_baseline_alerts(self):
        engine = Engine()
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, READ_HR),
             tcp("10.0.0.21", "10.0.0.10", 50000, 502, WRITE_REG))
        self.assertEqual(baseline_alerts(engine), [])
        counts = engine.snapshot()["baseline"]["counts"]
        self.assertEqual(counts, {"asset": 3, "link": 2, "op": 2})

    def test_known_behaviour_is_silent_in_detection(self):
        engine = self.learned_engine()
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, READ_HR))
        self.assertEqual(baseline_alerts(engine), [])

    def test_new_operation_on_known_link(self):
        engine = self.learned_engine()
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, WRITE_REG))
        alerts = baseline_alerts(engine)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "새로운 명령: Modbus/TCP Write Single Register")
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertEqual(alerts[0]["baseline"]["kind"], "op")

    def test_responses_do_not_create_operation_alerts(self):
        engine = self.learned_engine()
        feed(engine, tcp("10.0.0.10", "10.0.0.20", 502, 50000, mbap(1, b"\x06\x00\x10\x00\x01"),
                         src_mac=PLC_MAC, dst_mac=HMI_MAC))
        self.assertEqual(baseline_alerts(engine), [])

    def test_new_asset_and_new_link(self):
        engine = self.learned_engine()
        feed(engine, tcp("10.0.0.66", "10.0.0.10", 50000, 502, READ_HR, src_mac="00:0c:29:00:00:66"))
        titles = {a["title"]: a for a in baseline_alerts(engine)}
        self.assertIn("신규 자산 발견", titles)
        self.assertEqual(titles["새로운 통신: Modbus/TCP"]["severity"], "high")
        # Operations on a link that is itself unapproved are not reported separately.
        self.assertEqual(len(titles), 2)

    def test_policy_alert_suppresses_duplicate_new_operation_alert(self):
        engine = self.learned_engine()
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, UMAS_STOP))
        snap = engine.snapshot()
        self.assertEqual([a["source"] for a in snap["alerts"]], ["policy"])

    def test_learn_alert_adds_to_baseline(self):
        engine = self.learned_engine()
        frame = tcp("10.0.0.20", "10.0.0.10", 50000, 502, WRITE_REG)
        feed(engine, frame)
        alert = baseline_alerts(engine)[0]
        self.assertTrue(engine.learn_alert(alert["id"]))
        feed(engine, frame, start=1_700_000_100)
        alert = baseline_alerts(engine)[0]
        self.assertEqual((alert["status"], alert["count"]), ("acknowledged", 1))

    def test_learning_new_link_also_learns_its_operations(self):
        engine = self.learned_engine()
        new_link = tcp("10.0.0.20", "10.0.0.11", 50000, 502, WRITE_REG, dst_mac="00:1b:1b:00:00:11")
        feed(engine, new_link)
        link_alert = next(a for a in baseline_alerts(engine) if a["baseline"]["kind"] == "link")
        engine.learn_alert(link_alert["id"])
        feed(engine, new_link, start=1_700_000_100)
        self.assertFalse(any(a["baseline"]["kind"] == "op" for a in baseline_alerts(engine)))

    def test_learning_window_expires_into_detection(self):
        engine = Engine()
        engine.set_mode("learning", hours=1)
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, READ_HR))
        engine.baseline.learning_until = time.time() - 1  # window elapsed
        feed(engine, tcp("10.0.0.20", "10.0.0.10", 50000, 502, WRITE_REG))
        self.assertEqual(engine.snapshot()["baseline"]["mode"], "detecting")
        self.assertEqual(len(baseline_alerts(engine)), 1)

    def test_reset_relearns(self):
        engine = self.learned_engine()
        engine.set_mode("learning", reset=True)
        self.assertEqual(engine.snapshot()["baseline"]["counts"], {"asset": 0, "link": 0, "op": 0})
        engine.set_mode("detecting")  # seeds from current inventory
        self.assertEqual(engine.snapshot()["baseline"]["counts"]["link"], 1)

    def test_baseline_and_mode_persist(self):
        store = Store(":memory:")
        engine = self.learned_engine(store)
        engine.flush()
        restored = Engine(store)
        self.assertEqual(restored.snapshot()["baseline"]["mode"], "detecting")
        feed(restored, tcp("10.0.0.20", "10.0.0.10", 50000, 502, READ_HR))
        feed(restored, tcp("10.0.0.20", "10.0.0.10", 50000, 502, WRITE_REG))
        self.assertEqual(len(baseline_alerts(restored)), 1)


if __name__ == "__main__":
    unittest.main()

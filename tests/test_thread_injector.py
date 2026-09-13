"""Unit tests for thread_injector.py."""

from __future__ import annotations

from karst.harness.guards.thread_injector import ThreadInjector


class TestDataRetrievalTrigger:
    def test_suricata_query_triggers_guidance(self):
        injector = ThreadInjector(max_iterations=15)

        msgs = injector.check(
            iteration=0,
            had_tool_calls=True,
            sql="SELECT * FROM suricata WHERE severity = 1",
        )

        assert len(msgs) == 1
        assert "HARNESS NOTE" in msgs[0]
        assert "Suricata" in msgs[0]
        assert "correlate" in msgs[0].lower() or "conn" in msgs[0].lower()

    def test_conn_query_triggers_guidance(self):
        injector = ThreadInjector(max_iterations=15)

        msgs = injector.check(
            iteration=1,
            had_tool_calls=True,
            sql="SELECT src_ip, dst_ip FROM conn LIMIT 10",
        )

        assert len(msgs) == 1
        assert "HARNESS NOTE" in msgs[0]

    def test_unknown_table_no_guidance(self):
        injector = ThreadInjector(max_iterations=15)

        msgs = injector.check(
            iteration=0,
            had_tool_calls=True,
            sql="SELECT * FROM some_random_table",
        )

        assert len(msgs) == 0


class TestNoDuplicateInjection:
    def test_second_query_same_table_no_inject(self):
        injector = ThreadInjector(max_iterations=15)

        msgs1 = injector.check(
            iteration=0,
            had_tool_calls=True,
            sql="SELECT * FROM suricata",
        )
        msgs2 = injector.check(
            iteration=1,
            had_tool_calls=True,
            sql="SELECT * FROM suricata WHERE severity > 2",
        )

        assert len(msgs1) == 1
        assert len(msgs2) == 0


class TestIterationUrgency:
    def test_triggers_at_threshold(self):
        injector = ThreadInjector(max_iterations=15, urgency_threshold=0.75)

        msgs = injector.check(
            iteration=11,  # 11 >= 15 * 0.75 = 11.25 -> int = 11
            had_tool_calls=True,
            sql="SELECT * FROM conn",
        )

        urgency_msgs = [m for m in msgs if "iterations" in m.lower()]
        assert len(urgency_msgs) == 1
        assert "12 of 15" in urgency_msgs[0]  # iteration+1 display

    def test_no_trigger_before_threshold(self):
        injector = ThreadInjector(max_iterations=15, urgency_threshold=0.75)

        msgs = injector.check(
            iteration=5,
            had_tool_calls=True,
        )

        urgency_msgs = [m for m in msgs if "iterations" in m.lower()]
        assert len(urgency_msgs) == 0

    def test_only_triggers_once(self):
        injector = ThreadInjector(max_iterations=15, urgency_threshold=0.75)

        msgs1 = injector.check(iteration=11, had_tool_calls=True)
        msgs2 = injector.check(iteration=12, had_tool_calls=True)

        urgency1 = [m for m in msgs1 if "iterations" in m.lower()]
        urgency2 = [m for m in msgs2 if "iterations" in m.lower()]

        assert len(urgency1) == 1
        assert len(urgency2) == 0


class TestNoToolCallNudge:
    def test_nudge_on_non_final_iteration(self):
        injector = ThreadInjector(max_iterations=15)

        msgs = injector.check(
            iteration=3,
            had_tool_calls=False,
        )

        assert len(msgs) == 1
        assert "still use your tools" in msgs[0]

    def test_no_nudge_on_final_iteration(self):
        injector = ThreadInjector(max_iterations=15)

        msgs = injector.check(
            iteration=14,  # last iteration (0-based)
            had_tool_calls=False,
        )

        nudge_msgs = [m for m in msgs if "still use your tools" in m]
        assert len(nudge_msgs) == 0

    def test_no_nudge_when_tools_used(self):
        injector = ThreadInjector(max_iterations=15)

        msgs = injector.check(
            iteration=3,
            had_tool_calls=True,
        )

        nudge_msgs = [m for m in msgs if "still use your tools" in m]
        assert len(nudge_msgs) == 0


class TestCustomTableGuidance:
    def test_custom_guidance_used(self):
        injector = ThreadInjector(
            max_iterations=15,
            table_guidance={"custom_table": "Check the custom data."},
        )

        msgs = injector.check(
            iteration=0,
            had_tool_calls=True,
            sql="SELECT * FROM custom_table",
        )

        assert len(msgs) == 1
        assert "Check the custom data" in msgs[0]


class TestInjectionEvents:
    def test_events_recorded(self):
        injector = ThreadInjector(max_iterations=15)

        injector.check(
            iteration=0,
            had_tool_calls=True,
            sql="SELECT * FROM suricata",
        )

        events = injector.events
        assert len(events) == 1
        assert events[0].trigger == "data_retrieval"
        assert events[0].table == "suricata"
        assert events[0].iteration == 0

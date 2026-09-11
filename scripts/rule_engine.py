"""A minimal streaming rule engine, built to test premise P1.

The question is whether a time-window rule's verdict depends on the order events
arrive in, not merely on which events arrive. A batch engine that holds every
event and evaluates at the end is order independent by construction, but no
streaming system can do that: state has to be released or memory grows without
bound.

Release follows the watermark model used by production stream processors: the
watermark is the greatest timestamp seen so far, a window is retired once the
watermark passes its end plus a grace period, and an event arriving after that is
dropped. Raising the grace period buys tolerance of out-of-order arrival at the
cost of detection delay, which is the trade-off the mitigation study varies.

The rule shape - N events sharing a key inside a T-second window - is the most
common form of threshold rule in operations.
"""
from collections import deque


class SlidingWindowRule:
    """Fires when `threshold` events sharing `key_field` fall inside `window_seconds`.

    Events are fed in arrival order. Window membership is decided on event
    timestamps, but retirement is driven by the watermark, so the two disagree
    whenever arrival order departs from occurrence order.
    """

    def __init__(self, name, key_field, window_seconds, threshold, allowed_lateness=0.0):
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if allowed_lateness < 0:
            raise ValueError("allowed_lateness must not be negative")
        self.name = name
        self.key_field = key_field
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.allowed_lateness = allowed_lateness

        self.watermark = None
        self.pending = {}
        self.alerts = []
        self.dropped_late = 0
        self.accepted = 0

    def _deadline(self):
        """Timestamps at or below this belong to windows already retired."""
        return self.watermark - self.window_seconds - self.allowed_lateness

    def _retire(self):
        horizon = self._deadline()
        for key in [k for k, times in self.pending.items() if not times or times[-1] < horizon]:
            del self.pending[key]

    def process(self, event_time, event):
        """Feed one event in arrival order. Returns an alert dict or None."""
        key = event.get(self.key_field)
        if key is None:
            return None

        if self.watermark is not None and event_time < self._deadline():
            self.dropped_late += 1
            return None

        self.accepted += 1
        if self.watermark is None or event_time > self.watermark:
            self.watermark = event_time
        self._retire()

        times = self.pending.setdefault(key, deque())
        times.append(event_time)
        # Accepted events are within the grace period of the watermark, so the
        # deque stays close enough to sorted for a prefix trim to be correct.
        while times and times[0] < event_time - self.window_seconds:
            times.popleft()

        if len(times) >= self.threshold:
            alert = {
                "rule": self.name,
                "key": key,
                "count": len(times),
                "window_start": min(times),
                "window_end": max(times),
            }
            self.alerts.append(alert)
            times.clear()
            return alert
        return None


def run_rule(rule, stream):
    """Feed an ordered stream of (event_time, event) pairs through a rule."""
    for event_time, event in stream:
        rule.process(event_time, event)
    return {
        "rule": rule.name,
        "alerts": len(rule.alerts),
        "alert_keys": sorted({a["key"] for a in rule.alerts}),
        "accepted": rule.accepted,
        "dropped_late": rule.dropped_late,
    }

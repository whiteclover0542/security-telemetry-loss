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

Engine version 2 keeps each key's timestamps sorted and fires when some
T-second span containing the new event holds N events. Version 1 assumed the
per-key deque stayed in arrival order: an accepted late event appended at the
tail made the key look idle, so retirement wiped live state. That fired only
when a delay equalled the window almost exactly, and it inflated every
out-of-order result measured with it. With version 2 the only way arrival
order changes a verdict is the watermark drop, plus which events a firing
clears.
"""
import bisect

ENGINE_VERSION = 2
RETIRE_EVERY = 256


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

    def _useless_before(self):
        # Every future accepted event is at or after the deadline, and any span
        # containing it starts no earlier than one window before that.
        return self._deadline() - self.window_seconds

    def _retire(self):
        cutoff = self._useless_before()
        for key in [k for k, times in self.pending.items() if not times or times[-1] < cutoff]:
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
        if self.accepted % RETIRE_EVERY == 0:
            self._retire()

        window = self.window_seconds
        times = self.pending.setdefault(key, [])
        stale = bisect.bisect_left(times, self._useless_before())
        if stale:
            del times[:stale]

        if not times or event_time >= times[-1]:
            times.append(event_time)
            first = bisect.bisect_left(times, event_time - window)
            count, start, end = len(times) - first, times[first], event_time
        else:
            pos = bisect.bisect_right(times, event_time)
            times.insert(pos, event_time)
            count = start = end = 0
            for i in range(bisect.bisect_left(times, event_time - window), pos + 1):
                last = bisect.bisect_right(times, times[i] + window) - 1
                if last >= pos and last - i + 1 > count:
                    count, start, end = last - i + 1, times[i], times[last]

        if count >= self.threshold:
            alert = {
                "rule": self.name,
                "key": key,
                "count": count,
                "window_start": start,
                "window_end": end,
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

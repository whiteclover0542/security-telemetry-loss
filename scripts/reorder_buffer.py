"""A bounded reorder buffer, the mitigation for arrival-order distortion.

It acts before the rule sees the stream: events are held and released in
occurrence-time order, the way a log pipeline's sort buffer does.

A buffer at least as large as the worst delay restores occurrence order exactly,
so evasion is fully blocked. Release is evaluated only when an event arrives and
the remainder is flushed at end of stream; there is no timer. An undelayed event
waits `buffer_seconds` plus the gap until the next arrival, except events flushed
at end of stream, which wait less; on a sparse stream the real delay can exceed
the buffer size by up to the longest inter-arrival gap.

Input is (arrival_time, occurrence_time, event) in arrival order. Output is
(occurrence_time, event) in release order.
"""
import heapq


def reorder(stream, buffer_seconds):
    """Release events in occurrence order within a bounded arrival horizon.

    On each arrival at time A, every held event whose occurrence time is at most
    A - buffer_seconds is released, smallest occurrence first; the rest are
    released at end of stream. A delayed event rejoins its neighbours as long as
    they are still held when it arrives.
    """
    if buffer_seconds < 0:
        raise ValueError("buffer_seconds must not be negative")
    held = []  # heap of (occurrence_time, seq, event)
    seq = 0
    released = []
    for arrival, occurrence, event in stream:
        heapq.heappush(held, (occurrence, seq, event))
        seq += 1
        # Release anything whose occurrence is old enough that no future arrival
        # within the horizon could still precede it.
        while held and held[0][0] <= arrival - buffer_seconds:
            occ, _, ev = heapq.heappop(held)
            released.append((occ, ev))
    while held:
        occ, _, ev = heapq.heappop(held)
        released.append((occ, ev))
    return released


def perfectly_ordered(released):
    """True if the released stream is non-decreasing in occurrence time."""
    times = [t for t, _ in released]
    return times == sorted(times)

"""A bounded reorder buffer, the mitigation for arrival-order distortion.

An in-engine grace period cannot help here: a delayed event arrives carrying a
late arrival time, pushes the watermark forward, and the window its occurrence
belonged to is already retired. The fix has to act before the rule sees the
stream - hold each event for a bounded time and release events in occurrence-time
order, the way a log pipeline's sort buffer does.

The trade-off is direct. A buffer at least as large as the worst delay restores
the original occurrence order exactly, so evasion is fully blocked; but every
detection is held back by the buffer horizon. Smaller buffers cost less latency
and block less evasion. The sweep measures both ends.

Input is (arrival_time, occurrence_time, event) in arrival order. Output is
(occurrence_time, event) released in occurrence order among events whose arrival
is within `buffer_seconds` of each other, matching what a real buffer can sort.
"""
import heapq


def reorder(stream, buffer_seconds):
    """Release events in occurrence order within a bounded arrival horizon.

    An event that arrived at A is released once the buffer has seen an arrival at
    A + buffer_seconds, or at end of stream. Among all events still held, the one
    with the smallest occurrence time is released first, so a delayed event whose
    occurrence is old rejoins its neighbours as long as it arrived within the
    horizon of them.
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

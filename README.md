# Ordering Distortion in Asynchronous Log Pipelines

**Can an attacker evade time-window detection rules without deleting a single log line?**

Detection rules in security operations lean heavily on time windows: ten failed
logins followed by a success within five minutes, one account seen in two regions
within a minute, a burst of file access. Such rules quietly assume events arrive
in the order they occurred.

Real pipelines do not guarantee that. Events pass through agent buffers,
collector batching, message queues, retries and backpressure, and each leg delays
them by a different amount. Arrival order and occurrence order diverge. In
practice this is treated as "a bit of lag" and rarely enters rule design.

This study asks whether that gap is exploitable. If an attacker can induce delay
at a chosen point in the pipeline, their events may land outside the rule's
window while every log line still arrives intact: integrity checks pass, volume
monitoring sees nothing missing, and no deletion is recorded.

## Status

Design stage. The hypothesis rests on four premises, and the most load-bearing
one — that rule verdicts actually depend on arrival order — is being measured
first with a minimal implementation. Nothing is built on top of it until that
holds. No results yet.

## Documents

| Document | Contents |
| --- | --- |
| [Assignment requirements](docs/ASSIGNMENT.md) | Original brief; not edited after creation |
| [Topic selection](docs/TOPIC_SELECTION.md) | Candidates considered and why each was dropped |
| [Research progress](docs/PROGRESS.md) | Current status and open work |
| [Research foundation](research/RESEARCH_FOUNDATION.md) | Hypothesis, premises to verify, measurement plan |

## Preliminary study

An earlier topic — how the temporal structure of telemetry loss affects attack
detection — was taken as far as data collection, environment setup and
measurement before being dropped. It is preserved under
[preliminary/](preliminary/) together with the measurements that justified
dropping it: detector replay was ruled out after timing four training epochs, and
the fallback measurement produced results derivable without an experiment.

Its inputs carry over. The OpTC host logs (65,872,086 events, independently
verified) and the malicious event labels are the evaluation corpus for this
study as well.

## Reproducing the checks

```powershell
python -m unittest discover -s tests -v
```

Large inputs are not in this repository. The byte-range index and download
manifests under `data/` are, so a selected member can be retrieved and verified
again.

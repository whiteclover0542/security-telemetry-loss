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

Complete. The paper is [paper/PAPER.md](paper/PAPER.md) (Korean). Its results
come from 82,890 runs on rule engine v2 under a pre-registration committed before
they ran.

In short: where the detector stamps events with ingest time, delay silently
displaces events between windows and loses detected subjects with no trace.
Where the sensor's event time is preserved, every delay that removed a subject
also left late-drop records, though a targeted delay left as few as eight, and a
reorder buffer undoes delays it covers. An earlier engine bug had inflated some effects about tenfold; the paper
reports what it invalidated.

## Documents

| Document | Contents |
| --- | --- |
| [Paper](paper/PAPER.md) | Full paper, including the correction record (section VII-4) |
| [v2 results](research/V2_RESULTS.md) | Verdict on every pre-registered hypothesis |
| [Pre-registration v2](research/PREREGISTRATION_V2.md) | Experiments, hypotheses and decision rules, fixed before running |
| [Assignment requirements](docs/ASSIGNMENT.md) | Original brief; not edited after creation |
| [Topic selection](docs/TOPIC_SELECTION.md) | Candidates considered and why each was dropped |
| [Research progress](docs/PROGRESS.md) | Work log, verification passes and checklist |
| [Research foundation](research/RESEARCH_FOUNDATION.md) | Hypothesis, premises, and the P1/P2 checks |

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
python scripts/analyze_v2.py --output analysis_check.json   # re-judge the stored v2 results
```

The full sweep commands are in the paper's reproduction section.

Large inputs are not in this repository. The byte-range index and download
manifests under `data/` are, so a selected member can be retrieved and verified
again.

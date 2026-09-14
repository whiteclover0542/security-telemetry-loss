# Event Time or Ingest Time: How Telemetry Delay Changes What Time-Window Detection Misses and the Trace It Leaves

**Can an attacker evade time-window detection rules without deleting a single log line?**

Detection rules in security operations lean heavily on time windows: a hundred
new connections from one process within a minute, a burst of file reads and
writes, repeated remote thread creation. Such rules quietly assume events arrive
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

Complete. The paper is [paper/PAPER.md](paper/PAPER.md) (Korean), typeset with
its figures as [paper/PAPER.pdf](paper/PAPER.pdf). A visual summary of the study,
with an interactive example of the two engine configurations, is
[docs/overview.html](docs/overview.html); open it in a browser. The results come
from 82,890 runs on rule engine v2 under a pre-registration committed before
they ran.

In short: where the detector stamps events with ingest time, delay silently
displaces events between windows and loses detected subjects without any
late-drop record (other pipeline signals were not measured).
Where the sensor's event time is preserved, every delay that removed a subject
also left late-drop records, though a targeted delay left as few as eight, and a
reorder buffer undoes delays it covers. An earlier engine bug had inflated some effects about tenfold; the paper
reports what it invalidated.

## Documents

| Document | Contents |
| --- | --- |
| [Paper](paper/PAPER.md) | Full paper, including the correction record (section VII-4) |
| [Paper PDF](paper/PAPER.pdf) | The same paper typeset on A4 with three figures |
| [Visual summary](docs/overview.html) | One-page overview: key results as charts, the correction timeline, hypothesis verdicts |
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

The figures and the PDF are generated from the stored v2 results and the
Markdown source. The PDF step needs `markdown-it-py` and a local Chrome or Edge.

```powershell
python paper/make_figures.py   # paper/figures/*.svg from data/p1/v2
python paper/build_pdf.py      # paper/PAPER.md -> paper/PAPER.pdf
```

Large inputs are not in this repository. The byte-range index and download
manifests under `data/` are, so a selected member can be retrieved and verified
again.

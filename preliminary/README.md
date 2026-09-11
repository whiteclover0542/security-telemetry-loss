# Preliminary study — temporal structure of telemetry loss

This directory holds a topic that was taken as far as data collection,
environment setup and measurement before being dropped on 2026-09-11. It is kept
because the reasons for dropping it were established by measurement rather than
argument, and because those measurements are themselves evidence for the topic
selection recorded in [docs/TOPIC_SELECTION.md](../docs/TOPIC_SELECTION.md).

## What it asked

At an equal additional loss rate and an equal number of deleted events, does
temporally contiguous loss reduce attack detection more than uniform random loss?
The hypothesis was later revised, before any result was seen, from a difference
in means to a difference in variance: contiguous loss is not reliably worse, it
is less predictable.

## Why it was dropped

**Detector replay proved infeasible on this hardware.** Preparing one condition
costs 41m45s and twelve training epochs take a further 3h30m–4h30m, putting the
full design near 105 days and the most reduced form near 9 days. A run was taken
to four epochs and was killed by memory exhaustion at 19.5GiB.

**The fallback measurement produced a derivable result.** Measuring evidence loss
without the detector worked and supported the revised hypothesis in all 36
conditions, but the finding follows from the sampling process itself: uniform
removal takes a fixed share with small variance, a contiguous block takes
whatever it happens to overlap. Little was learned that a reader could not
derive.

## Where things are

| Path | Contents |
| --- | --- |
| `research/` | Foundation, literature review, design, analysis plan, results |
| `scripts/` | Loss masks, mask application, evidence loss, aggregation, scoring |
| `tests/` | Unit tests for the above |
| `config/` | Frozen study inputs and the run record contract |
| `data/` | Label position index and the 7,200 per-seed measurements |

Inputs under `../data/` are shared with the current study and stay there.

## Running its checks

```powershell
cd preliminary
python -m unittest discover -s tests -v
```

One test is skipped unless the label repository is checked out under
`../external/`, which is excluded from version control.

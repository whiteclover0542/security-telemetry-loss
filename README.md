# Security Telemetry Loss

**Security Telemetry Loss: Impact on Attack Detection and Reconstruction**

This research studies how the timing and type of missing security events affect attack detection, attack reconstruction, and the recovery of detector state.

## Research questions

- Do different event-loss patterns cause different detection failures at the same overall loss rate?
- Can incomplete detector state continue to affect results after event collection returns to normal?
- Which state-recovery methods restore useful detection context, and what historical evidence cannot be recovered?
- How can a monitoring system report insufficient evidence for specific detection rules?

## Status

Topic, primary hypothesis, and literature review completed. The experiment design, the analysis plan and the tooling are fixed; the detector runner is not written and no replay has been executed. Two of the twelve normal-day inputs are downloaded and verified; the three attack-host inputs are not. The questions above are research proposals, not established findings or claims of novelty.

Every metric, threshold and reduction rule is recorded before results exist, so that nothing in the analysis can be chosen to fit an outcome.

## Project documents

| Document | Contents |
| --- | --- |
| [Assignment requirements](docs/ASSIGNMENT.md) | Original brief; not edited after creation |
| [Research progress](docs/PROGRESS.md) | Current status, completed work, open blockers |
| [Research foundation](docs/RESEARCH_FOUNDATION.md) | Research questions, candidate hypotheses, final hypothesis, measurement plan |
| [Literature review](research/LITERATURE_REVIEW.md) | Prior work, what is already known, what this study claims |
| [Experiment design](research/EXPERIMENT_DESIGN.md) | Conditions, execution budget, reduction rule, change log |
| [Analysis plan](research/ANALYSIS_PLAN.md) | Effect definitions and the metric decision order, fixed before results |
| [Detector selection](research/DETECTOR_SELECTION.md) | Detector choice, frozen thresholds, stop conditions |
| [Runbook](research/RUNBOOK.md) | Step-by-step execution procedure |
| [Results template](research/RESULTS_TEMPLATE.md) | Empty recording format for baseline and loss runs |
| [Data access](research/DATA_ACCESS.md) | Source verification and download records |
| [Correction and label review](research/LABEL_AND_CORRECTION_REVIEW.md) | Inria correction and labelling code review |
| [Study inputs](config/study_inputs.json) · [Run record contract](config/run_record_schema.json) | Frozen inputs, metrics and per-run field contract |

## Reproducing the checks

```powershell
python -m unittest discover -s tests -v
```

Large inputs are not in this repository. The byte-range index and download manifests under `data/` are, so a selected member can be retrieved and verified again. The paper and the reproduction package will be added as the research progresses.

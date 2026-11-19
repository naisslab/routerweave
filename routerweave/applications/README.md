# Routerweave case studies

This module turns activity predictions into two application outputs. Screen Time publishes device activity intervals and evaluates their durations and switches. Appliance energy estimation reconstructs appliance states from directional operations and integrates a power profile over those states.

## Run the examples

Use Python 3.12 and NumPy 2.3.5. From this directory, create an environment with `python -m venv .venv`. Activate it with `.venv\Scripts\Activate.ps1` in PowerShell or `. .venv/bin/activate` in a POSIX shell, then run:

```sh
python -m pip install -r requirements.txt
python -B -m case_studies screen-time examples/synthetic_screen_time.json --details
python -B -m case_studies appliance-energy examples/synthetic_fan_energy.json
```

Both commands read the named UTF-8 JSON file and print JSON to standard output. All times are in seconds on a common clock within a timeline. Intervals include their start and exclude their end.

The examples are synthetic, with hand-specified predictions. In the short Screen Time example, the reference switches at 75 s and the immediate record reports the switch at 85 s. The matched delay is 10 s and the immediate label is correct for 25 of the 30 scored seconds.

## Screen Time

### Input and publication

The input contains a `timelines` array. Each entry has a unique `id`, a `platform`, a `profile`, a `layout`, and `predictions`. Use `variable_fast`, `variable_medium`, or `variable_slow` for the randomized dwell profiles, or `real_guided` for a user-timed layout. Each layout starts with a 60 s segment marked `warmup: true`; subsequent segments cover the timeline without overlap. A null label marks an unknown reference interval. Randomized study inputs require complete reference annotations.

Supply predictions for every 5 s slot after warm-up. The first slot ends at 65 s. Round the final slot end up to the grid; displayed intervals are clipped to the actual recording end. Class order is background, browsing, live_stream, long_video, music, short_video.

| Prediction field | Shape | Meaning |
|---|---|---|
| ends | N | Observation-end times |
| experts | N × 3 × 6 | Class probabilities at 5, 10 and 30 s scales |
| available | N × 3 | Availability flags for the three scales |
| immediate_probabilities | N × 6 | Causal GRU probabilities at the observation end |
| delayed_probabilities | N × 6 | Transport-corrected delayed probabilities aligned with the **target** slot |

The immediate winner is published at the observation end. For each pending slot, the replay checks for confirmation at ages 0, 5 and 10 s. All three scales must be available, agree with the current immediate winner, and that winner must equal the preceding winner and the target slot's original guess. At 15 s an unresolved slot uses its delayed winner. Records publish in interval order, so an earlier pending slot can hold back a later confirmed one. Labels and publication clocks are computed without reference labels. These are replay times; capture, model inference and transport latency are outside the clock.

### Constructing timelines

`case_studies.activity_timeline` also exposes the workload constructors. Supply one platform's ordered pool of `Recording(source_id, label, intervals, app)` objects, with eligible time ranges in the source recording's clock. For example, this creates a synthetic source pool and draws a layout:

```python
from case_studies.activity_timeline import LABELS, Recording, random_timeline

pool = [Recording(label, label, ((0, 3600),), label) for label in LABELS]
layout = random_timeline(seed=7, profile="fast", sources=pool)
```

Randomized layouts span 15–30 minutes after warm-up. Dwell ranges are 10–30, 30–90 and 120–300 s. Source crops within a timeline are disjoint. The seed offsets preserve the original random streams for mixture weights, dwell lengths, and crop selection. For user-timed layouts, `guided_timeline(template, sources)` takes a selected template with `trace_id`, `elapsed_s`, `segments` (start_s, end_s, synthetic_activity) and `gaps` (start_s, end_s). Timing comes from the template and traffic from same-category recordings.

`replay_packets(layout, recordings)` takes a mapping from source ID to a time-sorted sequence of (source time, flow ID, metadata) rows. It repositions cropped packets and assigns a separate flow namespace to each excerpt; warm-up and its continuation share one namespace. Supply service metadata already associated in the source recording, including associations established before a crop. This interface operates on packet metadata in memory. To run the original recognition experiment from captures requires the upstream features, fitted classifier and temporal heads. The examples start with their output contract.

### Outputs and scoring

| Output | Population and calculation |
|---|---|
| retrospective | All supplied timelines, using delayed records. Accuracy pools seconds. Temporal IoU averages over classes with nonempty union in each timeline, then equally over timelines. Active-duration MAE is the mean absolute error in total foreground seconds per timeline. |
| by_platform | Delayed accuracy and temporal IoU for each platform, across both cohorts |
| by_activity_duration | The same measures for each randomized dwell profile |
| live_monitoring | Randomized timelines, using immediate records. Includes time accuracy, reference/published/matched switch counts, precision, recall and mean matched delay. An undefined ratio or mean is null; a guided-only input has no live summary. |
| timelines | With `--details`, both publication histories, merged intervals, per-class durations, confusion seconds (reference rows, prediction columns), switch counts and individual matched delays |

Durations accumulate all published intervals in coverage. Accuracy and duration error use only annotated time after warm-up. A switch matches once when old and new labels agree, its publication follows or coincides with the reference switch within 30 s, and it occurs no later than the next reference switch. For the last switch the observation grid end also bounds the match. Unknown gaps break reference adjacency. The first 30 s expert winner initializes the predicted switch sequence.

The paper used 500 randomized layouts and 100 layouts with LSApp timing and substituted Android traffic. The randomized cohort reused development recordings; 37 layouts had been used to fit the temporal heads. The guided cohort included 854 s of unknown reference time. The CLI uses every supplied timeline. Reproducing the paper values requires the corresponding layouts and frozen predictions; the examples exercise the public calculation on different inputs.

## Appliance energy

The input contains a `segments` array. Each entry supplies a device alias, profile name, coverage start and end, and two lists of (time, action) pairs: `logged` for reference operations and `inferred` for predicted operations. Coverage intervals for the same device must be disjoint. Commands outside coverage and actions other than power_on or power_off do not change state.

| Profile | ON (W) | Standby (W) | State rule |
|---|---:|---:|---|
| air_purifier | 6.94 | 1.02 | Latching |
| dehumidifier | 117.00 | 1.08 | Latching |
| circulation_fan | 7.08 | 3.48 | Latching |
| kettle | 2025 | 0 | Each start opens a 180 s heating cycle |

Latching appliances retain state until an opposite operation or the end of coverage. The study initializes both histories to the state opposite the first logged switch in each segment. This uses reference information only for the shared boundary condition. For a separately known boundary condition, provide the boolean `initially_on`; it is required for latching devices when no logged switch is available. To estimate without any reference log, call `state_history(start, end, inferred, profile, initially_on=...)` in `case_studies.appliance_energy`. The kettle begins idle; heating ends at the earlier of cycle expiry and the coverage end. Overlapping heating cycles count once. The original figure script summed individual cycles; the evaluated starts did not overlap.

For each segment, the output includes its initial state, ON intervals, ON/OFF seconds, Wh, and seconds of state agreement. Energy is `(on_w × on_seconds + standby_w × off_seconds) / 3600`. The study summary sums Wh across devices and segments, weights state agreement by evaluated device-seconds and returns absolute total error divided by total reference Wh. A zero reference total gives a null relative error.

### Check the fan example

The [synthetic fan trace](examples/synthetic_fan_energy.json) covers 600 s. Its first logged operation turns the fan off at 120 s, so both histories start with the fan on. The last logged OFF at 480 s is missing from the inferred operations, leaving the estimated fan state on until 600 s.

| History | ON intervals (s) | ON (s) | Standby (s) | Energy (Wh) |
|---|---|---:|---:|---:|
| Logged | [0, 120), [300, 480) | 300 | 300 | 0.88 |
| Inferred | [0, 130), [330, 600) | 400 | 200 | 0.98 |

For example, `estimated_wh = (400 × 7.08 + 200 × 3.48) / 3600 = 0.98`. Both rows use the same power coefficients. These values reproduce the calculation for the synthetic input. Recomputing the paper's aggregate requires its original coverage intervals and operation records.

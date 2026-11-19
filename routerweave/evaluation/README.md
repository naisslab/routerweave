# Routerweave evaluation

This module scores activity recognition on four datasets, compares observation units and evidence views, and measures recognition latency and resource use. The `evidence/` directory contains anonymized records from the experiments. The numbers printed by the scorer are computed from those records. The examples use synthetic traffic.

## Run the published comparisons

Use Python 3.11 or newer. From this directory, run:

```sh
python -B score.py all
```

This command uses the Python standard library, reads eight CSVs relative to the script, and prints JSON to standard output. It runs without a GPU, network connection, original captures, or trained checkpoints. Choose `comparison`, `observation`, `fusion`, `latency`, or `capacity` to score one group. Pass `--inputs DIRECTORY` to score another directory with the same schemas.

[experiment_index.json](experiment_index.json) identifies each dataset and split, model or checkpoint, pipeline, scoring unit, original experiment entry, and summary command. Source hashes identify the retained inputs and implementations. The archive roots `primary` and `external` each denote a modeling-results directory, and `source` denotes the original source tree. A historical command containing only a script name runs in the recorded entry's directory. The scoring commands above use only the files in this module. All results here have a null timeline ID.

## Recognition comparison

| Dataset | Test unit | Routerweave | BehavIoT | FlowPrint |
|---|---|---:|---:|---:|
| RouterWeave-App | 2,424 labeled 30 s windows, 39 captures | 94.41 | 69.49 | 73.42 |
| RouterWeave-IoT | 1,022 matched detector candidates | 97.46 | 91.15 | 40.30 |
| BehavIoT-Dataset | 1,409 supplied activity clips, 18 labels | 84.21 | 70.79 | 37.34 |
| ITC-Net-Blend-60 | 2,104 nonempty windows, 8 proxy labels | 78.69 | 67.85 | 82.31 |

Values are macro-F1 percentages. For each test-supported class the scorer computes `2 TP / (number of references + number of predictions)`, then averages over classes. Every test unit contributes to accuracy. An abstention produces a miss for its true class. The three RouterWeave-IoT fits use seeds 42, 43 and 44. Each is scored separately before averaging.

- **RouterWeave-App.** The fit uses 156 recordings. The frozen joint model is scored on 39 historically inspected recordings. The numerical baseline slices a device's packets at the registered window cutoffs using `(end − 30 s, end]`. FlowPrint uses global destination/certificate matching. An empty fingerprint can still receive a fallback label.
- **RouterWeave-IoT.** Scoring is conditional on a candidate matching a reference operation. There are 19 test-supported classes in a 20-output vocabulary. Distinct segments from 39 of the 74 evaluation capture batches also entered fitting. The Routerweave classifier uses a known-device label mask. FlowPrint fingerprints a source and assigns its label to each candidate from that source. Missed detections enter the separate event experiment.
- **BehavIoT-Dataset.** Capture components stay together across the 4,223/1,408/1,409 train/validation/test clips. Device category and operation family determine the label. Routerweave uses complete payload sequences and a single 40-epoch seed-42 fit. The retained numerical BehavIoT row omits hostname and periodic filtering. Variant performance had already been inspected on test data.
- **ITC-Net-Blend-60.** Whole captures are split 399/129/149, producing 5,885/2,031/2,104 windows. Each nonempty 30 s interval inherits its app's dominant purpose, including the final partial interval. Calls within a messaging app therefore still count as messaging. The eight-class Routerweave fit used seed 42, a maximum of 25 epochs and validation checkpoint selection. The mapping covers 35 apps. [Label mappings](taxonomy.json)

### Run adapters and fit baselines on new data

Install the numerical dependencies with `python -m pip install -r requirements.txt`. Fitting and prediction run locally. The install is separate from scoring.

```sh
python -B dataset_units.py app examples/synthetic_recording.json
python -B dataset_units.py iot examples/synthetic_recording.json
python -B dataset_units.py behaviot examples/synthetic_recording.json
python -B dataset_units.py itc examples/synthetic_recording.json
python -B fit_baseline.py itc behaviot examples/synthetic_units.json
python -B fit_baseline.py itc flowprint examples/synthetic_units.json
```

The recording adapter accepts aligned, time-ordered packet columns `t` (seconds), `size` (bytes), `direction` (+1 outgoing, −1 incoming), `flow` (connection ID), and `local` (LAN peer). App inputs supply platform and window IDs/cutoffs. IoT inputs supply device and member indices from an upstream detector. The public IoT adapter takes one complete clip and uses the released device/action taxonomy. ITC bins from the first eligible packet using half-open intervals. Supply whole recordings in their assigned partition. The adapter emits evaluation units for the numerical baseline.

The fitter takes separate `train` and `test` lists with unique unit IDs. Its outputs are unit IDs and predicted labels. A training unit has a label and a conditioning group (OS, physical device, or Android for ITC). Optional `idle: true` training units supply the external negative pool for that group. Set the top-level `background` field when background is a scored class. Prediction uses packets or fingerprints and the group where required. Test labels are ignored.

BehavIoT splits each flow at gaps greater than 1 s, skips singleton bursts, and fits one-vs-rest forests on 22 burst statistics. Forests have 100 trees and random state 100. The non-ITC fitter caps positive training bursts at 300,000 per group before adding idle negatives. ITC counts all binary positive votes above 0.5. The other numerical adapters choose one decision per burst and then vote across bursts. FlowPrint takes one list of fingerprints per unit (`tokens` and `flows`), merges training fingerprints at Jaccard similarity 0.9, and votes over recognized query fingerprints. In the IoT source-level experiment, supply one fingerprint batch per source and map its prediction back to the associated candidates. Precomputed tokens must use a consistent encoding across train and test. The native application baseline also implements packet-to-fingerprint construction. Equal-score ties in the Python upstream matching procedure can depend on set iteration order. The supplied prediction record preserves the decisions used in the paper. The FlowPrint functions are adapted from the upstream revision recorded in the bindings. [Upstream license](LICENSE-FlowPrint)

## Observation units and evidence fusion

**Event scoring.** The figure uses ±1 s on 1,033 reference events in 1,095 inspected development containers. Fixed 1/3/5 s windows score 72.92/67.79/65.74% event F1. Gap 0.5/1/2 s groups score 73.48/72.56/74.54%. The learned unit scores 94.20% (983 TP, 71 FP, 50 FN). The full output retains 11 settings at ±0.5/1/2 s. At ±1 s, the additional 3 s gap setting reaches 75.65%.

`observation_units.py` constructs fixed windows at one-second cutoffs and silence groups with a 5 s span cap. A frozen model supplies candidate probabilities. A 0.5 confidence gate and a 2 s first-hit cooldown determine accepted outputs. Association requires shared packet membership and eligible midpoint time before one-to-one assignment. Class correctness is checked afterward. The clock is a network-member midpoint, and the data have at most one reference per container. Fixed and gap families have separately fitted classifiers. Gap 2 s and 3 s reuse the gap-family weights fitted with shorter gaps. The supplied rows replay the recorded associations; the scorer exposes how to evaluate new candidates and references in memory. This experiment measures event recognition on the development containers.

**Evidence views.** Run `python -B score.py fusion` from this directory to reproduce the table from the included per-window predictions in `evidence/views.csv`. This command uses only the Python standard library. The three independently fitted models share 156 fit captures, the same 39 test captures, seed 7, and a seven-epoch budget. Accuracy weights each selected window equally.

| Cohort | Windows | Traffic only | Service only | Joint |
|---|---:|---:|---:|---:|
| All | 2,424 | 80.28% | 90.22% | 94.76% |
| Buffered media | 63 | 60.32% | 90.48% | 96.83% |
| Ambiguous services | 501 | 70.66% | 92.42% | 99.40% |

The traffic-only, service-only and joint models correctly classified 1,946, 2,187 and 2,297 of the 2,424 windows. The joint model gained 14.48 percentage points over traffic only and 4.54 over service only. [Training protocol and checkpoints](experiment_index.json)

The buffered-media subgroup uses a full low-download window immediately following a burst. The ambiguous-service subgroup comprises non-live activities with a visible live-service role. Both use predictions from the seven-epoch experiment.

`fusion_control.EvidenceModel(view)` accepts normalized PyTorch tensors. For each sample, provide `device[30,40]`, `connection_attributes[n,16]`, `connection_temporal[n,30,2]` and `header_profile[40]`, plus a batch-level `context[B,380]`. It returns six log probabilities in background, browsing, live stream, long video, music and short video order. Select `traffic_only`, `service_only` or `joint`. The traffic control closes both service paths. The service control zeros the anonymous traffic embedding and the first three global-scale channels; service-group traffic statistics remain available. Load the matching state dictionary for each fitted arm and call `eval()` for inference. PyTorch is an optional dependency for this module. Raw training capture data, normalizers, original training schedules and production weights are identified by the bindings or their referenced records. The packaged model implements the forward pass; the published score command uses frozen predictions.

## Router replay

The single-stream experiment used a GL-MT3000 with two CPU cores. Android, iOS and Windows each supply one ten-minute capture with 115 updates per repetition. The IoT workload contains 50 action and 50 background recordings; 46 actions have a network reference onset. Single-stream replay retains packet and timer timestamps and skips idle sleeping. P95 is the nearest-rank percentile. The application clock starts at window cutoff. The manuscript IoT clock starts at the first reference-member packet and stops at a related positive decision regardless of class.

| Single-stream definition | Timed outputs | P95 | Peak RSS (MiB) | Model (decimal MB) |
|---|---:|---:|---:|---:|
| Application · Routerweave | 10,350 | 41.08 ms | 6.99 | 2.50 |
| Application · FlowPrint | 10,350 | 11.62 ms | 19.77 | 2.83 |
| IoT · Routerweave, matched positive | 3,810 / 4,140 eligible trials | 4.77 s | 5.41 | 1.68 |
| IoT · BehavIoT, matched positive burst | 390 / 1,380 eligible trials | 7.43 s | 0.88 | 0.48 |
| IoT · BehavIoT, final window decision | 1,380 / 1,380 eligible trials | 11.43 s | 1.00 | 0.48 |

The 7.43 s endpoint precedes BehavIoT's final window aggregation. The final-window run includes 330 positive and 1,050 unknown/background decisions. Both timings are retained with their denominators. There are 30 repetitions per fitted seed, including three seeds for RouterWeave-IoT. Repetition measures timing variation on the same traces. `replay_cpu_pct` uses the sum of process CPU seconds divided by twice the sum of measured wall seconds across process runs. This is utilization during accelerated single-stream replay. RSS comes from the peak over process runs; the manuscript's RSS numbers are in MiB. Model footprint uses decimal MB and includes the workload-specific indices.

**Concurrency.** Equal numbers of Windows application and Google Nest Mini IoT streams replay fixed templates with separate state and shared weights. Each load has one paced trial, 30 s warm-up and 20 five-second observation rounds. The concurrency experiment uses the 34-action IoT classifier identified in the bindings. Its workload differs from the 20-output single-stream accuracy experiment. At 54 logical devices, P95 aggregate processing cost is **4.761 s**, P95 post-cutoff completion delay is **2.085 s**, process CPU is **27.68%** of two cores and peak RSS is **149.89 decimal MB**. At 64 devices, processing cost reaches 5.639 s and RSS 174.31 MB. The largest tested load meeting both a 5 s processing budget and a 150 MB process budget is 54. These short trials establish neither an exact limit nor live forwarding performance.

### Build and exercise the native code

The recorded router used AArch64 Linux/musl. Use Zig 0.14.1 on PATH. The build writes into a new directory and performs no router deployment. For a standalone x86-64 Linux example:

```sh
python -B native/build.py --target x86_64-linux-musl --output bin-x86
python -B examples/generate_replay_fixture.py toy-input
./bin-x86/latency toy-input app-fp toy-input/sample.pcap 192.0.2.10 00:00:00:00:00:00 0 unused 30 0
```

The synthetic trace contains two destination flows and a tiny two-class fingerprint model. It emits label 1 at the 30-second cutoff. The MAC, device index and detector string are unused in application mode. Its timing has no experimental meaning. To build the router programs, run `python -B native/build.py --output bin-arm`. The three binaries are `latency`, `latency-rf-window` and `capacity`.

The latency argument order is model directory, mode, timestamp-ordered Ethernet PCAP, device IPv4 address, device MAC, device index, detector key, duration (s), and pacing flag. The four modes are `app-rw`, `app-fp`, `iot-rw` and `iot-rf`. Application Routerweave reads `weights.bin` and `normalizer.bin`; application FlowPrint reads `flowprint.bin`. IoT Routerweave reads `iot-models.bin`; BehavIoT reads the fitted device forest under `rf/`. The final-window program additionally reads `rf-labels.txt`. The capacity argument order is model/input directory, workload manifest, warm-up (s), observation duration (s), pacing flag, and tail (s). A manifest starts with App and IoT stream counts, followed by one `pcap ipv4` row per App stream and one `pcap mac detector device_index` row per IoT stream. The capacity runtime reads `native-models.bin` for IoT. Use workload-specific assets when repeating a physical measurement. Results in this module are taken from the original router observations.

## Scoring inputs and provenance

| File in `evidence/` | Contents |
|---|---|
| `classification.csv` | Dataset, frozen row ID, truth, and predictions; two additional seed columns for RouterWeave-IoT. |
| `views.csv` | Window index, anonymous recording number, ground truth, three predictions and two cohort flags. |
| `events.csv` | Per-container true positives derived from associated labels, accepted outputs, and references for each arm and tolerance. |
| `latency.csv` | Mode, seed, repetition, input, status, reference onset/cutoff and observed decision in relative seconds. Missing decisions remain empty. |
| `processes.csv`, `footprint.csv` | Per-process CPU seconds, wall seconds, RSS, and model/index sizes used in the router table. |
| `rounds.csv`, `capacity.csv` | Round due/completion times and service cost; trial duration, core count, CPU time and peak RSS. |

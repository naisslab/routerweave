# RouterWeave

**Activity recognition at the home router, across devices and platforms.**

[Paper (arXiv:2611.26134)](https://arxiv.org/abs/2611.26134) · [Quick Start](#quick-start) · [Data Release](#data-release) · [Citation](#citation)

Vendor dashboards each cover a subset of household activity. RouterWeave uses the home router as a shared observation point. It infers device activity from packet timing, size, direction, and available service metadata without decrypting application payloads. The same record format represents sustained activities such as video streaming and discrete operations such as toggling a smart light.

## Data Release

**We plan to open-source the RouterWeave research datasets soon.** You can explore the code in the meantime with the synthetic examples below.

## Quick Start

Run both case studies on bundled synthetic inputs. You need Python 3.12. The examples run locally without a router or GPU.

```bash
git clone https://github.com/naisslab/routerweave.git
cd routerweave/routerweave/applications
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -B -m case_studies screen-time examples/synthetic_screen_time.json --details
python -B -m case_studies appliance-energy examples/synthetic_fan_energy.json
```

Both commands print JSON. The Screen Time example reports published activity intervals and switch timing. The appliance example estimates **0.98 Wh** from inferred fan operations and **0.88 Wh** from the reference log. [Case-study guide](routerweave/applications/README.md)

## How It Works

1. **Collect and preprocess traffic.** RouterWeave extracts per-device packet observations from router captures. During data collection, device logs and controller events provide ground truth.
2. **Recognize activities and operations.** For sustained application activities, the model analyzes concurrent connections in sliding windows and adjusts how much it relies on service metadata. For brief IoT operations, a device-specific localizer selects the relevant packets and a shared classifier labels the operation.
3. **Build activity records.** The record manager tracks activity intervals and state transitions by source device. Screen Time sums activity durations. Appliance energy estimation combines reconstructed ON/OFF intervals with measured power profiles.

## Results From the Paper

| Experiment | Reported Result |
| --- | --- |
| Application activity recognition | **94.41% macro-F1** on labeled RouterWeave-App windows |
| IoT operation classification | **97.46% macro-F1** on candidates matched to RouterWeave-IoT reference operations |
| Router replay | **54 concurrent logical devices** within a five-second processing budget on a GL.iNet GL-MT3000 |
| Cross-platform Screen Time | **92.15% retrospective time accuracy** across 600 constructed Android, iOS, and Windows timelines |
| Appliance energy estimation | **4.28% aggregate energy error** relative to smart-plug logs across four appliances |

The paper details the four-dataset evaluation, baselines, and case-study protocols. [Read the paper](https://arxiv.org/abs/2611.26134)

## Repository Guide

| Module | Start Here |
| --- | --- |
| [Data collection](routerweave/collection/README.md) | Capture router traffic and align it with device logs or controller events. |
| [Traffic processing](routerweave/traffic/README.md) | Extract per-device packet and flow records from PCAP files. |
| [Application activity recognition](routerweave/recognition/activity/README.md) | Train a model and classify sustained activity on a sample capture. |
| [IoT operation recognition](routerweave/recognition/iot/README.md) | Run the smart-light example or train the localizer and classifier. |
| [Case studies](routerweave/applications/README.md) | Generate Screen Time records and appliance energy estimates. |
| [Evaluation](routerweave/evaluation/README.md) | Find scoring scripts, baseline implementations, and native router benchmarks. |

## Citation

```bibtex
@article{liu2026routerweave,
  title   = {{RouterWeave}: A Unified Observation Layer for Cross-Platform Activity Analysis via Home Routers},
  author  = {Liu, Chengeng and Li, Ronghua and Long, Yan and Liu, Shinan},
  journal = {arXiv preprint arXiv:2611.26134},
  year    = {2026},
  url     = {https://arxiv.org/abs/2611.26134}
}
```

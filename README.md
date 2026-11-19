# Routerweave

Routerweave is a router-side observation framework for cross-platform device activity.

## Pipeline

**Shared traffic acquisition.** During [collection](routerweave/collection/README.md), router captures are aligned with device logs and controller events to establish ground truth. At inference time, [traffic processing](routerweave/traffic/README.md) extracts packet timing, sizes, directions, and available service metadata for each device from the router capture.

**Task-adaptive inference.** The temporal structure of the activity determines how Routerweave groups and interprets packets.

- [Sustained activities](routerweave/recognition/activity/README.md) on Android, iOS, and Windows can span several concurrent connections. The model analyzes these connections together in sliding windows. Reliability-gated feature-wise linear modulation (FiLM) controls how strongly service metadata influences the traffic representation.
- [IoT operations](routerweave/recognition/iot/README.md) often produce brief exchanges interleaved with background traffic. A device-specific localizer selects the packets associated with an operation, and a classifier shared across devices assigns its label.

**Unified activity records.** The record manager opens, extends, and closes activity intervals for each device. It records IoT operations as transitions, allowing an inferred state to persist between events. Applications can query the resulting device history or subscribe to updates. In the [case studies](routerweave/applications/README.md), Screen Time sums interval durations by activity, while appliance energy estimation integrates power over the time spent in each state.

The [evaluation module](routerweave/evaluation/README.md) includes recognition baselines, ablation studies, and router benchmarks.

## Repository layout

```text
routerweave/
├── collection/
├── traffic/
├── recognition/
│   ├── activity/
│   └── iot/
├── applications/
└── evaluation/
```

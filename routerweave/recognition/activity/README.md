# Sustained application activity recognition

Classify a device’s IPv4 traffic in 30-second windows at five-second intervals.

## Run the example

Use Python 3.11 or later. From this directory, run the following commands to prepare the four synthetic recordings, train a small model on CPU and predict activity in the held-out recording.

```sh
python -m pip install -r requirements.txt
python -B -m activity.prepare examples/recordings.json work/features
python -B -m activity.train work/features/manifest.json work/fit --epochs 1 --steps 1 --batch 8
python -B -m activity.predict examples/ios_browsing_test.pcap work/fit/model.pt --ip 192.0.2.10 --start 0 --stop 60
```

Training saves the model to `work/fit/model.pt` and scores to `work/fit/training.json`. The example prints seven JSON lines. Each gives the window end time in Unix seconds (`end`), the predicted activity (`label`) and its distribution over six classes (`probabilities`).

## Run on your recordings

Create a manifest with one entry per labelled recording. Use [examples/recordings.json](examples/recordings.json) as the template.

| Fields | What to supply |
| --- | --- |
| `pcap`, `ip` | Classic PCAP file path relative to the manifest and the device’s IPv4 address. |
| `id`, `group`, `fold` | A unique recording ID, acquisition group and split. Keep each group in one split. Use all three development folds (`0`, `1`, `2`) and optionally `"test"`. |
| `platform`, `label` | Recording platform and one of `background`, `browsing`, `live_stream`, `long_video`, `music`, `short_video`. |
| `intervals` | Ordered, nonoverlapping pairs of start and stop times in Unix seconds. Each recording needs at least one fully captured 30-second window with the stated label. |
| `csv` (optional) | Packet table with `stream_id` (one-based PCAP frame number), `time`, `length`, `direction` and `ip_protocol`. Pass the same file to prediction with `--packet-table`. |
| `evaluation_ends` (optional) | Window endpoints for evaluation. By default, evaluation uses nonoverlapping 30-second windows within each labelled interval. |

Run the commands above with your manifest, capture, device IP and time range. Use new output directories for preparation and training. Omit `--epochs 1 --steps 1 --batch 8` for the default training schedule. Add `--device cuda` to train on a GPU with a CUDA-enabled PyTorch installation.

If you already have a trained checkpoint, run `activity.predict` directly with that file and the capture. Set `--start` and `--stop` to the desired observation interval in Unix seconds.

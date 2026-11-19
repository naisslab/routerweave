# Routerweave IoT operation recognition

[models/classifier.pt](models/classifier.pt) contains the IoT operation classifier used in the paper.

## Reproduce the smart-light example

Use Python 3.12. From this directory, install the dependencies and run CPU inference on the bundled development trace.

```sh
python -m pip install -r requirements.txt
python -m iot_operations --localizer examples/smart_light/localizer.pt --classifier models/classifier.pt --input examples/smart_light/packet_trace.json
```

Expect one candidate with `packet_indices` equal to `[2, 3, 4]` (zero-based), `label` equal to `smart_light/power_operation`, and `probability` above 0.99.

To use another trace, pass normalized JSON in the [example format](examples/smart_light/packet_trace.json). Each row of `packets` contains time in seconds, transport-unit length in bytes, direction (+1 outgoing, −1 incoming), connection ID and protocol (0 TCP, 1 UDP), in chronological order. The `device_id` must match the checkpoints. Convert raw PCAP to normalized transport units before running this command.

## Train both stages

Run the example from this directory. It fits a device localizer, freezes it, generates its actual candidates and fits the operation classifier. The [two synthetic traces](examples/synthetic_training_traces.json) exercise the training pipeline. Use a new output directory.

```sh
python -m iot_operations.train --samples examples/synthetic_training_traces.json --config configs/localizer.json --output trained-example --localizer-epochs 1 --classifier-epochs 1
```

The command writes `localizer-1.pt` and `classifier.pt` in `trained-example`. It prints the device-to-checkpoint mapping and counts for predicted candidates, candidates with training labels, base training rows and augmented rows.

For your recordings, supply a JSON array of training samples in the same format. Each sample contains one device's normalized traffic, its device category, reviewed operation fingerprints and known background indices. A fingerprint contains the recorded action and its member observations from that trace. Members are matched by timestamp (rounded to five decimals), byte length, direction, connection and protocol. When needed, append matching frame and record-offset fields to both rows to resolve ties. Missing or ambiguous members stop training. Already aligned data can instead supply `references` with `original_action` and zero-based `packet_indices`.

The first and last fingerprint members supervise the localizer's start and end heads. The full member set supervises packet selection. For classifier fitting, the frozen localizer runs on the training traces. Reviewed fingerprints label its candidates; ambiguous candidates are excluded. Reference groups, known background and reference groups augmented with nearby background supply additional rows. Labels merge related actions such as power-on and power-off. Inference takes only the device identity and traffic.

Omit both epoch overrides for the study schedule. The localizer uses at least 30 epochs and the update budget in [the configuration](configs/localizer.json). For a device with a different budget, set its entry in `minimum_updates_by_device` (300 for one speaker in the study). The shared classifier trains for 40 epochs with AdamW, up to 128 candidates per batch and inverse-square-root device/class frequency weights. The synthetic example checks training and checkpoint loading; the original study training set is not bundled.

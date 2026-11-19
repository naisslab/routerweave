"""Known-device IoT operation recognition from canonical transport units."""

import numpy as np
import torch
from numpy._core.multiarray import _reconstruct

from .classifier import OperationClassifier
from .localizer import Localizer, locate
from .traffic_features import Traffic


class Recognizer:
    def __init__(self, locator_path, classifier_path):
        """Load the two explicitly supplied local research checkpoints on CPU."""
        with torch.serialization.safe_globals([_reconstruct, np.ndarray, np.dtype, type(np.dtype("float32"))]):
            locator = torch.load(locator_path, weights_only=True, map_location="cpu")
        classifier = torch.load(classifier_path, weights_only=True, map_location="cpu")
        if locator["architecture"] != "anchored_end" or locator["arm"] != "B" or classifier["arm"] != "numeric":
            raise ValueError("Expected an end-aware localizer and numeric-size FiLM classifier")
        self.device = locator["device_id"]
        self.device_index = classifier["devices"].index(self.device)
        self.classes = tuple(classifier["classes"])
        policy = locator["policy"]
        self.model = Localizer(policy["hidden"])
        self.model.load_state_dict(locator["state"])
        self.model.eval()
        self.mean = np.asarray(locator["mean"])
        self.scale = np.asarray(locator["scale"])
        self.context = locator["context"]
        self.owned = policy["owned_packets"]
        self.threshold = policy["threshold"]
        if (self.mean.shape != (10,) or self.scale.shape != (10,) or not np.isfinite(self.mean).all()
                or not np.isfinite(self.scale).all() or (self.scale <= 0).any()
                or self.context < 0 or self.owned < 1 or not 0 < self.threshold <= 1):
            raise ValueError("Invalid localizer normalization or decoding settings")

        state = dict(classifier["state"])
        # The original checkpoint also stores an unused, alternative concatenation layer.
        for key in ("film.concat.weight", "film.concat.bias"):
            state.pop(key, None)
        norm = {k: state[k] for k in ("token_mean", "token_scale", "flat_mean", "flat_scale",
                                      "context_mean", "context_scale")}
        if tuple(state["support"].shape) != (len(classifier["devices"]), len(self.classes)):
            raise ValueError("Device and class names must match the support matrix")
        self.classifier = OperationClassifier(norm, state["support"])
        self.classifier.load_state_dict(state)
        self.classifier.eval()

    @torch.inference_mode()
    def recognize(self, packets, device_id):
        if device_id != self.device:
            raise ValueError("The physical device does not match its localizer")
        traffic = Traffic(packets)
        candidates = locate(self.model, traffic, self.mean, self.scale, context=self.context,
                            owned=self.owned, threshold=self.threshold)
        results = []
        for candidate in candidates:
            probs = self.classifier.probabilities(traffic, candidate, self.device_index)
            index = int(probs.argmax())
            probability = float(probs[index])
            ids = candidate.packet_indices
            results.append(dict(anchor=candidate.anchor, predicted_end=candidate.predicted_end,
                                packet_indices=list(ids), start=traffic.times[ids[0]], end=traffic.times[ids[-1]],
                                start_probability=candidate.start_probability,
                                label=self.classes[index] if probability >= .5 else "__uncertain__",
                                probability=probability))
        return results

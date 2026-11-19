"""Fit and recognize the baseline from per-unit FlowPrint fingerprints."""

from collections import Counter, defaultdict
from itertools import combinations
import numpy as np


class Fingerprint(frozenset):
    def __new__(cls, tokens, flows):
        result = super().__new__(cls, tokens)
        result.n_flows = flows
        return result

    def merge(self, *other):
        union = set().union(self, *other)
        result = super(Fingerprint, type(self)).__new__(type(self), union)
        result.__setattr__("n_flows", self.n_flows + sum((o.n_flows for o in other)))
        return result

    def compare(self, other):
        return len(self & other) / max(len(self | other), 1)

    def __lt__(self, other):
        return (len(self), self.n_flows) < (len(other), other.n_flows)


class Matcher:
    def score_combinations(self, fingerprints, threshold):
        fingerprints = sorted(set(fingerprints))
        lengths = dict()
        for fp in fingerprints:
            length = len(fp)
            lengths[length] = lengths.get(length, set()) | set([fp])
        for length, fingerprints in sorted(lengths.items()):
            if length == 0:
                continue
            length_comb = set()
            length2 = length
            while (length2 - length) / max(length2, 1) <= 1 - threshold:
                if length2 in lengths:
                    length_comb.add(length2)
                length2 += 1
            for length2 in length_comb:
                if length == length2:
                    yield from combinations(lengths.get(length), 2)
                else:
                    a = lengths.get(length)
                    b = lengths.get(length2)
                    yield from ((x, y) for x in a for y in b)

    def merge_fingerprints(self, fingerprints, threshold=1):
        result = np.asarray(fingerprints)
        unique = sorted(set(fingerprints))
        if threshold <= 0:
            result[:] = Fingerprint(set().union(*unique), sum(fp.n_flows for fp in unique))
        elif threshold < 1:
            pairs = set(
                [
                    (fp1, fp2)
                    for fp1, fp2 in self.score_combinations(unique, threshold)
                    if fp1.compare(fp2) >= threshold
                ]
            )
            mapping = dict()
            for fp1, fp2 in pairs:
                fp_merged = mapping.get(fp1, fp1).merge(mapping.get(fp2, fp2))
                mapping[fp1] = fp_merged
                mapping[fp2] = fp_merged
            result = np.array([mapping.get(fp, fp) for fp in fingerprints])
        return result

    def predict(self, X, y=None, default="common"):
        result = np.zeros(len(X), dtype=object)
        if default == "common":
            default = max(self.fingerprints, key=lambda x: x.n_flows)
        elif default == "largest":
            default = max(self.fingerprints, key=lambda x: len(x))
        lookup = dict()
        for fingerprint in self.fingerprints:
            for dst in fingerprint:
                lookup[dst] = lookup.get(dst, set()) | set([fingerprint])
        for i, fingerprint in enumerate(X):
            matches = list(set().union(*[lookup.get(x, set()) for x in fingerprint]))
            if not matches:
                result[i] = default
            else:
                scores = np.asarray([fingerprint.compare(m) for m in matches])
                result[i] = matches[scores.argmax()]
        return result

    def recognize(self, X, y=None, default="common"):
        return np.asarray([self.fingerprints.get(x) for x in self.predict(X, default=default)])


def fit_fingerprints(training, similarity=0.9):
    if not training or not 0 < similarity <= 1:
        raise ValueError("Expected training fingerprints and similarity in (0, 1]")
    supplied = [Fingerprint(tokens, flows) for tokens, flows, _ in training]
    matcher = Matcher()
    merged = matcher.merge_fingerprints(np.asarray(supplied, dtype=object), similarity)
    votes = defaultdict(Counter)
    for fingerprint, (_, _, label) in zip(merged, training):
        votes[fingerprint][label] += 1
    matcher.fingerprints = {fp: v.most_common(1)[0][0] for fp, v in votes.items()}
    return matcher


def fingerprint_vote(model, fingerprints, empty_label):
    if not fingerprints:
        return empty_label
    labels = model.recognize([Fingerprint(tokens, 0) for tokens in fingerprints])
    return Counter(labels).most_common(1)[0][0]
